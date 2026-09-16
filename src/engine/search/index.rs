//! Full-text search index using Tantivy.

use super::types::{SearchDocument, SearchHit};
use crate::common::neighbor::is_generic_neighbor_token;
use std::{io, path::Path};
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{BooleanQuery, BoostQuery, Occur, PhraseQuery, Query, QueryParser, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, STORED,
};
use tantivy::tokenizer::{LowerCaser, RawTokenizer, SimpleTokenizer, TextAnalyzer};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};

/// Extract only the filename from a path, stripping directories.
/// Handles both Unix (/) and Windows (\) path separators regardless of platform.
/// Prevents leaking usernames or directory structures in API responses.
fn sanitize_basename(input: &str) -> String {
    let input = input.trim();
    if input.is_empty() {
        return String::new();
    }

    let last_sep = input.rfind('/').into_iter().chain(input.rfind('\\')).max();
    let base = match last_sep {
        Some(idx) => &input[idx + 1..],
        None => input,
    };

    let base = base.trim();
    if base.is_empty() {
        return String::new();
    }

    if base.len() > 255 {
        base[..255].to_string()
    } else {
        base.to_string()
    }
}

/// Full-text search index for function metadata.
pub struct SearchIndex {
    index: Index,
    reader: IndexReader,
    writer: parking_lot::Mutex<IndexWriter>,
    fields: SearchFields,
}

struct SearchFields {
    key_hex: Field,
    func_name: Field,
    func_name_demangled: Field,
    lang: Field,
    binary_name: Field,
    origin_token: Field,
    prototype_token: Field,
    frame_token: Field,
    comment_token: Field,
    operand_token: Field,
    semantic_token: Field,
    variant_token: Option<Field>,
    ts: Field,
}

impl SearchIndex {
    /// Open or create a search index at the given directory.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let schema = build_schema();

        let index = if dir.join("meta.json").exists() {
            Index::open_in_dir(dir)
                .map_err(|e| io::Error::other(format!("open search index: {e}")))?
        } else {
            if std::fs::read_dir(dir)?.next().is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "search directory has files but no manifest; prepare a new generation",
                ));
            }
            Index::create_in_dir(dir, schema)
                .map_err(|e| io::Error::other(format!("create search index: {e}")))?
        };

        register_tokenizers(&index);
        if index.schema() != build_schema() && index.schema() != build_schema_version(false) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "search schema differs from the current projection; run offline preparation",
            ));
        }
        let fields = SearchFields::load(&index.schema()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("incompatible search schema; run preparation: {e}"),
            )
        })?;

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| io::Error::other(format!("reader: {e}")))?;

        let writer = index
            .writer(50_000_000)
            .map_err(|e| io::Error::other(format!("writer: {e}")))?;

        Ok(Self {
            index,
            reader,
            writer: parking_lot::Mutex::new(writer),
            fields,
        })
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.reader.searcher().num_docs() == 0)
    }

    pub(crate) fn has_variant_vocabulary(&self) -> bool {
        self.fields.variant_token.is_some()
    }

    /// Index a single function document (with immediate commit).
    pub fn index_function(&self, doc: &SearchDocument) -> io::Result<()> {
        self.index_function_no_commit(doc)?;
        self.commit()
    }

    /// Index a single function document without committing.
    pub fn index_function_no_commit(&self, doc: &SearchDocument) -> io::Result<()> {
        let key_hex = format!("{:032x}", doc.key);
        let writer = self.writer.lock();
        writer.delete_term(Term::from_field_text(self.fields.key_hex, &key_hex));
        let tdoc = self.build_document(doc);
        writer
            .add_document(tdoc)
            .map_err(|e| io::Error::other(format!("add doc: {e}")))?;
        Ok(())
    }

    /// Insert into a fresh offline generation whose keys are already unique.
    /// Avoid retaining one redundant deletion operation per prepared document.
    pub(crate) fn append_prepared_document(&self, doc: &SearchDocument) -> io::Result<()> {
        self.writer
            .lock()
            .add_document(self.build_document(doc))
            .map_err(|e| io::Error::other(format!("add prepared doc: {e}")))?;
        Ok(())
    }

    /// Commit pending changes and reload the reader.
    pub fn commit(&self) -> io::Result<()> {
        let mut writer = self.writer.lock();
        writer
            .commit()
            .map_err(|e| io::Error::other(format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::other(format!("reload: {e}")))?;
        Ok(())
    }

    /// Delete a function from the index.
    pub fn delete(&self, key: u128) -> io::Result<()> {
        let key_hex = format!("{:032x}", key);
        let mut writer = self.writer.lock();
        writer.delete_term(Term::from_field_text(self.fields.key_hex, &key_hex));
        writer
            .commit()
            .map_err(|e| io::Error::other(format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::other(format!("reload: {e}")))?;
        Ok(())
    }

    /// Rebuild the entire index from an iterator of documents.
    pub fn rebuild<I>(&self, docs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = SearchDocument>,
    {
        let mut writer = self.writer.lock();
        writer
            .delete_all_documents()
            .map_err(|e| io::Error::other(format!("search index delete_all_documents: {e}")))?;

        for doc in docs.into_iter() {
            let tdoc = self.build_document(&doc);
            writer
                .add_document(tdoc)
                .map_err(|e| io::Error::other(format!("add doc: {e}")))?;
        }

        writer
            .commit()
            .map_err(|e| io::Error::other(format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::other(format!("reload: {e}")))?;
        Ok(())
    }

    /// Search for functions matching the query. Returns up to `limit` results.
    pub fn search(&self, query: &str, limit: usize) -> io::Result<Vec<SearchHit>> {
        self.search_internal(query, 0, limit).map(|(hits, _)| hits)
    }

    /// Search with pagination support. Returns (results, total_count).
    pub fn search_paginated(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<SearchHit>, usize)> {
        self.search_internal(query, offset, limit)
    }

    /// Get the number of documents in the search index.
    pub fn doc_count(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    pub fn semantic_neighbors(
        &self,
        seed: &SearchDocument,
        exclude_key: u128,
        limit: usize,
    ) -> io::Result<Vec<SearchHit>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let clauses = self.semantic_neighbor_clauses(seed, exclude_key);
        if clauses.is_empty() {
            return Ok(Vec::new());
        }

        let searcher = self.reader.searcher();
        let query = BooleanQuery::new(clauses);
        let top_docs = searcher
            .search(&query, &TopDocs::with_limit(limit))
            .map_err(|e| io::Error::other(format!("semantic search: {e}")))?;

        let mut hits = Vec::with_capacity(top_docs.len());
        for (score, doc_addr) in top_docs {
            let doc = searcher
                .doc::<TantivyDocument>(doc_addr)
                .map_err(|e| io::Error::other(format!("fetch doc: {e}")))?;
            hits.push(self.doc_to_hit(&doc, score));
        }

        if hits.is_empty() {
            return self.semantic_neighbors_fallback(seed, exclude_key, limit);
        }

        Ok(hits)
    }

    fn build_document(&self, doc: &SearchDocument) -> TantivyDocument {
        let key_hex = format!("{:032x}", doc.key);
        let mut tdoc = TantivyDocument::new();
        tdoc.add_text(self.fields.key_hex, &key_hex);
        tdoc.add_text(self.fields.func_name, &doc.func_name);
        tdoc.add_text(self.fields.func_name_demangled, &doc.func_name_demangled);
        tdoc.add_text(self.fields.lang, &doc.lang);
        tdoc.add_u64(self.fields.ts, doc.ts);
        for value in &doc.binary_names {
            tdoc.add_text(self.fields.binary_name, value);
        }
        for value in &doc.origin_tokens {
            tdoc.add_text(self.fields.origin_token, value);
        }
        for value in &doc.prototype_tokens {
            tdoc.add_text(self.fields.prototype_token, value);
        }
        for value in &doc.frame_tokens {
            tdoc.add_text(self.fields.frame_token, value);
        }
        for value in &doc.comment_tokens {
            tdoc.add_text(self.fields.comment_token, value);
        }
        for value in &doc.operand_tokens {
            tdoc.add_text(self.fields.operand_token, value);
        }
        for value in &doc.semantic_tokens {
            tdoc.add_text(self.fields.semantic_token, value);
        }
        if let Some(field) = self.fields.variant_token {
            for value in &doc.variant_tokens {
                tdoc.add_text(field, value);
            }
        }
        tdoc
    }

    fn query_fields(&self) -> Vec<Field> {
        vec![
            self.fields.func_name,
            self.fields.func_name_demangled,
            self.fields.binary_name,
            self.fields.origin_token,
            self.fields.prototype_token,
            self.fields.frame_token,
            self.fields.comment_token,
            self.fields.operand_token,
            self.fields.semantic_token,
        ]
    }

    fn search_internal(
        &self,
        query: &str,
        offset: usize,
        limit: usize,
    ) -> io::Result<(Vec<SearchHit>, usize)> {
        let query_str = query.trim();
        if query_str.is_empty() {
            return Ok((Vec::new(), 0));
        }

        let searcher = self.reader.searcher();
        let query_parser = QueryParser::for_index(&self.index, self.query_fields());
        let tantivy_query = query_parser.parse_query_lenient(query_str).0;

        let total_count = searcher
            .search(&tantivy_query, &Count)
            .map_err(|e| io::Error::other(format!("count: {e}")))?;

        let top_docs = searcher
            .search(&tantivy_query, &TopDocs::with_limit(offset + limit))
            .map_err(|e| io::Error::other(format!("search: {e}")))?;

        let mut hits = Vec::with_capacity(limit.min(top_docs.len().saturating_sub(offset)));
        for (score, doc_addr) in top_docs.into_iter().skip(offset) {
            let doc = searcher
                .doc::<TantivyDocument>(doc_addr)
                .map_err(|e| io::Error::other(format!("fetch doc: {e}")))?;
            hits.push(self.doc_to_hit(&doc, score));
        }

        Ok((hits, total_count))
    }

    fn doc_to_hit(&self, doc: &TantivyDocument, score: f32) -> SearchHit {
        let key_hex = doc
            .get_first(self.fields.key_hex)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let func_name = doc
            .get_first(self.fields.func_name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let func_name_demangled = doc
            .get_first(self.fields.func_name_demangled)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let lang = doc
            .get_first(self.fields.lang)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let binary_names: Vec<String> = doc
            .get_all(self.fields.binary_name)
            .filter_map(|v| v.as_str())
            .map(sanitize_basename)
            .filter(|s| !s.is_empty())
            .collect();

        let ts = doc
            .get_first(self.fields.ts)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        SearchHit::new_with_demangled(
            key_hex,
            func_name,
            func_name_demangled,
            lang,
            binary_names,
            ts,
            score,
        )
    }

    fn semantic_neighbor_clauses(
        &self,
        seed: &SearchDocument,
        exclude_key: u128,
    ) -> Vec<(Occur, Box<dyn Query>)> {
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        clauses.extend(self.weighted_term_clauses(
            self.fields.prototype_token,
            &seed.prototype_tokens,
            1.65,
            10,
        ));
        clauses.extend(self.weighted_term_clauses(
            self.fields.frame_token,
            &seed.frame_tokens,
            1.25,
            10,
        ));
        clauses.extend(self.weighted_term_clauses(
            self.fields.operand_token,
            &seed.operand_tokens,
            1.15,
            8,
        ));
        clauses.extend(self.weighted_term_clauses(
            self.fields.comment_token,
            &seed.comment_tokens,
            0.95,
            10,
        ));
        clauses.extend(self.weighted_term_clauses(
            self.fields.origin_token,
            &seed.origin_tokens,
            0.9,
            4,
        ));
        clauses.extend(self.weighted_term_clauses(
            self.fields.semantic_token,
            &seed.semantic_tokens,
            0.85,
            24,
        ));
        if let Some(field) = self.fields.variant_token {
            clauses.extend(self.weighted_term_clauses(field, &seed.semantic_tokens, 0.5, 24));
        }

        let exclude_term =
            Term::from_field_text(self.fields.key_hex, &format!("{:032x}", exclude_key));
        let exclude_query = TermQuery::new(exclude_term, IndexRecordOption::Basic);
        clauses.push((Occur::MustNot, Box::new(exclude_query)));
        clauses
    }

    fn weighted_term_clauses(
        &self,
        field: Field,
        tokens: &[String],
        base_weight: f32,
        max_terms: usize,
    ) -> Vec<(Occur, Box<dyn Query>)> {
        let mut ranked: Vec<(String, f32)> = best_neighbor_tokens(tokens, max_terms)
            .into_iter()
            .map(|token| {
                let weight = neighbor_token_priority(&token) * base_weight;
                (token, weight)
            })
            .collect();
        ranked.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Fingerprints preserve underscores; the indexed symbol analyzer splits
        // them. Use identical analysis and retain adjacency/order for compounds
        // instead of asking the index for an unindexed literal or loose parts.
        let mut analyzer = symbol_analyzer();
        let mut seen = std::collections::HashSet::new();
        ranked
            .into_iter()
            .filter_map(|(token, weight)| {
                let mut stream = analyzer.token_stream(&token);
                let mut terms = Vec::new();
                while stream.advance() {
                    // Bound query expansion for pathological compound tokens.
                    // Omit the whole token rather than querying a false prefix.
                    if terms.len() == 64 {
                        return None;
                    }
                    let part = stream.token();
                    terms.push((part.position, Term::from_field_text(field, &part.text)));
                }
                // Ranked input keeps the strongest representation when case or
                // punctuation differences collapse to the same indexed phrase.
                if !seen.insert(terms.clone()) {
                    return None;
                }
                let query: Box<dyn Query> = match terms.len() {
                    0 => return None,
                    1 => Box::new(TermQuery::new(terms.pop()?.1, IndexRecordOption::WithFreqs)),
                    _ => Box::new(PhraseQuery::new_with_offset(terms)),
                };
                let boosted = BoostQuery::new(query, weight.max(0.05));
                Some((Occur::Should, Box::new(boosted) as Box<dyn Query>))
            })
            .collect()
    }

    fn semantic_neighbors_fallback(
        &self,
        seed: &SearchDocument,
        exclude_key: u128,
        limit: usize,
    ) -> io::Result<Vec<SearchHit>> {
        let mut terms = Vec::new();
        terms.extend(best_neighbor_tokens(&seed.prototype_tokens, 6));
        terms.extend(best_neighbor_tokens(&seed.frame_tokens, 6));
        terms.extend(best_neighbor_tokens(&seed.comment_tokens, 8));
        terms.extend(best_neighbor_tokens(&seed.operand_tokens, 6));
        terms.extend(best_neighbor_tokens(&seed.origin_tokens, 4));
        terms.extend(best_neighbor_tokens(&seed.semantic_tokens, 12));

        if terms.is_empty() {
            return Ok(Vec::new());
        }

        terms.sort();
        terms.dedup();
        let query_str = terms
            .into_iter()
            .map(|token| token.replace('_', " "))
            .collect::<Vec<_>>()
            .join(" ");

        let searcher = self.reader.searcher();
        let query_parser = QueryParser::for_index(&self.index, self.query_fields());
        let query = query_parser.parse_query_lenient(&query_str).0;
        let top_docs = searcher
            .search(&query, &TopDocs::with_limit(limit.saturating_add(8)))
            .map_err(|e| io::Error::other(format!("semantic fallback: {e}")))?;

        let exclude_key_hex = format!("{:032x}", exclude_key);
        let mut hits = Vec::new();
        for (score, doc_addr) in top_docs {
            let doc = searcher
                .doc::<TantivyDocument>(doc_addr)
                .map_err(|e| io::Error::other(format!("fetch doc: {e}")))?;
            let hit = self.doc_to_hit(&doc, score);
            if hit.key_hex == exclude_key_hex {
                continue;
            }
            hits.push(hit);
            if hits.len() >= limit {
                break;
            }
        }
        Ok(hits)
    }
}

pub(super) fn best_neighbor_tokens(tokens: &[String], max_terms: usize) -> Vec<String> {
    let mut ranked: Vec<String> = tokens
        .iter()
        .filter(|token| !is_generic_neighbor_token(token))
        .cloned()
        .collect();
    ranked.sort_by(|a, b| {
        neighbor_token_priority(b)
            .partial_cmp(&neighbor_token_priority(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.len().cmp(&a.len()))
            .then_with(|| a.cmp(b))
    });
    ranked.dedup();
    ranked.truncate(max_terms);
    ranked
}

fn neighbor_token_priority(token: &str) -> f32 {
    let len = token.len();
    let mut score = if len >= 14 {
        1.45
    } else if len >= 10 {
        1.25
    } else if len >= 6 {
        1.0
    } else {
        0.8
    };
    if token.contains('_') {
        score += 0.12;
    }
    if token.chars().any(|ch| ch.is_ascii_digit()) {
        score += 0.04;
    }
    score
}

fn build_schema() -> Schema {
    build_schema_version(true)
}

fn build_schema_version(with_variants: bool) -> Schema {
    let mut builder = Schema::builder();

    let symbol_options = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("symbol")
                .set_index_option(IndexRecordOption::WithFreqsAndPositions),
        )
        .set_stored();
    let symbol_index_only = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("symbol")
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );

    let stored_only = TextOptions::default().set_stored();
    let key_options = TextOptions::default().set_stored().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("raw")
            .set_index_option(IndexRecordOption::Basic),
    );

    builder.add_text_field("key_hex", key_options);
    builder.add_text_field("func_name", symbol_options.clone());
    builder.add_text_field("func_name_demangled", symbol_options.clone());
    builder.add_text_field("lang", stored_only);
    builder.add_text_field("binary_name", symbol_options);
    builder.add_text_field("origin_token", symbol_index_only.clone());
    builder.add_text_field("prototype_token", symbol_index_only.clone());
    builder.add_text_field("frame_token", symbol_index_only.clone());
    builder.add_text_field("comment_token", symbol_index_only.clone());
    builder.add_text_field("operand_token", symbol_index_only.clone());
    builder.add_text_field("semantic_token", symbol_index_only.clone());
    builder.add_u64_field("ts", STORED);
    if with_variants {
        builder.add_text_field("variant_token", symbol_index_only);
    }

    builder.build()
}

fn symbol_analyzer() -> TextAnalyzer {
    TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .build()
}

fn register_tokenizers(index: &Index) {
    let raw = TextAnalyzer::builder(RawTokenizer::default()).build();
    index.tokenizers().register("symbol", symbol_analyzer());
    index.tokenizers().register("raw", raw);
}

impl SearchFields {
    fn load(schema: &Schema) -> io::Result<Self> {
        let get = |name: &str| {
            schema
                .get_field(name)
                .map_err(|e| io::Error::other(format!("{name} field missing: {e}")))
        };
        Ok(Self {
            key_hex: get("key_hex")?,
            func_name: get("func_name")?,
            func_name_demangled: get("func_name_demangled")?,
            lang: get("lang")?,
            binary_name: get("binary_name")?,
            origin_token: get("origin_token")?,
            prototype_token: get("prototype_token")?,
            frame_token: get("frame_token")?,
            comment_token: get("comment_token")?,
            operand_token: get("operand_token")?,
            semantic_token: get("semantic_token")?,
            variant_token: schema.get_field("variant_token").ok(),
            ts: get("ts")?,
        })
    }
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    #[test]
    fn legacy_schema_and_canonical_search_are_preserved() -> io::Result<()> {
        let root =
            std::env::temp_dir().join(format!("dazhbog-variant-schema-{}", std::process::id()));
        std::fs::create_dir(&root)?;
        let result = (|| -> io::Result<()> {
            let document = |key, name: &str, variant: &[&str]| SearchDocument {
                key,
                func_name: name.into(),
                func_name_demangled: String::new(),
                lang: String::new(),
                binary_names: vec![],
                origin_tokens: vec![],
                prototype_tokens: vec![],
                frame_tokens: vec![],
                comment_tokens: vec![],
                operand_tokens: vec![],
                semantic_tokens: vec![name.into()],
                variant_tokens: variant.iter().map(|s| s.to_string()).collect(),
                ts: 1,
            };
            let seed = document(1, "orchid", &[]);
            let hidden = document(2, "quartz", &["orchid"]);
            let distractor = document(3, "orchid_stub", &[]);
            for legacy in [true, false] {
                let dir = root.join(if legacy { "legacy" } else { "current" });
                std::fs::create_dir(&dir)?;
                if legacy {
                    Index::create_in_dir(&dir, build_schema_version(false))
                        .map_err(io::Error::other)?;
                }
                let index = SearchIndex::open(&dir)?;
                assert_eq!(index.has_variant_vocabulary(), !legacy);
                for doc in [&seed, &hidden, &distractor] {
                    index.index_function_no_commit(doc)?;
                }
                index.commit()?;
                let hits = index.semantic_neighbors(&seed, 1, 8)?;
                assert!(hits.iter().any(|hit| hit.key_hex == format!("{:032x}", 3)));
                assert_eq!(
                    hits.iter().any(|hit| hit.key_hex == format!("{:032x}", 2)),
                    !legacy
                );
                assert!(index
                    .search("orchid", 8)?
                    .iter()
                    .all(|hit| hit.key_hex != format!("{:032x}", 2)));
            }
            // An unmarked empty store with a legacy search directory is valid
            // for inspection, but replay must not certify it as a v4 projection.
            let mut cfg = crate::config::Config::default();
            let data_dir = root.join("uncertified");
            cfg.engine.data_dir = data_dir.to_string_lossy().into_owned();
            {
                let rt =
                    crate::engine::EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())?;
                rt.index_db.remove(b"canonical_projection_v4")?;
                rt.flush()?;
            }
            let search_dir = data_dir.join("search_index");
            std::fs::remove_dir_all(&search_dir)?;
            std::fs::create_dir(&search_dir)?;
            Index::create_in_dir(&search_dir, build_schema_version(false))
                .map_err(io::Error::other)?;
            {
                let rt = crate::engine::EngineRuntime::open_for_replay(
                    cfg.engine.clone(),
                    cfg.scoring.clone(),
                )?;
                assert!(rt.index_db.get(b"canonical_projection_v4")?.is_none());
            }
            assert!(
                crate::engine::EngineRuntime::open(cfg.engine.clone(), cfg.scoring.clone())
                    .is_err()
            );
            let prepared = crate::engine::EngineRuntime::prepare(cfg.engine, cfg.scoring)?;
            assert!(prepared.search.has_variant_vocabulary());
            assert!(prepared.index_db.get(b"canonical_projection_v4")?.is_some());
            Ok(())
        })();
        std::fs::remove_dir_all(root)?;
        result
    }
}
