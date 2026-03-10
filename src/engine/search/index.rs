//! Full-text search index using Tantivy.

use super::types::{SearchDocument, SearchHit};
use std::{io, path::Path};
use tantivy::collector::{Count, TopDocs};
use tantivy::query::{BooleanQuery, BoostQuery, Occur, Query, QueryParser, TermQuery};
use tantivy::schema::{Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, STORED};
use tantivy::tokenizer::{LowerCaser, RawTokenizer, SimpleTokenizer, TextAnalyzer};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term};

const NEIGHBOR_STOPWORDS: &[&str] = &[
    "__cdecl",
    "__fastcall",
    "__stdcall",
    "__thiscall",
    "__vectorcall",
    "__usercall",
    "__userpurge",
    "__hidden",
    "__int16",
    "__int64",
    "__cxx11",
    "__src",
    "__dst",
    "__formal",
    "__return_ptr",
    "__struct_ptr",
    "arg",
    "args",
    "argsize",
    "argloc",
    "bool",
    "byte",
    "char",
    "cdecl",
    "const",
    "default",
    "defaults",
    "dispatch",
    "dispatcher",
    "double",
    "error",
    "errors",
    "err",
    "uuu",
    "u20",
    "u7b",
    "u7d",
    "0ca",
    "entry",
    "field",
    "float",
    "frame",
    "frregs",
    "frsize",
    "func",
    "function",
    "int",
    "loc",
    "long",
    "null",
    "offset",
    "param",
    "ptr",
    "qword",
    "ret",
    "return",
    "short",
    "signed",
    "size",
    "state",
    "stdcall",
    "struct",
    "sub",
    "switch",
    "table",
    "jumptable",
    "case",
    "cases",
    "this",
    "thiscall",
    "type",
    "uint",
    "ulong",
    "unsigned",
    "ushort",
    "var",
    "vectorcall",
    "void",
    "word",
    "backend",
    "frontend",
    "engine",
    "context",
    "module",
    "common",
    "generic",
    "internal",
    "impl",
    "handler",
    "manager",
    "emulator",
    "x86",
    "x64",
    "x86_64",
    "amd64",
    "arm",
    "arm64",
    "aarch64",
    "mips",
    "ppc",
    "sse",
    "avx",
    "neon",
    "qeaa",
    "qeax",
    "qeba",
    "qeav",
    "qeaaxxz",
    "ueaa",
    "ueba",
    "ueaapeaxi",
    "ueaaxxz",
    "aeaa",
    "aeav",
    "aeaaxxz",
    "aebv",
    "aeaufframe",
    "peav",
    "yapeavufunction",
    "yapeavuclass",
    "sapeavuclass",
    "sapeavuscriptstruct",
    "saxpeavuobject",
    "zzappendmembergetprev",
    "vfmember",
    "back_chain",
    "sender_sp",
    "retstr",
    "saved_r4",
    "deleting",
    "cold",
    "v_0",
    "_lambda_1_",
    "oword",
];

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

    truncate_utf8(base, 255).to_string()
}

fn truncate_utf8(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }

    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }

    &input[..end]
}

#[cfg(test)]
mod tests {
    use super::{sanitize_basename, truncate_utf8};

    #[test]
    fn truncate_utf8_respects_char_boundaries() {
        let input = format!("{}{}", "a".repeat(254), "é");
        assert_eq!(truncate_utf8(&input, 255), "a".repeat(254));
    }

    #[test]
    fn sanitize_basename_truncates_without_panicking() {
        let input = format!("/tmp/{}{}", "a".repeat(254), "é");
        let sanitized = sanitize_basename(&input);

        assert_eq!(sanitized, "a".repeat(254));
        assert!(sanitized.is_ascii());
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
    ts: Field,
}

impl SearchIndex {
    /// Open or create a search index at the given directory.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let schema = build_schema();

        let index = match Index::open_in_dir(dir) {
            Ok(idx) => idx,
            Err(_) => Index::create_in_dir(dir, schema.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("create index: {e}")))?,
        };

        register_tokenizers(&index);
        let (index, fields) = match SearchFields::load(&index.schema()) {
            Ok(fields) => (index, fields),
            Err(_) => {
                drop(index);
                if dir.exists() {
                    std::fs::remove_dir_all(dir)?;
                }
                std::fs::create_dir_all(dir)?;
                let rebuilt = Index::create_in_dir(dir, schema).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("recreate index: {e}"))
                })?;
                register_tokenizers(&rebuilt);
                let fields = SearchFields::load(&rebuilt.schema())?;
                (rebuilt, fields)
            }
        };

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reader: {e}")))?;

        let writer = index
            .writer(50_000_000)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("writer: {e}")))?;

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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("add doc: {e}")))?;
        Ok(())
    }

    /// Commit pending changes and reload the reader.
    pub fn commit(&self) -> io::Result<()> {
        let mut writer = self.writer.lock();
        writer
            .commit()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reload: {e}")))?;
        Ok(())
    }

    /// Delete a function from the index.
    pub fn delete(&self, key: u128) -> io::Result<()> {
        let key_hex = format!("{:032x}", key);
        let mut writer = self.writer.lock();
        writer.delete_term(Term::from_field_text(self.fields.key_hex, &key_hex));
        writer
            .commit()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reload: {e}")))?;
        Ok(())
    }

    /// Rebuild the entire index from an iterator of documents.
    pub fn rebuild<I>(&self, docs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = SearchDocument>,
    {
        let mut writer = self.writer.lock();
        writer.delete_all_documents().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("search index delete_all_documents: {e}"),
            )
        })?;

        for doc in docs.into_iter() {
            let tdoc = self.build_document(&doc);
            writer
                .add_document(tdoc)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("add doc: {e}")))?;
        }

        writer
            .commit()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reload: {e}")))?;
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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("semantic search: {e}")))?;

        let mut hits = Vec::with_capacity(top_docs.len());
        for (score, doc_addr) in top_docs {
            let doc = searcher
                .doc(doc_addr)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("fetch doc: {e}")))?;
            hits.push(self.doc_to_hit(&doc, score));
        }

        if hits.is_empty() {
            return self.semantic_neighbors_fallback(seed, exclude_key, limit);
        }

        Ok(hits)
    }

    fn build_document(&self, doc: &SearchDocument) -> tantivy::Document {
        let key_hex = format!("{:032x}", doc.key);
        let mut tdoc = tantivy::Document::new();
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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("count: {e}")))?;

        let top_docs = searcher
            .search(&tantivy_query, &TopDocs::with_limit(offset + limit))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("search: {e}")))?;

        let mut hits = Vec::with_capacity(limit.min(top_docs.len().saturating_sub(offset)));
        for (score, doc_addr) in top_docs.into_iter().skip(offset) {
            let doc = searcher
                .doc(doc_addr)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("fetch doc: {e}")))?;
            hits.push(self.doc_to_hit(&doc, score));
        }

        Ok((hits, total_count))
    }

    fn doc_to_hit(&self, doc: &tantivy::Document, score: f32) -> SearchHit {
        let key_hex = doc
            .get_first(self.fields.key_hex)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string();

        let func_name = doc
            .get_first(self.fields.func_name)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string();

        let func_name_demangled = doc
            .get_first(self.fields.func_name_demangled)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string();

        let lang = doc
            .get_first(self.fields.lang)
            .and_then(|v| v.as_text())
            .unwrap_or("")
            .to_string();

        let binary_names: Vec<String> = doc
            .get_all(self.fields.binary_name)
            .filter_map(|v| v.as_text())
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

        ranked
            .into_iter()
            .map(|(token, weight)| {
                let term = Term::from_field_text(field, &token);
                let query = TermQuery::new(term, IndexRecordOption::WithFreqs);
                let boosted = BoostQuery::new(Box::new(query), weight.max(0.05));
                (Occur::Should, Box::new(boosted) as Box<dyn Query>)
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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("semantic fallback: {e}")))?;

        let exclude_key_hex = format!("{:032x}", exclude_key);
        let mut hits = Vec::new();
        for (score, doc_addr) in top_docs {
            let doc = searcher
                .doc(doc_addr)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("fetch doc: {e}")))?;
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

fn best_neighbor_tokens(tokens: &[String], max_terms: usize) -> Vec<String> {
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

fn is_generic_neighbor_token(token: &str) -> bool {
    let raw_lower = token.trim().to_ascii_lowercase();
    let normalized = token
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
        .to_ascii_lowercase();
    normalized.len() < 3
        || normalized.chars().all(|ch| ch.is_ascii_digit())
        || NEIGHBOR_STOPWORDS.contains(&raw_lower.as_str())
        || NEIGHBOR_STOPWORDS.contains(&normalized.as_str())
        || (normalized.starts_with("__") && normalized.ends_with("call"))
        || matches!(
            normalized.as_str(),
            "x86" | "x64" | "x86_64" | "amd64" | "arm" | "arm64" | "aarch64" | "mips" | "ppc"
        )
        || matches!(
            normalized.as_str(),
            "rax"
                | "rbx"
                | "rcx"
                | "rdx"
                | "rsi"
                | "rdi"
                | "rbp"
                | "rsp"
                | "eax"
                | "ebx"
                | "ecx"
                | "edx"
                | "esi"
                | "edi"
                | "ebp"
                | "esp"
                | "ax"
                | "bx"
                | "cx"
                | "dx"
                | "si"
                | "di"
                | "bp"
                | "sp"
                | "lr"
                | "pc"
                | "fp"
        )
        || normalized
            .strip_prefix('r')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
        || normalized
            .strip_prefix('x')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
        || normalized
            .strip_prefix('w')
            .map(|rest| rest.chars().all(|ch| ch.is_ascii_digit()) && !rest.is_empty())
            .unwrap_or(false)
        || normalized
            .strip_prefix("__m")
            .map(|rest| !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit()))
            .unwrap_or(false)
}

fn build_schema() -> Schema {
    let mut builder = Schema::builder();

    let symbol_options = TextOptions::default()
        .set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("symbol")
                .set_index_option(IndexRecordOption::WithFreqs),
        )
        .set_stored();
    let symbol_index_only = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("symbol")
            .set_index_option(IndexRecordOption::WithFreqs),
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
    builder.add_text_field("semantic_token", symbol_index_only);
    builder.add_u64_field("ts", STORED);

    builder.build()
}

fn register_tokenizers(index: &Index) {
    let symbol = TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .build();
    let raw = TextAnalyzer::builder(RawTokenizer::default()).build();
    index.tokenizers().register("symbol", symbol);
    index.tokenizers().register("raw", raw);
}

impl SearchFields {
    fn load(schema: &Schema) -> io::Result<Self> {
        let get = |name: &str| {
            schema.get_field(name).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("{name} field missing: {e}"))
            })
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
            ts: get("ts")?,
        })
    }
}
