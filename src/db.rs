use crate::engine::{EngineRuntime, Record, UpsertResult, IndexError};
use crate::config::Config;
use crate::util::{addr_off, addr_seg};

use std::{io, sync::Arc};

#[derive(Clone)]
pub struct Database {
    rt: Arc<EngineRuntime>,
}

#[derive(Debug, Clone)]
pub struct FuncLatest {
    pub popularity: u32,
    pub len_bytes: u32,
    pub name: String,
    pub data: Vec<u8>,
}

impl Database {
    pub async fn open(cfg: Arc<Config>) -> io::Result<Arc<Self>> {
        let rt = EngineRuntime::open(cfg.engine.clone())?;
        Ok(Arc::new(Self { rt: Arc::new(rt) }))
    }

    pub async fn get_latest(&self, key: u128) -> io::Result<Option<FuncLatest>> {
        let addr = self.rt.index.get(key);
        if addr == 0 { return Ok(None); }
        let seg_id = addr_seg(addr);
        let off = addr_off(addr);
        let reader = self.rt.segments.get_reader(seg_id).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "segment not found"))?;
        let rec = reader.read_at(off)?;
        if rec.flags & 0x01 == 0x01 { return Ok(None); }
        Ok(Some(FuncLatest {
            popularity: rec.popularity,
            len_bytes: rec.len_bytes,
            name: rec.name,
            data: rec.data,
        }))
    }

    pub async fn push(&self, items: &[(u128, u32, u32, &str, &[u8])]) -> io::Result<Vec<u32>> {
        // status: 1 if new unique key, 0 if update (changed metadata), 2 if unchanged (skipped)
        let mut status = Vec::with_capacity(items.len());
        for (key, pop, _len_bytes_decl, name, data) in items.iter() {
            // Enforce invariants at ingestion; avoid any possibility of on-disk mismatch
            if name.len() > u16::MAX as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long (> u16::MAX)"));
            }
            if data.len() > u32::MAX as usize {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "data large (> u32::MAX)"));
            }

            let old = self.rt.index.get(*key);
            
            // Check if metadata has actually changed
            if old != 0 {
                let seg_id = crate::util::addr_seg(old);
                let off = crate::util::addr_off(old);
                match self.rt.segments.get_reader(seg_id) {
                    Some(reader) => {
                        match reader.read_at(off) {
                            Ok(existing) => {
                                // Skip if name and data are identical (ignoring popularity/timestamp)
                                if existing.name == *name && existing.data == *data {
                                    status.push(2); // unchanged/skipped
                                    continue;
                                }
                            },
                            Err(e) => {
                                log::warn!("Failed to read existing record at seg={}, off={}: {}", seg_id, off, e);
                                // Proceed with update on read error
                            }
                        }
                    },
                    None => {
                        log::warn!("Segment {} not found for existing record", seg_id);
                        // Proceed with update if segment missing
                    }
                }
            }
            
            let rec = Record {
                key: *key,
                ts_sec: crate::util::now_ts_sec(),
                prev_addr: old,
                len_bytes: (*data).len() as u32, // authoritative: actual data length
                popularity: *pop,
                name: name.to_string(),
                data: data.to_vec(),
                flags: 0,
            };
            let addr = self.rt.segments.append(&rec)?;
            match self.rt.index.upsert(*key, addr) {
                Ok(UpsertResult::Inserted) => status.push(1),
                Ok(UpsertResult::Replaced(_)) => status.push(0),
                Err(IndexError::Full) => {
                    crate::metrics::METRICS.append_failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Err(io::Error::new(io::ErrorKind::Other, "index full"));
                }
            }
        }
        Ok(status)
    }

    pub async fn delete_keys(&self, keys: &[u128]) -> io::Result<u32> {
        let mut deleted = 0u32;
        for &key in keys {
            let old = self.rt.index.get(key);
            let rec = Record {
                key,
                ts_sec: crate::util::now_ts_sec(),
                prev_addr: old,
                len_bytes: 0,
                popularity: 0,
                name: String::new(),
                data: Vec::new(),
                flags: 0x01, // tombstone
            };
            let addr = self.rt.segments.append(&rec)?;
            // For tombstones, we still write to disk even if index is full
            let _ = self.rt.index.upsert(key, addr);
            if old != 0 { deleted += 1; }
        }
        Ok(deleted)
    }

    pub async fn get_history(&self, key: u128, mut limit: u32) -> io::Result<Vec<(u64,String,Vec<u8>)>> {
        if limit == 0 { return Ok(vec![]); }
        let mut out = Vec::new();
        let mut addr = self.rt.index.get(key);
        while addr != 0 && limit > 0 {
            let r = self.rt.segments.get_reader(addr_seg(addr)).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "seg"))?;
            let rec = r.read_at(addr_off(addr))?;
            if rec.flags & 0x01 == 0 { // skip tombstones
                out.push((rec.ts_sec, rec.name, rec.data));
                limit -= 1;
            }
            addr = rec.prev_addr;
        }
        Ok(out)
    }
}
