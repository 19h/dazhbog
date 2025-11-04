use std::{io, fs::{File, OpenOptions}, path::{Path, PathBuf}, os::unix::fs::FileExt};
#[cfg(windows)] use std::os::windows::fs::FileExt as _;

use crate::engine::crc32c::crc32c;
use crate::util::pack_addr;

pub type Addr = u64;

const MAGIC: u32 = 0x4C4D4E31; // 'L','M','N','1'

#[derive(Clone)]
pub struct Record {
    pub key: u128,
    pub ts_sec: u64,
    pub prev_addr: Addr,
    pub len_bytes: u32,
    pub popularity: u32,
    pub name: String,
    pub data: Vec<u8>,
    pub flags: u8, // 0=normal, 1=tombstone
}

pub struct SegmentWriter {
    file: File,
    id: u16,
    cap: u64,
    off: u64,
}

pub struct SegmentReader {
    file: File,
    pub id: u16,
}

pub struct OpenSegments {
    dir: PathBuf,
    pub current: std::sync::Mutex<SegmentWriter>,
    pub readers: parking_lot::Mutex<Vec<SegmentReader>>,
    #[allow(dead_code)]
    pub use_mmap: bool, // currently unused; retained for future optimization
    pub seg_bytes: u64,
}

impl SegmentWriter {
    fn open(path: &Path, id: u16, cap: u64) -> io::Result<Self> {
        let p = path.join(format!("seg.{:05}.dat", id));
        let file = OpenOptions::new().create(true).read(true).append(true).open(&p)?;
        let off = file.metadata()?.len();
        Ok(Self { file, id, cap, off })
    }

    pub fn append(&mut self, rec: &Record) -> io::Result<Addr> {
        // --- STRONG INVARIANTS ---
        // 1) name length must fit in u16 (on-disk format)
        if rec.name.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "record.name too long (> u16::MAX)"));
        }
        // 2) declared len_bytes must match actual data length
        if rec.len_bytes as usize != rec.data.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "record.len_bytes mismatch with data length"));
        }

        let name_len = rec.name.len() as u16;
        let data_len = rec.data.len() as u32;

        // Body layout size (in bytes); keep in sync with reader
        let body_len: usize = 8+8+8+8+4+4+2+4+1+5 + (name_len as usize) + (data_len as usize);
        let total_len = 4 + 4 + 4 + body_len; // magic + rec_len + crc + body

        if self.off + (total_len as u64) > self.cap {
            return Err(io::Error::new(io::ErrorKind::Other, "segment full"));
        }

        let mut buf = Vec::with_capacity(total_len);
        let rec_len = total_len as u32;

        // header placeholders
        buf.extend_from_slice(&MAGIC.to_le_bytes());
        buf.extend_from_slice(&rec_len.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // CRC placeholder

        // body (LE)
        buf.extend_from_slice(&(rec.key as u64).to_le_bytes());
        buf.extend_from_slice(&((rec.key >> 64) as u64).to_le_bytes());
        buf.extend_from_slice(&rec.ts_sec.to_le_bytes());
        buf.extend_from_slice(&rec.prev_addr.to_le_bytes());
        buf.extend_from_slice(&rec.len_bytes.to_le_bytes());
        buf.extend_from_slice(&rec.popularity.to_le_bytes());
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&data_len.to_le_bytes());
        buf.push(rec.flags);
        buf.extend_from_slice(&[0u8;5]); // pad to 8
        buf.extend_from_slice(rec.name.as_bytes());
        buf.extend_from_slice(&rec.data);

        // crc over body
        let crc = crc32c(0, &buf[12..]);
        buf[8..12].copy_from_slice(&crc.to_le_bytes());

        let offset = self.off;
        self.file.write_all_at(&buf, offset)?;
        self.off += buf.len() as u64;
        Ok(pack_addr(self.id, offset, rec.flags))
    }
}

impl Clone for SegmentReader {
    fn clone(&self) -> Self {
        Self {
            file: self.file.try_clone().expect("failed to clone file handle"),
            id: self.id,
        }
    }
}

impl SegmentReader {
    fn open(path: &Path, id: u16) -> io::Result<Self> {
        let p = path.join(format!("seg.{:05}.dat", id));
        let file = OpenOptions::new().read(true).open(&p)?;
        Ok(Self { file, id })
    }

    pub fn read_at(&self, offset: u64) -> io::Result<Record> {
        let mut hdr = [0u8;12];
        self.file.read_exact_at(&mut hdr, offset)?;
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        if magic != MAGIC { return Err(io::Error::new(io::ErrorKind::InvalidData, "bad magic")); }
        let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let crc = u32::from_le_bytes(hdr[8..12].try_into().unwrap());
        let mut body = vec![0u8; rec_len - 12];
        self.file.read_exact_at(&mut body, offset + 12)?;
        let crc2 = crc32c(0, &body);
        if crc != crc2 { return Err(io::Error::new(io::ErrorKind::InvalidData, "crc mismatch")); }
        let p = &body[..];
        let lo = u64::from_le_bytes(p[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(p[8..16].try_into().unwrap());
        let key = ((hi as u128) << 64) | (lo as u128);
        let ts_sec = u64::from_le_bytes(p[16..24].try_into().unwrap());
        let prev_addr = u64::from_le_bytes(p[24..32].try_into().unwrap());
        let len_bytes = u32::from_le_bytes(p[32..36].try_into().unwrap());
        let popularity = u32::from_le_bytes(p[36..40].try_into().unwrap());
        let name_len = u16::from_le_bytes(p[40..42].try_into().unwrap()) as usize;
        let data_len = u32::from_le_bytes(p[42..46].try_into().unwrap()) as usize;
        let flags = p[46];
        let name_start = 52;
        let name = std::str::from_utf8(&p[name_start .. name_start+name_len]).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "utf8"))?.to_string();
        let data_start = name_start + name_len;
        let data = p[data_start .. data_start+data_len].to_vec();

        // Backwards compatibility: if len_bytes doesn't match data_len, use actual data length
        // (Old data may have been written before strict invariant was enforced)
        let actual_len_bytes = if data_len != len_bytes as usize {
            log::debug!("Record at offset {} has len_bytes={} but data_len={}, using actual data length", 
                       "unknown", len_bytes, data_len);
            data_len as u32
        } else {
            len_bytes
        };

        Ok(Record { key, ts_sec, prev_addr, len_bytes: actual_len_bytes, popularity, name, data, flags })
    }
}

// Helper struct for progress reporting
struct ProgressReporter {
    total_size: u64,
    processed_size: u64,
    last_progress: u8,
}

impl ProgressReporter {
    fn new(total_size: u64) -> Self {
        Self {
            total_size,
            processed_size: 0,
            last_progress: 0,
        }
    }
    
    fn update(&mut self, bytes: u64, operation: &str) {
        if self.total_size == 0 {
            return;
        }
        
        self.processed_size += bytes;
        let progress = ((self.processed_size as f64 / self.total_size as f64) * 100.0) as u8;
        if progress >= self.last_progress + 10 && progress <= 100 {
            log::info!("{}: {}%", operation, progress);
            self.last_progress = progress;
        }
    }
}

// Record scanner callback return values
#[allow(dead_code)]
enum ScanAction {
    Continue,
    Break,
}

impl OpenSegments {
    // Helper: calculate total size of all segment files
    fn total_segment_size(&self, readers: &[SegmentReader]) -> u64 {
        readers.iter()
            .filter_map(|r| r.file.metadata().ok())
            .map(|m| m.len())
            .sum()
    }
    
    // Helper: scan all records with a callback
    // Callback receives (reader, offset, rec_len, key, flags)
    fn scan_records<F>(&self, readers: &[SegmentReader], mut callback: F) -> io::Result<u64>
    where
        F: FnMut(&SegmentReader, u64, u64, u128, u8) -> io::Result<ScanAction>,
    {
        const MIN_STRUCTURED_SIZE: u64 = 12 + 16 + 8 + 8 + 4 + 4 + 2 + 4 + 1;
        let mut total_processed = 0u64;
        
        for r in readers.iter() {
            let len = r.file.metadata()?.len();
            let mut off = 0u64;
            
            while off + 12 < len {
                let mut hdr = [0u8; 12];
                if r.file.read_exact_at(&mut hdr, off).is_err() {
                    break;
                }
                
                let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
                if magic != MAGIC {
                    break;
                }
                
                let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as u64;
                if rec_len == 0 || off + rec_len > len {
                    break;
                }
                
                if rec_len < MIN_STRUCTURED_SIZE {
                    log::warn!("Skipping malformed record at offset {}: rec_len {} < minimum {}", off, rec_len, MIN_STRUCTURED_SIZE);
                    off += rec_len;
                    total_processed += rec_len;
                    continue;
                }
                
                // Read key and flags
                let mut keybuf = [0u8; 16];
                r.file.read_exact_at(&mut keybuf, off + 12)?;
                let lo = u64::from_le_bytes(keybuf[0..8].try_into().unwrap());
                let hi = u64::from_le_bytes(keybuf[8..16].try_into().unwrap());
                let key = ((hi as u128) << 64) | (lo as u128);
                
                let mut fb = [0u8; 1];
                r.file.read_exact_at(&mut fb, off + 12 + 8 + 8 + 8 + 8 + 4 + 4 + 2 + 4)?;
                let flags = fb[0];
                
                match callback(r, off, rec_len, key, flags)? {
                    ScanAction::Continue => {},
                    ScanAction::Break => return Ok(total_processed),
                }
                
                off += rec_len;
                total_processed += rec_len;
            }
        }
        
        Ok(total_processed)
    }
    
    pub fn open(dir: &Path, seg_bytes: u64, use_mmap: bool) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        // determine next segment id
        let mut max_id = None;
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("seg.") && name.ends_with(".dat") {
                    let mid = &name[4..9];
                    if let Ok(id) = mid.parse::<u16>() {
                        max_id = Some(max_id.map_or(id, |m: u16| m.max(id)));
                    }
                }
            }
        }
        let id = max_id.map_or(1u16, |v| v);
        let writer = SegmentWriter::open(dir, id, seg_bytes)?;
        let mut readers = Vec::new();
        for sid in 1..=id {
            readers.push(SegmentReader::open(dir, sid)?);
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            current: std::sync::Mutex::new(writer),
            readers: parking_lot::Mutex::new(readers),
            use_mmap,
            seg_bytes,
        })
    }

    pub fn next_writer(&self) -> io::Result<()> {
        let mut w = self.current.lock().unwrap();
        let new_id = w.id.checked_add(1).ok_or_else(|| io::Error::new(io::ErrorKind::Other, "segment id overflow"))?;
        let nw = SegmentWriter::open(&self.dir, new_id, self.seg_bytes)?;
        // new reader for this segment
        {
            let mut r = self.readers.lock();
            r.push(SegmentReader::open(&self.dir, new_id)?);
        }
        *w = nw;
        Ok(())
    }

    pub fn get_reader(&self, seg_id: u16) -> Option<SegmentReader> {
        let rs = self.readers.lock();
        rs.iter().find(|r| r.id == seg_id).cloned()
    }

    pub fn append(&self, rec: &Record) -> io::Result<Addr> {
        let mut writer = self.current.lock().unwrap();
        match writer.append(rec) {
            Ok(addr) => Ok(addr),
            Err(e) if e.kind() == io::ErrorKind::Other && e.to_string().contains("segment full") => {
                drop(writer);
                self.next_writer()?;
                let mut writer = self.current.lock().unwrap();
                writer.append(rec)
            },
            Err(e) => Err(e),
        }
    }

    pub fn rebuild_index(&self, index: &crate::engine::index::ShardedIndex) -> io::Result<()> {
        let rs = self.readers.lock();
        let total_size = self.total_segment_size(&rs);
        
        if total_size > 0 {
            log::info!("Loading segments: {:.2} MB total", total_size as f64 / 1_048_576.0);
        }
        
        let mut progress = ProgressReporter::new(total_size);
        
        self.scan_records(&rs, |r, off, rec_len, key, flags| {
            let addr = crate::util::pack_addr(r.id, off, flags);
            
            if flags & 0x01 == 0x01 {
                // tombstone: delete head
                index.delete(key);
            } else {
                // During rebuild, log but ignore index full errors
                if let Err(_) = index.upsert(key, addr) {
                    log::warn!("Index full during rebuild for key {:032x}", key);
                }
            }
            
            progress.update(rec_len, "Loading segments");
            Ok(ScanAction::Continue)
        })?;
        
        if total_size > 0 {
            log::info!("Segments loaded successfully");
        }
        
        Ok(())
    }
    
    /// Deduplicate records: for each key, keep only records with unique (name, data) combinations
    /// Returns (records_before, records_after, bytes_saved)
    pub fn deduplicate(&self) -> io::Result<(u64, u64, u64)> {
        use std::collections::HashMap;
        
        log::info!("Starting deduplication...");
        
        // Step 1: Scan all records and build deduplication map
        let rs = self.readers.lock();
        let total_size = self.total_segment_size(&rs);
        
        log::info!("Scanning {:.2} MB for duplicates...", total_size as f64 / 1_048_576.0);
        
        // Map: key -> Vec<(addr, ts_sec, name, data, rec_len)>
        let mut key_records: HashMap<u128, Vec<(Addr, u64, String, Vec<u8>, u64)>> = HashMap::new();
        let mut total_records = 0u64;
        let mut total_bytes = 0u64;
        let mut progress = ProgressReporter::new(total_size);
        
        self.scan_records(&rs, |r, off, rec_len, _key, flags| {
            if flags & 0x01 == 0 { // Skip tombstones
                if let Ok(rec) = r.read_at(off) {
                    let addr = crate::util::pack_addr(r.id, off, rec.flags);
                    key_records.entry(rec.key)
                        .or_insert_with(Vec::new)
                        .push((addr, rec.ts_sec, rec.name, rec.data, rec_len));
                    total_records += 1;
                    total_bytes += rec_len;
                }
            }
            
            progress.update(rec_len, "Scanning");
            Ok(ScanAction::Continue)
        })?;
        
        drop(rs); // Release lock before rewriting
        
        log::info!("Found {} total records across {} unique keys", total_records, key_records.len());
        
        // Step 2: Identify unique records to keep
        let mut keep_addrs = std::collections::HashSet::new();
        let mut duplicates = 0u64;
        
        for (_key, records) in key_records.iter_mut() {
            if records.len() <= 1 {
                // Single record, keep it
                if let Some((addr, _, _, _, _)) = records.first() {
                    keep_addrs.insert(*addr);
                }
                continue;
            }
            
            // Sort by timestamp descending (newest first)
            records.sort_by(|a, b| b.1.cmp(&a.1));
            
            // Track unique (name, data) combinations
            let mut seen = std::collections::HashSet::new();
            for (addr, _ts, name, data, _len) in records.iter() {
                let signature = (name.as_str(), data.as_slice());
                if seen.insert(signature) {
                    keep_addrs.insert(*addr);
                } else {
                    duplicates += 1;
                }
            }
        }
        
        let records_to_keep = keep_addrs.len() as u64;
        log::info!("Keeping {} unique records, removing {} duplicates", records_to_keep, duplicates);
        
        if duplicates == 0 {
            log::info!("No duplicates found, skipping rewrite");
            return Ok((total_records, total_records, 0));
        }
        
        // Step 3: Write deduplicated segments
        log::info!("Writing deduplicated segments...");
        
        let temp_dir = self.dir.join(".dedup_temp");
        std::fs::create_dir_all(&temp_dir)?;
        
        let mut new_writer = SegmentWriter::open(&temp_dir, 1, self.seg_bytes)?;
        let mut written_records = 0u64;
        let mut written_bytes = 0u64;
        let mut write_progress = ProgressReporter::new(records_to_keep * 100); // Estimate based on record count
        
        let rs = self.readers.lock();
        self.scan_records(&rs, |r, off, rec_len, _key, _flags| {
            let addr = crate::util::pack_addr(r.id, off, 0);
            
            if keep_addrs.contains(&addr) {
                if let Ok(rec) = r.read_at(off) {
                    // Write record with prev_addr = 0 (chains will be rebuilt by index)
                    let new_rec = Record {
                        key: rec.key,
                        ts_sec: rec.ts_sec,
                        prev_addr: 0,
                        len_bytes: rec.len_bytes,
                        popularity: rec.popularity,
                        name: rec.name,
                        data: rec.data,
                        flags: rec.flags,
                    };
                    new_writer.append(&new_rec)?;
                    written_records += 1;
                    written_bytes += rec_len;
                    write_progress.update(100, "Writing");
                }
            }
            
            Ok(ScanAction::Continue)
        })?;
        drop(rs);
        drop(new_writer);
        
        // Step 4: Replace old segments with new ones
        log::info!("Replacing segments...");
        
        // Close all readers before deleting
        {
            let mut rs = self.readers.lock();
            rs.clear();
        }
        
        // Delete old segment files
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("seg.") && name.ends_with(".dat") {
                    std::fs::remove_file(entry.path())?;
                }
            }
        }
        
        // Move new segments to data dir
        for entry in std::fs::read_dir(&temp_dir)? {
            let entry = entry?;
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with("seg.") && name.ends_with(".dat") {
                    let dest = self.dir.join(name);
                    std::fs::rename(entry.path(), dest)?;
                }
            }
        }
        std::fs::remove_dir(&temp_dir)?;
        
        // Reopen readers
        {
            let mut rs = self.readers.lock();
            rs.push(SegmentReader::open(&self.dir, 1)?);
        }
        
        // Update current writer
        {
            let mut w = self.current.lock().unwrap();
            *w = SegmentWriter::open(&self.dir, 1, self.seg_bytes)?;
        }
        
        let bytes_saved = total_bytes - written_bytes;
        log::info!(
            "Deduplication complete: {} -> {} records, saved {:.2} MB ({:.1}%)",
            total_records,
            written_records,
            bytes_saved as f64 / 1_048_576.0,
            (bytes_saved as f64 / total_bytes as f64) * 100.0
        );
        
        Ok((total_records, written_records, bytes_saved))
    }
}
