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

    pub fn remaining(&self) -> u64 { self.cap - self.off }

    pub fn append(&mut self, rec: &Record) -> io::Result<Addr> {
        let name_len = rec.name.len() as u16;
        let data_len = rec.data.len() as u32;
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

        // body
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
        Ok(Record { key, ts_sec, prev_addr, len_bytes, popularity, name, data, flags })
    }
}

impl OpenSegments {
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
        // walk all segments; for each record, set index head to that address
        let rs = self.readers.lock();
        for r in rs.iter() {
            let len = r.file.metadata()?.len();
            let mut off = 0u64;
            while off + 12 < len {
                let mut hdr = [0u8;12];
                if let Err(_) = r.file.read_exact_at(&mut hdr, off) { break; }
                let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
                if magic != super::segment::MAGIC { break; }
                let rec_len = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as u64;
                if rec_len == 0 || off + rec_len > len { break; }
                // Read body minimal key+flags to seed index fast
                let mut keybuf = [0u8; 16 + 1 + 4]; // key + flags align (read enough)
                r.file.read_exact_at(&mut keybuf, off + 12)?;
                let lo = u64::from_le_bytes(keybuf[0..8].try_into().unwrap());
                let hi = u64::from_le_bytes(keybuf[8..16].try_into().unwrap());
                let key = ((hi as u128) << 64) | (lo as u128);
                let flags = { 
                    let mut fb = [0u8;1];
                    r.file.read_exact_at(&mut fb, off + 12 + 8 + 8 + 8 + 8 + 4 + 4 + 2 + 4)?; // offset to flags byte
                    fb[0]
                };
                let addr = crate::util::pack_addr(r.id, off, flags);
                // publish head
                if flags & 0x01 == 0x01 {
                    // tombstone: delete head
                    index.delete(key);
                } else {
                    index.upsert(key, addr);
                }
                off += rec_len as u64;
            }
        }
        Ok(())
    }
}
