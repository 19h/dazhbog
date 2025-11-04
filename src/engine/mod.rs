mod crc32c;
mod segment;
mod index;
mod spin;

pub use segment::{Record, OpenSegments};
pub use index::{ShardedIndex, UpsertResult, IndexError};

use crate::config::Engine;
use std::{io, path::PathBuf, sync::Arc};

#[derive(Clone)]
pub struct EngineRuntime {
    #[allow(dead_code)]
    pub dir: PathBuf,
    pub segments: Arc<OpenSegments>,
    pub index: Arc<ShardedIndex>,
    #[allow(dead_code)]
    pub cfg: Engine,
}

impl EngineRuntime {
    pub fn open(cfg: Engine) -> io::Result<Self> {
        std::fs::create_dir_all(&cfg.data_dir)?;
        let dir = PathBuf::from(&cfg.data_dir);
        let segments = Arc::new(OpenSegments::open(&dir, cfg.segment_bytes, cfg.use_mmap_reads)?);
        
        // Deduplication (if enabled)
        if cfg.deduplicate_on_startup {
            segments.deduplicate()?;
        }
        
        let index = Arc::new(ShardedIndex::new(cfg.index_capacity, cfg.shard_count));
        // Recovery: scan segments and rebuild index
        segments.rebuild_index(&index)?;
        Ok(Self { dir, segments, index, cfg })
    }
}
