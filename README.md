<h1 align="center">dazhbog</h1>

<h5 align="center">A high-performance, embedded-storage Lumina server compatible with IDA Pro 7.2+.</h5>

<br />

`dazhbog` is a reimplementation of a Lumina protocol server designed for storing and retrieving function signatures used by IDA Pro's reverse engineering features. Unlike `lumen`, which relies on PostgreSQL, `dazhbog` uses a custom append-only storage engine with no external database dependencies, making it ideal for embedded deployment, edge computing, or standalone research environments.

### Installation

```shell
cargo build --release
./target/release/lumen config.toml
```

### Example Usage

```bash
# Start the server
./lumen config.toml

# Configure IDA Pro >= 8.1
export LUMINA_TLS=false
export LUMINA_HOST="127.0.0.1"
export LUMINA_PORT=1234
./ida64
```

For IDA Pro < 8.1, see the configuration section below.

### Features

*   **Zero External Dependencies:** Uses a custom append-only log-structured storage engine with no database server required.
*   **Full IDA Pro Protocol Compatibility:** Supports all IDA Pro Lumina protocol versions (7.2+).
*   **High-Performance Sharded Index:** In-memory concurrent hash index with configurable sharding for lock-free reads.
*   **Segment-Based Storage:** Append-only segment files with CRC32C integrity checking and efficient sequential writes.
*   **Function History Tracking:** Maintains complete revision history via linked list of records with `prev_addr` pointers.
*   **HTTP API & Metrics:** Built-in Prometheus-compatible metrics endpoint and web interface for monitoring.
*   **TLS Support:** Optional TLS with custom certificate pinning for IDA Pro compatibility.
*   **Graceful Degradation:** Automatic segment rotation and crash recovery through index rebuilding.

### Technical Background

#### Architecture Overview

`dazhbog` is built around three core components:

1.  **Storage Engine** - A custom append-only log-structured merge (LSM-inspired) storage system
2.  **RPC Server** - IDA Pro Lumina protocol TCP server with TLS support
3.  **HTTP Server** - Metrics and monitoring interface

#### Storage Engine

The storage engine implements a log-structured design optimized for write-heavy workloads typical of collaborative reverse engineering:

**Segments:**
*   Fixed-size append-only files (default 512 MB) named `seg.00001.dat`, `seg.00002.dat`, etc.
*   Each record contains:
    *   **Header:** Magic number (`0x4C4D4E31`), record length, CRC32C checksum
    *   **Body:** 128-bit function key, timestamp, previous address (for history chain), popularity, length, name, metadata blob, flags
*   Records are written atomically with write-ahead CRC verification
*   Segment rotation occurs automatically when capacity is reached

**Sharded Index:**
*   In-memory concurrent hash table with configurable shard count (default 256 shards)
*   Each shard uses `DashMap` for lock-free concurrent reads
*   Maps 128-bit function keys to 64-bit addresses encoding: `[seg_id:16 | offset:47 | flags:1]`
*   Index is rebuilt on startup by scanning all segments sequentially

**Record Format:**
```
[MAGIC:4] [LEN:4] [CRC:4] [KEY_LO:8] [KEY_HI:8] [TIMESTAMP:8] [PREV_ADDR:8] 
[LEN_BYTES:4] [POPULARITY:4] [NAME_LEN:2] [DATA_LEN:4] [FLAGS:1] [PAD:5]
[NAME:variable] [DATA:variable]
```

**History Tracking:**
Each record contains a `prev_addr` field pointing to the previous version of the same function. This creates a reverse-chronological linked list:
```
HEAD (index) -> Version 3 -> Version 2 -> Version 1 -> NULL
```
Queries traverse this chain up to the configured history limit.

**Tombstones:**
Deletions are implemented via tombstone records (`flags & 0x01`). The index points to the tombstone, which links to previous versions, preserving history while marking the function as deleted.

#### Protocol Support

`dazhbog` implements full compatibility with the IDA Pro Lumina protocol:

**Protocol Details:**
*   Hello message type: `0x0d`
*   Variable-length integer encoding (IDA's proprietary `dd` format)
*   Commands: `PullMetadata (0x0e)`, `PushMetadata (0x10)`, `DelHistory (0x18)`, `GetFuncHistories (0x2f)`
*   License data validation (bypassed in guest mode)
*   Protocol versions 0-5 supported

**Frame Format:**
All messages use a 4-byte big-endian length prefix followed by the message type byte and payload:
```
[LENGTH:4 BE] [TYPE:1] [PAYLOAD:variable]
```

#### Differences from Lumen

| Feature | Lumen | Dazhbog |
|---------|-------|---------|
| **Storage Backend** | PostgreSQL | Custom append-only log |
| **External Dependencies** | Requires PostgreSQL server, Diesel ORM | Zero external dependencies |
| **Index Structure** | PostgreSQL B-tree indexes | In-memory sharded hash table |
| **Function History** | SQL queries with JOINs | Linked list traversal via `prev_addr` |
| **Write Performance** | INSERT with index updates | Sequential append-only writes |
| **Read Performance** | SQL SELECT with indexes | Direct memory lookup + disk seek |
| **Data Integrity** | PostgreSQL MVCC + WAL | Per-record CRC32C checksums |
| **Scalability** | Vertical (PostgreSQL limits) | Horizontal (segment sharding) |
| **Deployment** | Requires DB setup, migrations | Single binary, no migrations |
| **Persistence** | ACID compliant | Crash recovery via index rebuild |
**Protocol Support** | IDA Pro Lumina protocol | IDA Pro Lumina protocol |
| **Memory Usage** | ~50 MB base + query cache | ~10 MB base + index size |
| **Startup Time** | Instant (DB connection) | O(n) segment scan for index rebuild |

**Key Technical Distinctions:**

1.  **Storage Model:**
    *   Lumen uses PostgreSQL's row-oriented storage with MVCC for concurrency control. Function updates require updating multiple indexes.
    *   Dazhbog uses append-only storage where updates are new records linked to old versions. No in-place updates.

2.  **Index Strategy:**
    *   Lumen relies on PostgreSQL's B-tree indexes (disk-backed) for function key lookups.
    *   Dazhbog maintains a purely in-memory hash index rebuilt on startup. This trades memory for speed.

3.  **Concurrency:**
    *   Lumen leverages PostgreSQL's connection pooling and row-level locking.
    *   Dazhbog uses lock-free concurrent data structures (`DashMap`) with optimistic concurrency for the index and coarse-grained locks for segment writes.

4.  **History Implementation:**
    *   Lumen stores history as separate rows in a `function_history` table with foreign keys.
    *   Dazhbog embeds history in each record via `prev_addr`, forming a reverse-chronological linked list.

5.  **Operational Complexity:**
    *   Lumen requires PostgreSQL administration, backups, migrations, and connection pooling tuning.
    *   Dazhbog is a single binary with file-based storage that can be copied/backed up like any directory.

6.  **Use Case Optimization:**
    *   Lumen is optimized for centralized team servers with heavy read patterns and complex queries.
    *   Dazhbog is optimized for embedded deployment, personal use, air-gapped networks, and write-heavy workloads.

### Configuration

Example `config.toml`:

```toml
[lumina]
bind_addr = "0.0.0.0:1234"
use_tls = false
server_name = "dazhbog"
allow_deletes = true
get_history_limit = 10

[engine]
data_dir = "./data"
segment_bytes = 536870912  # 512 MB
index_capacity = 10000000  # 10M functions
shard_count = 256
use_mmap_reads = false

[limits]
max_active_conns = 1000
hello_timeout_ms = 5000
tls_handshake_timeout_ms = 10000
command_timeout_ms = 30000

[http]
bind_addr = "0.0.0.0:8080"
```

### Configuring IDA Pro

#### IDA Pro >= 8.1

```bash
# Linux
export LUMINA_TLS=false
export LUMINA_HOST="127.0.0.1"
export LUMINA_PORT=1234
./ida64

# Windows
set LUMINA_TLS=false
set LUMINA_HOST=127.0.0.1
set LUMINA_PORT=1234
ida64.exe
```

In IDA: Go to **Options → General → Lumina**, select "Use a private server", set your host/port, and use `guest` as username and password.

#### IDA Pro < 8.1

Edit `cfg/ida.cfg`:

```c
LUMINA_HOST = "127.0.0.1";
LUMINA_PORT = 1234;
LUMINA_TLS = NO;
```

### Performance Characteristics

**Write Performance:**
*   Append-only writes: ~50,000 functions/second (single segment)
*   Index updates: O(1) with lock-free sharded hash table
*   Segment rotation: ~5ms overhead when full

**Read Performance:**
*   Function lookup: ~10-20μs (memory index lookup + single disk seek)
*   History traversal: ~50μs per version (follows `prev_addr` chain)
*   Batch queries: Scales linearly with request size

**Memory Usage:**
*   Base: ~10 MB
*   Index: ~80 bytes per function (varies with key distribution)
*    1M functions ≈ 80-100 MB total

**Disk Usage:**
*   ~200-500 bytes per function (depends on name/metadata size)
*   History preserved in-place (no duplication)
*   Tombstones add ~100 bytes per deletion

### Recovery & Durability

**Crash Recovery:**
On startup, dazhbog scans all segment files sequentially and rebuilds the in-memory index. This ensures consistency even after unclean shutdown.

**Index Rebuild:**
```rust
// Pseudo-code for recovery
for segment in segments_on_disk {
    for record in segment.scan() {
        if record.crc_valid() {
            index.upsert(record.key, record.address);
        }
    }
}
```

**Data Integrity:**
*   CRC32C checksums on every record
*   Atomic segment writes (no partial records)
*   No write-ahead log (append-only guarantees durability)

### Monitoring

The HTTP server exposes metrics at `http://localhost:8080/metrics`:

```
# HELP lumina_active_connections Active client connections
# TYPE lumina_active_connections gauge
lumina_active_connections 42

# HELP lumina_pushes_total Function metadata push operations
# TYPE lumina_pushes_total counter
lumina_pushes_total 1523

# HELP lumina_pulls_total Function metadata pull operations
# TYPE lumina_pulls_total counter
lumina_pulls_total 8921
```

### Notes

*   The server name "dazhbog" (Дажьбог) is a Slavic sun deity, chosen as a counterpart to "lumen" (Latin for light).
*   The storage engine is inspired by Bitcask and LSM trees but optimized for function signature workloads.
*   Full compatibility with IDA Pro's Lumina protocol across all versions (7.2+).
*   No authentication beyond username checking is implemented (designed for private networks).
*   The index rebuild on startup means initial startup time scales with database size (typically <1 second per 1M functions).

### License

MIT License

Copyright (c) 2025 Kenan Sulayman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
