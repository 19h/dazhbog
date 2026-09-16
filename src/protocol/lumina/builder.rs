//! Lumina protocol response builders.

use bytes::BytesMut;
use log::*;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::wire::*;

/// Write a packet in Lumina format with chunking for large payloads.
pub async fn write_lumina_packet<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> io::Result<()> {
    let len = payload.len() as u32;
    let len_bytes = len.to_be_bytes();
    debug!(
        "write_lumina_packet: type=0x{:02x}, payload_len={}",
        msg_type, len
    );
    w.write_all(&len_bytes).await?;
    w.write_u8(msg_type).await?;

    // Write payload in chunks with yield points for large responses
    write_all_chunked(w, payload).await?;

    w.flush().await?;
    Ok(())
}

/// Write bytes in chunks with yield points to prevent worker thread starvation.
async fn write_all_chunked<W: AsyncWriteExt + Unpin>(w: &mut W, buf: &[u8]) -> io::Result<()> {
    const CHUNK_SIZE: usize = 64 * 1024; // 64KB chunks

    if buf.len() <= CHUNK_SIZE {
        // Small write, no need to chunk
        return w.write_all(buf).await;
    }

    // Large write - chunk it and yield between chunks
    let mut offset = 0;
    while offset < buf.len() {
        let end = (offset + CHUNK_SIZE).min(buf.len());
        w.write_all(&buf[offset..end]).await?;
        offset = end;

        // Yield to the runtime to allow other tasks to run
        if offset < buf.len() {
            tokio::task::yield_now().await;
        }
    }

    Ok(())
}

/// Read a Lumina packet (client-side).
pub async fn read_lumina_packet<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max_len: usize,
) -> io::Result<(u8, Vec<u8>)> {
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb).await?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "remote frame too large",
        ));
    }
    let mut typb = [0u8; 1];
    r.read_exact(&mut typb).await?;
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok((typb[0], payload))
}

/// Send a Lumina OK response (0x0a).
pub async fn send_lumina_ok<W: AsyncWriteExt + Unpin>(w: &mut W) -> io::Result<()> {
    write_lumina_packet(w, 0x0a, &[]).await
}

/// Send a Lumina Hello result (0x31).
pub async fn send_lumina_hello_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    features: u32,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(&[0x00]);
    payload.extend_from_slice(&[0x00, 0x00]);
    payload.extend_from_slice(&pack_dd(features));
    write_lumina_packet(w, 0x31, &payload).await
}

/// Send a Lumina Notify response (0x0c).
pub async fn send_lumina_notify<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    notify_type: u32,
    message: &str,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(notify_type));
    payload.extend_from_slice(message.as_bytes());
    payload.extend_from_slice(b"\0");
    write_lumina_packet(w, 0x0c, &payload).await
}

/// Send a Lumina Info Result response (0x2c).
pub async fn send_lumina_info_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    server_mac: &str,
    server_version: &str,
    start_time: u64,
    current_time: u64,
) -> io::Result<()> {
    let mut payload = BytesMut::new();

    // peer_conn_t client
    payload.extend_from_slice(&pack_dd(1)); // session_id
    payload.extend_from_slice(b"dazhbog-client\0"); // peer_name
                                                    // lumina_user_t
    payload.extend_from_slice(b"\0\0\0"); // license_info: id, name, email
    payload.extend_from_slice(b"\0"); // name
    payload.extend_from_slice(&pack_dd(0)); // karma
    payload.extend_from_slice(&pack_dq(current_time)); // last_active
    payload.extend_from_slice(&pack_dd(0)); // features
    payload.extend_from_slice(&pack_dq(current_time)); // established

    // lumina_server_info_t server
    payload.extend_from_slice(server_mac.as_bytes());
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(server_version.as_bytes());
    payload.extend_from_slice(b"\0");
    payload.extend_from_slice(&pack_dq(start_time));
    payload.extend_from_slice(&pack_dq(current_time));

    write_lumina_packet(w, 0x2c, &payload).await
}

/// Send a Lumina Stats Result response (0x2e).
pub async fn send_lumina_stats_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    stats: &[super::LuminaStats],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(stats.len() as u32));

    for stat in stats {
        // lumina_user_t
        payload.extend_from_slice(stat.user.license_info.id.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(stat.user.license_info.name.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(stat.user.license_info.email.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(stat.user.name.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(&pack_dd(stat.user.karma as u32));
        payload.extend_from_slice(&pack_dq(stat.user.last_active));
        payload.extend_from_slice(&pack_dd(stat.user.features));

        // stats
        payload.extend_from_slice(&pack_dq(stat.nfuncs));
        payload.extend_from_slice(&pack_dq(stat.npushes));
        payload.extend_from_slice(&pack_dq(stat.nhist_recs));
        payload.extend_from_slice(&pack_dq(stat.nidbs));
        payload.extend_from_slice(&pack_dq(stat.ninput_files));
    }

    write_lumina_packet(w, 0x2e, &payload).await
}

/// Send a Lumina Fail response (0x0b).
pub async fn send_lumina_fail<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    code: u32,
    message: &str,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(code));
    payload.extend_from_slice(message.as_bytes());
    payload.extend_from_slice(b"\0");
    write_lumina_packet(w, 0x0b, &payload).await
}

/// Send a Lumina Pop Result response (0x13).
pub async fn send_lumina_pop_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    results: &[super::types::PopResult],
) -> io::Result<()> {
    // (name, size, metadata, pattern_type, pattern_data, freq, hostname, file_path, md5, ea64)
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(results.len() as u32));
    for (name, size, metadata, pat_type, pat_data, freq, host, path, md5, ea) in results {
        // func_info_t
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(&pack_dd(*size));
        payload.extend_from_slice(&pack_dd(metadata.len() as u32));
        payload.extend_from_slice(metadata);

        // pattern_id_t
        payload.extend_from_slice(&pack_dd(*pat_type));
        payload.extend_from_slice(&pack_dd(pat_data.len() as u32));
        payload.extend_from_slice(pat_data);

        // frequency
        payload.extend_from_slice(&pack_dd(*freq));

        // pop_fun_t specific
        payload.extend_from_slice(host.as_bytes());
        payload.extend_from_slice(b"\0");

        // input_file_t
        payload.extend_from_slice(path.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(md5);

        // ea64
        payload.extend_from_slice(&pack_ea64(*ea));
    }

    write_lumina_packet(w, 0x13, &payload).await
}

/// Send a Lumina PullResult response (0x0f).
pub async fn send_lumina_pull_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    statuses: &[u32],
    funcs: &[(u32, u32, String, Vec<u8>)],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(statuses.len() as u32));
    for &status in statuses {
        payload.extend_from_slice(&pack_dd(status));
    }
    payload.extend_from_slice(&pack_dd(funcs.len() as u32));
    for (pop, len, name, data) in funcs {
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(&pack_dd(*len));
        payload.extend_from_slice(&pack_dd(data.len() as u32));
        payload.extend_from_slice(data);
        payload.extend_from_slice(&pack_dd(*pop));
    }
    write_lumina_packet(w, 0x0f, &payload).await
}

/// Send a Lumina PushResult response (0x11).
pub async fn send_lumina_push_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    status: &[u32],
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(status.len() as u32));
    for &s in status {
        payload.extend_from_slice(&pack_dd(s));
    }
    write_lumina_packet(w, 0x11, &payload).await
}

/// Send a Lumina DelResult response (0x19).
pub async fn send_lumina_del_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    deleted_mds: u32,
) -> io::Result<()> {
    let payload = pack_dd(deleted_mds);
    write_lumina_packet(w, 0x19, &payload).await
}

/// Send a Lumina GetFuncHistories result (0x30).
///
/// `pattern_idx_to_entries_idx[i]` is the index into `histories` for request
/// pattern `i`, or `-1` when it has no history (`index_t`, packed as `dd(idx+1)`).
/// Each entry is a `func_history_entry_t`: `dq id`, `ea64 func_ea`, `cstr name`,
/// `bytevec metadata`, `dq ts`, `index author_idx`, `index idb_path_idx`.
/// Without `BOPF_DETAILS` the metadata is omitted (empty bytevec), as the
/// reference does. Authors and IDB paths are not disclosed (`-1`), matching
/// the lumina.hex-rays.com build.
pub async fn send_lumina_histories_result<W: AsyncWriteExt + Unpin>(
    w: &mut W,
    pattern_idx_to_entries_idx: &[i32],
    histories: &[Vec<(u64, String, Vec<u8>)>],
    details: bool,
) -> io::Result<()> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(pattern_idx_to_entries_idx.len() as u32));
    for &idx in pattern_idx_to_entries_idx {
        payload.extend_from_slice(&pack_index(idx));
    }
    payload.extend_from_slice(&pack_dd(histories.len() as u32));
    for history in histories {
        payload.extend_from_slice(&pack_dd(history.len() as u32));
        for (ts, name, metadata) in history {
            payload.extend_from_slice(&pack_dq(0)); // id (unknown)
            payload.extend_from_slice(&pack_ea64(u64::MAX)); // func_ea = BADADDR
            payload.extend_from_slice(name.as_bytes());
            payload.extend_from_slice(b"\0");
            if details {
                payload.extend_from_slice(&pack_dd(metadata.len() as u32));
                payload.extend_from_slice(metadata);
            } else {
                payload.extend_from_slice(&pack_dd(0));
            }
            payload.extend_from_slice(&pack_dq(*ts));
            payload.extend_from_slice(&pack_index(-1)); // author_idx
            payload.extend_from_slice(&pack_index(-1)); // idb_path_idx
        }
    }
    payload.extend_from_slice(&pack_dd(0)); // authors
    payload.extend_from_slice(&pack_dd(0)); // idb_paths
    write_lumina_packet(w, 0x30, &payload).await
}

/// Build a Lumina Hello payload (client-side).
pub fn build_lumina_hello_payload(
    protocol_version: u32,
    license_data: &[u8],
    lic_number: [u8; 6],
    username: &str,
    password: &str,
    unk2: u32,
) -> Vec<u8> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(protocol_version));
    payload.extend_from_slice(&pack_dd(license_data.len() as u32));
    payload.extend_from_slice(license_data);
    payload.extend_from_slice(&lic_number);
    payload.extend_from_slice(&pack_dd(unk2));
    if protocol_version > 2 {
        payload.extend_from_slice(username.as_bytes());
        payload.extend_from_slice(b"\0");
        payload.extend_from_slice(password.as_bytes());
        payload.extend_from_slice(b"\0");
    }
    payload.to_vec()
}

/// Build a PullMetadata payload for a set of 16-byte hashes (client-side).
pub fn build_pull_metadata_payload(hashes_be: &[[u8; 16]]) -> Vec<u8> {
    let mut payload = BytesMut::new();
    payload.extend_from_slice(&pack_dd(0));
    payload.extend_from_slice(&pack_dd(0));
    payload.extend_from_slice(&pack_dd(hashes_be.len() as u32));
    for h in hashes_be {
        payload.extend_from_slice(&pack_dd(0));
        payload.extend_from_slice(&pack_dd(16));
        payload.extend_from_slice(h);
    }
    payload.to_vec()
}
