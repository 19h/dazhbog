use dazhbog::db::semantic::{
    character_distribution_score, choose_canonical_name, cross_field_consistency_score,
    is_rejected_function_name, normalize_origin_token, shape_metadata_for_request,
    synthesize_metadata, SynthesisInput,
};
use dazhbog::protocol::lumina::{pack_dd, parse_metadata, serialize_metadata_chunks, MdKey};

fn chunk(raw_key: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&pack_dd(raw_key));
    out.extend_from_slice(&pack_dd(data.len() as u32));
    out.extend_from_slice(data);
    out
}

#[test]
fn metadata_chunk_roundtrip_preserves_known_and_unknown_keys() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&chunk(MdKey::Fcmt.raw(), b"hello semantic world\0"));
    blob.extend_from_slice(&chunk(MdKey::Ops.raw(), b"eax ptr [rbp-10h]"));
    blob.extend_from_slice(&chunk(42, b"\x01\x02opaque\x00payload"));

    let parsed = parse_metadata(&blob);
    assert_eq!(parsed.raw_chunks.len(), 3);
    assert_eq!(parsed.fcmt.as_deref(), Some("hello semantic world"));
    assert!(parsed.ops.is_some());
    assert!(parsed.raw_chunks.iter().any(|chunk| chunk.raw_key == 42));

    let rebuilt = serialize_metadata_chunks(&parsed.raw_chunks);
    assert_eq!(rebuilt, blob);
}

#[test]
fn bundle_synthesis_combines_requested_type_and_comment_chunks() {
    let mut type_blob = Vec::new();
    type_blob.extend_from_slice(&chunk(MdKey::Type.raw(), &[1, b'i', b'n', b't', 0]));

    let mut comment_blob = Vec::new();
    comment_blob.extend_from_slice(&chunk(MdKey::Fcmt.raw(), b"network parser entrypoint\0"));

    let parsed_type = parse_metadata(&type_blob);
    let parsed_comment = parse_metadata(&comment_blob);

    let inputs = vec![
        SynthesisInput {
            score: 10.0,
            name: "sub_140001000",
            raw_data: &type_blob,
            metadata: &parsed_type,
        },
        SynthesisInput {
            score: 9.5,
            name: "parse_http_headers",
            raw_data: &comment_blob,
            metadata: &parsed_comment,
        },
    ];

    let merged = synthesize_metadata(&inputs, &[MdKey::Type.raw(), MdKey::Fcmt.raw()]);
    let reparsed = parse_metadata(&merged);

    assert!(reparsed.type_parts.is_some());
    assert_eq!(reparsed.fcmt.as_deref(), Some("network parser entrypoint"));
}

#[test]
fn canonical_name_selection_and_origin_normalization_are_semantic() {
    let type_blob = chunk(MdKey::Type.raw(), &[1, b'i', b'n', b't', 0]);
    let comment_blob = chunk(MdKey::Fcmt.raw(), b"semantic comment\0");
    let parsed_type = parse_metadata(&type_blob);
    let parsed_comment = parse_metadata(&comment_blob);
    let inputs = vec![
        SynthesisInput {
            score: 8.0,
            name: "sub_140001000",
            raw_data: &type_blob,
            metadata: &parsed_type,
        },
        SynthesisInput {
            score: 7.8,
            name: "TlsHandshakeState::Advance",
            raw_data: &comment_blob,
            metadata: &parsed_comment,
        },
    ];

    assert_eq!(choose_canonical_name(&inputs), "TlsHandshakeState::Advance");
    assert_eq!(
        normalize_origin_token(r"C:\Users\analyst\work\firmware\ProjectAlpha.idb"),
        "projectalpha"
    );
    assert_eq!(
        normalize_origin_token("/srv/builds/acme/router/http_parser.bin"),
        "http_parser"
    );
}

#[test]
fn strict_request_shaping_removes_unrequested_chunks() {
    let mut blob = Vec::new();
    blob.extend_from_slice(&chunk(MdKey::Type.raw(), &[1, b'i', b'n', b't', 0]));
    blob.extend_from_slice(&chunk(MdKey::Fcmt.raw(), b"semantic pull path\0"));
    blob.extend_from_slice(&chunk(MdKey::Ops.raw(), b"eax ptr [rbp-10h]"));

    let shaped = shape_metadata_for_request(&blob, &[MdKey::Type.raw(), MdKey::Fcmt.raw()]);
    let parsed = parse_metadata(&shaped);

    assert_eq!(parsed.raw_chunks.len(), 2);
    assert!(parsed.type_parts.is_some());
    assert_eq!(parsed.fcmt.as_deref(), Some("semantic pull path"));
    assert!(parsed.ops.is_none());
}

#[test]
fn bundle_synthesis_falls_back_on_incompatible_structural_mix() {
    let type_blob = chunk(MdKey::Type.raw(), &[1, b'i', b'n', b't', 0]);
    let ops_blob = chunk(MdKey::Ops.raw(), b"goroutine scheduler channel park");
    let parsed_type = parse_metadata(&type_blob);
    let parsed_ops = parse_metadata(&ops_blob);
    let inputs = vec![
        SynthesisInput {
            score: 10.0,
            name: "_ZN3foo3barEv",
            raw_data: &type_blob,
            metadata: &parsed_type,
        },
        SynthesisInput {
            score: 9.8,
            name: "main\u{b7}init",
            raw_data: &ops_blob,
            metadata: &parsed_ops,
        },
    ];

    let merged = synthesize_metadata(&inputs, &[MdKey::Type.raw(), MdKey::Ops.raw()]);
    let reparsed = parse_metadata(&merged);

    assert!(reparsed.type_parts.is_some());
    assert!(reparsed.ops.is_none());
    assert_eq!(
        reparsed.requested_coverage(&[MdKey::Type.raw(), MdKey::Ops.raw()]),
        1
    );
}

#[test]
fn cross_field_consistency_rewards_coherent_tokens() {
    let coherent = chunk(MdKey::Fcmt.raw(), b"http_headers request parser\0");
    let incoherent = chunk(MdKey::Fcmt.raw(), b"objc selector queue kalloc\0");

    let coherent_score = cross_field_consistency_score("http_headers", &parse_metadata(&coherent));
    let incoherent_score =
        cross_field_consistency_score("http_headers", &parse_metadata(&incoherent));

    assert!(coherent_score > incoherent_score);
}

#[test]
fn rejected_function_name_policy_catches_generated_names() {
    assert!(is_rejected_function_name("sub_140001000"));
    assert!(is_rejected_function_name("FUN_140001000"));
    assert!(is_rejected_function_name("vftable_140001000"));
    assert!(is_rejected_function_name("unknown_140001000"));
    assert!(is_rejected_function_name(
        "CEntityComponentCargoInterface::SLoadingCargoRevokedWarningActive_Helper_1413E7BC0_Wrapper_14145B750"
    ));
    assert!(is_rejected_function_name("NetworkParser_1413E7BC0"));
    assert!(is_rejected_function_name("NetworkParser_12345"));
    assert!(is_rejected_function_name(
        "xxxJxOxHxNxxxWxIxCxKxxx7905747460165283064"
    ));
    assert!(is_rejected_function_name("x".repeat(6000).as_str()));

    assert!(!is_rejected_function_name("NetworkParser::parse_headers"));
    assert!(!is_rejected_function_name("x"));
}

#[test]
fn character_distribution_score_is_length_scaled() {
    let short = character_distribution_score("x");
    let long = character_distribution_score("x".repeat(6000).as_str());

    assert!(short.match_score < 0.1);
    assert!(short.evidence_bits < 3123.085);
    assert!(long.match_score < 0.1);
    assert!(long.evidence_bits >= 3123.085);
}

#[test]
fn synthesis_fallback_preserves_the_complete_donor() {
    use dazhbog::db::semantic::synthesize_selection;
    let malformed = b"\xff";
    let comment = chunk(MdKey::Fcmt.raw(), b"headers parser\0");
    let parsed_bad = parse_metadata(malformed);
    let parsed_comment = parse_metadata(&comment);
    let inputs = [
        SynthesisInput {
            score: 10.0,
            name: "sub_140001000",
            raw_data: malformed,
            metadata: &parsed_bad,
        },
        SynthesisInput {
            score: 9.5,
            name: "parse_http_headers",
            raw_data: &comment,
            metadata: &parsed_comment,
        },
    ];
    assert_eq!(choose_canonical_name(&inputs), "parse_http_headers");
    let result = synthesize_selection(&inputs, &[]);
    assert!(!result.used_synthesis);
    assert_eq!(result.name, inputs[0].name);
    assert_eq!(result.data, malformed);
    assert_eq!(result.donor_indices, vec![0]);
}

#[test]
fn truncated_chunk_headers_are_reported_without_losing_valid_prefix() {
    let prefix = chunk(MdKey::Fcmt.raw(), b"valid comment\0");
    for suffix in [&[255][..], &[42][..], &[42, 255][..]] {
        let mut data = prefix.clone();
        data.extend(suffix);
        let parsed = parse_metadata(&data);
        assert_eq!(parsed.fcmt.as_deref(), Some("valid comment"));
        assert_eq!(parsed.raw_chunks.len(), 1);
        assert!(!parsed.errors.is_empty());
    }
}
