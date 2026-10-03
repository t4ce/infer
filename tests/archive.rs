mod common;

test_format!(Archive, "application/vnd.bzip3", "bz3", bz3, "sample.tar.bz3");
test_format!(Archive, "application/vnd.sqlite3", "sqlite", sqlite, "sample.db");

test_format!(Archive, "application/zstd", "zst", zst, "sample.tar.zst");
test_format!(Archive, "application/x-lz4", "lz4", lz4, "sample.tar.lz4");
test_format!(Archive, "application/x-cpio", "cpio", cpio, "sample.cpio");
test_format!(Archive, "application/zstd", "zst", zst_skip, "sample.skippable.zst");
test_format!(Archive, "application/x-par2", "par2", par2, "sample.par2");

#[test]
fn zstd_many_empty_skippable_frames_do_not_recurse() {
    let mut input = Vec::new();
    for _ in 0..50_000 {
        input.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    }

    assert!(!infer::archive::is_zst(&input));
}

#[test]
fn zstd_skippable_frames_before_real_frame_match() {
    let mut input = Vec::from([0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    input.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);

    assert!(infer::archive::is_zst(&input));
}

#[test]
fn lz4_many_empty_skippable_frames_do_not_recurse() {
    let mut input = Vec::new();
    for _ in 0..50_000 {
        input.extend_from_slice(&[0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    }

    assert!(!infer::archive::is_lz4(&input));
}

#[test]
fn lz4_skippable_frames_before_real_frame_match() {
    let mut input = Vec::from([0x50, 0x2A, 0x4D, 0x18, 0, 0, 0, 0]);
    input.extend_from_slice(&[0x04, 0x22, 0x4D, 0x18]);

    assert!(infer::archive::is_lz4(&input));
}

#[test]
fn warcraft_map_identity_requires_both_container_signatures() {
    let mut bytes = [0u8; 516];
    bytes[..4].copy_from_slice(b"HM3W");
    assert_ne!(infer::detect_content_type(&bytes), Some(infer::ContentTypeId::WARCRAFT3_MAP));
    bytes[512..].copy_from_slice(b"MPQ\x1a");
    assert_eq!(infer::detect_content_type(&bytes), Some(infer::ContentTypeId::WARCRAFT3_MAP));
    assert_eq!(infer::get(&bytes).unwrap().extension(), "w3m");
    assert_eq!(
        infer::content_type_from_extension(".W3M"),
        Some(infer::ContentTypeId::WARCRAFT3_MAP)
    );
    assert_eq!(
        infer::content_type_from_extension("w3x"),
        Some(infer::ContentTypeId::WARCRAFT3_MAP)
    );
    assert!(!infer::archive::is_warcraft3_map(&bytes[..515]));
    bytes[0] = 0;
    assert!(!infer::archive::is_warcraft3_map(&bytes));
}
