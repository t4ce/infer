mod common;

test_format!(Audio, "audio/mpeg", "mp3", mp3, "sample.mp3");
test_format!(Audio, "audio/x-dsf", "dsf", dsf, "sample.dsf");
test_format!(Audio, "audio/x-ape", "ape", ape, "sample.ape");
test_format!(Audio, "audio/opus", "opus", opus, "sample_48kbps.opus");

// Generic MP4 brands are common in M4A files produced by ffmpeg. Only
// audio-only track evidence may override the generic MP4 identity.
#[test]
fn generic_bmff_audio_identity() {
    fn atom(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut out = ((payload.len() + 8) as u32).to_be_bytes().to_vec();
        out.extend_from_slice(kind);
        out.extend_from_slice(payload);
        out
    }
    fn track(handler: &[u8; 4]) -> Vec<u8> {
        let mut payload = vec![0; 8];
        payload.extend_from_slice(handler);
        atom(b"trak", &atom(b"mdia", &atom(b"hdlr", &payload)))
    }
    let header = atom(b"ftyp", b"isom\0\0\0\0isomiso2mp41");
    let mut audio = header.clone();
    // Handler-looking bytes in media data must be ignored.
    audio.extend(atom(b"mdat", b"vide"));
    audio.extend(atom(b"moov", &track(b"soun")));
    assert_eq!(
        infer::detect_content_type(&audio),
        Some(infer::ContentTypeId::M4A)
    );

    let mut tracks = track(b"soun");
    tracks.extend(track(b"vide"));
    let mut video = header.clone();
    video.extend(atom(b"moov", &tracks));
    assert_eq!(
        infer::detect_content_type(&video),
        Some(infer::ContentTypeId::MP4)
    );
    assert_eq!(
        infer::detect_content_type(&header),
        Some(infer::ContentTypeId::MP4)
    );
    for end in header.len()..audio.len() {
        assert_ne!(
            infer::detect_content_type(&audio[..end]),
            Some(infer::ContentTypeId::M4A)
        );
    }
    let mut invalid = audio.clone();
    invalid.extend_from_slice(b"\0\0\0\x04free");
    assert_ne!(
        infer::detect_content_type(&invalid),
        Some(infer::ContentTypeId::M4A)
    );
}
