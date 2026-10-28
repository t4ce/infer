/// Returns whether a buffer is MIDI data.
#[must_use]
pub fn is_midi(buf: &[u8]) -> bool {
    buf.len() > 3 && buf[0] == 0x4D && buf[1] == 0x54 && buf[2] == 0x68 && buf[3] == 0x64
}

/// Returns whether a buffer is MP3 data.
#[must_use]
pub fn is_mp3(buf: &[u8]) -> bool {
    buf.len() > 2
        && ((buf[0] == 0x49 && buf[1] == 0x44 && buf[2] == 0x33) // ID3v2
			// Final bit (has crc32) may be or may not be set.
	    		// ID3V1 Support
			|| (buf[0] == 0xFF && buf[1] == 0xFB)
	   		|| (buf[0] == 0xFF && buf[1] == 0xF3)
	   		|| (buf[0] == 0xFF && buf[1] == 0xF2))
}

/// Returns whether a buffer is M4A data.
#[must_use]
pub fn is_m4a(buf: &[u8]) -> bool {
    let branded = buf.len() > 11
        && ((&buf[4..8] == b"ftyp" && &buf[8..12] == b"M4A ") || &buf[..4] == b"M4A ");
    if branded {
        return true;
    }
    // Generic ISO BMFF brands (e.g. ffmpeg's `isom`) do not distinguish
    // audio from video. Inspect bounded box payloads, never magic strings
    // inside compressed media data. No allocation or recursive descent.
    if !super::video::is_mp4(buf) {
        return false;
    }
    let mut audio = false;
    let mut top = buf;
    while !top.is_empty() {
        let Some((kind, payload, rest)) = bmff_box(top) else {
            return false;
        };
        top = rest;
        if kind != b"moov" {
            continue;
        }
        let mut movie = payload;
        while !movie.is_empty() {
            let Some((kind, payload, rest)) = bmff_box(movie) else {
                return false;
            };
            movie = rest;
            if kind != b"trak" {
                continue;
            }
            let mut track = payload;
            let mut handler = None;
            while !track.is_empty() {
                let Some((kind, payload, rest)) = bmff_box(track) else {
                    return false;
                };
                track = rest;
                if kind != b"mdia" {
                    continue;
                }
                let mut media = payload;
                while !media.is_empty() {
                    let Some((kind, payload, rest)) = bmff_box(media) else {
                        return false;
                    };
                    media = rest;
                    if kind == b"hdlr" {
                        let Some(value) = payload.get(8..12) else {
                            return false;
                        };
                        if handler.replace(value).is_some() {
                            return false;
                        }
                    }
                }
            }
            match handler {
                Some(b"soun") => audio = true,
                // Permit metadata/text tracks, but never admit a video track.
                Some(b"meta" | b"text" | b"sbtl" | b"subt") => {}
                _ => return false,
            }
        }
    }
    audio
}

/// Read one ISO BMFF box, including extended sizes and boxes to EOF.
fn bmff_box(buf: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let size = u32::from_be_bytes(buf.get(..4)?.try_into().ok()?);
    let kind = buf.get(4..8)?;
    let (size, header) = match size {
        0 => (buf.len(), 8),
        1 => (
            usize::try_from(u64::from_be_bytes(buf.get(8..16)?.try_into().ok()?)).ok()?,
            16,
        ),
        size => (usize::try_from(size).ok()?, 8),
    };
    if size < header {
        return None;
    }
    Some((kind, buf.get(header..size)?, buf.get(size..)?))
}

/// Returns whether a buffer is OGG data.
#[must_use]
pub fn is_ogg(buf: &[u8]) -> bool {
    buf.len() > 3 && buf[0] == 0x4F && buf[1] == 0x67 && buf[2] == 0x67 && buf[3] == 0x53
}

/// Returns whether a buffer is OGG Opus data.
#[must_use]
pub fn is_ogg_opus(buf: &[u8]) -> bool {
    if !is_ogg(buf) {
        return false;
    }

    buf.len() > 35
        && buf[28] == 0x4F
        && buf[29] == 0x70
        && buf[30] == 0x75
        && buf[31] == 0x73
        && buf[32] == 0x48
        && buf[33] == 0x65
        && buf[34] == 0x61
        && buf[35] == 0x64
}

/// Returns whether a buffer is FLAC data.
#[must_use]
pub fn is_flac(buf: &[u8]) -> bool {
    buf.len() > 3 && buf[0] == 0x66 && buf[1] == 0x4C && buf[2] == 0x61 && buf[3] == 0x43
}

/// Returns whether a buffer is WAV data.
#[must_use]
pub fn is_wav(buf: &[u8]) -> bool {
    buf.len() > 11
        && buf[0] == 0x52
        && buf[1] == 0x49
        && buf[2] == 0x46
        && buf[3] == 0x46
        && buf[8] == 0x57
        && buf[9] == 0x41
        && buf[10] == 0x56
        && buf[11] == 0x45
}

/// Returns whether a buffer is AMR data.
#[must_use]
pub fn is_amr(buf: &[u8]) -> bool {
    buf.len() > 11
        && buf[0] == 0x23
        && buf[1] == 0x21
        && buf[2] == 0x41
        && buf[3] == 0x4D
        && buf[4] == 0x52
        && buf[5] == 0x0A
}

/// Returns whether a buffer is AAC data.
#[must_use]
pub fn is_aac(buf: &[u8]) -> bool {
    buf.len() > 1 && buf[0] == 0xFF && (buf[1] == 0xF1 || buf[1] == 0xF9)
}

/// Returns whether a buffer is AIFF data.
#[must_use]
pub fn is_aiff(buf: &[u8]) -> bool {
    buf.len() > 11
        && buf[0] == 0x46
        && buf[1] == 0x4F
        && buf[2] == 0x52
        && buf[3] == 0x4D
        && buf[8] == 0x41
        && buf[9] == 0x49
        && buf[10] == 0x46
        && buf[11] == 0x46
}

/// Returns whether a buffer is DSF data.
#[must_use]
pub fn is_dsf(buf: &[u8]) -> bool {
    // ref: https://dsd-guide.com/sites/default/files/white-papers/DSFFileFormatSpec_E.pdf
    buf.len() > 4 && buf[0] == b'D' && buf[1] == b'S' && buf[2] == b'D' && buf[3] == b' '
}

/// Returns whether a buffer is APE (Monkey's Audio) data.
#[must_use]
pub fn is_ape(buf: &[u8]) -> bool {
    // ref: https://github.com/fernandotcl/monkeys-audio/blob/master/src/MACLib/APEHeader.h
    buf.len() > 4 && buf[0] == b'M' && buf[1] == b'A' && buf[2] == b'C' && buf[3] == b' '
}
