use super::{matchers, Matcher, Type};

/// Stable, on-disk content identity.
///
/// Numeric values are part of the TRUEOS contract: they are never derived
/// from matcher order, never reused, and are safe to retain even when a newer
/// reader does not know their meaning.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ContentTypeId(u32);

impl ContentTypeId {
    /// No declared or recognised content identity.
    pub const NONE: Self = Self(0);
    /// Deliberately opaque bytes. This is a declaration, never an inference.
    pub const BLOB: Self = Self(1);
    /// Strict UTF-8 text when no more-specific text matcher applies.
    pub const UTF8_TEXT: Self = Self(2);

    /// Construct an identity read from durable storage.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the durable little-endian `u32` value.
    #[must_use]
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Whether this identity is currently registered by this fork.
    #[must_use]
    pub const fn is_registered(self) -> bool {
        content_type_info(self).is_some()
    }
}

/// Immutable registry metadata for a [`ContentTypeId`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContentTypeInfo {
    pub id: ContentTypeId,
    pub canonical_name: &'static str,
    pub mime_type: &'static str,
    pub preferred_extension: Option<&'static str>,
    pub aliases: &'static [&'static str],
    pub matcher_type: Option<MatcherType>,
}

impl ContentTypeInfo {
    const fn new(
        id: ContentTypeId,
        canonical_name: &'static str,
        mime_type: &'static str,
        preferred_extension: Option<&'static str>,
        aliases: &'static [&'static str],
        matcher_type: Option<MatcherType>,
    ) -> Self {
        Self {
            id,
            canonical_name,
            mime_type,
            preferred_extension,
            aliases,
            matcher_type,
        }
    }
}

macro_rules! content_registry {
    ($(($name:ident, $raw:expr, $kind:expr, $mime:literal, $extension:literal)),* $(,)?) => {
        impl ContentTypeId {
            $(pub const $name: Self = Self($raw);)*
        }

        /// Frozen registry. Append new entries; never renumber or reuse one.
        pub const CONTENT_TYPES: &[ContentTypeInfo] = &[
            ContentTypeInfo::new(ContentTypeId::BLOB, "BLOB", "application/octet-stream", Some("bin"), &[], None),
            ContentTypeInfo::new(ContentTypeId::UTF8_TEXT, "UTF8_TEXT", "text/plain", Some("txt"), UTF8_TEXT_ALIASES, Some(MatcherType::Text)),
            $(ContentTypeInfo::new(ContentTypeId::$name, stringify!($name), $mime, Some($extension), aliases_for(ContentTypeId::$name), Some($kind)),)*
        ];
    };
}

const UTF8_TEXT_ALIASES: &[&str] = &["text", "yml", "yaml", "json", "toml", "ini", "cfg", "log"];
const JPEG_ALIASES: &[&str] = &["jpeg", "jpe"];
const TIFF_ALIASES: &[&str] = &["tiff"];
const PE_ALIASES: &[&str] = &["dll"];
const WAV_ALIASES: &[&str] = &["wave"];
const HTML_ALIASES: &[&str] = &["htm", "xhtml"];
const OLE_ALIASES: &[&str] = &["doc", "xls", "ppt", "msi"];

const fn aliases_for(id: ContentTypeId) -> &'static [&'static str] {
    if id.raw() == ContentTypeId::JPEG.raw() {
        JPEG_ALIASES
    } else if id.raw() == ContentTypeId::TIFF.raw() {
        TIFF_ALIASES
    } else if id.raw() == ContentTypeId::PORTABLE_EXECUTABLE.raw() {
        PE_ALIASES
    } else if id.raw() == ContentTypeId::WAV.raw() {
        WAV_ALIASES
    } else if id.raw() == ContentTypeId::HTML.raw() {
        HTML_ALIASES
    } else if id.raw() == ContentTypeId::OLE_COMPOUND_FILE.raw() {
        OLE_ALIASES
    } else {
        &[]
    }
}

// Superseded pre-freeze draft kept out of the build solely to make the
// durable-ID renumbering reviewable. Do not re-enable it.
#[cfg(any())]
content_registry!(
    (WASM, 0x0001_0000, MatcherType::App, "application/wasm", "wasm"),
    (ELF, 0x0001_0001, MatcherType::App, "application/x-executable", "elf"),
    (
        PORTABLE_EXECUTABLE,
        0x0001_0002,
        MatcherType::App,
        "application/vnd.microsoft.portable-executable",
        "exe"
    ),
    (JAVA_CLASS, 0x0001_0003, MatcherType::App, "application/java", "class"),
    (LLVM_BITCODE, 0x0001_0004, MatcherType::App, "application/x-llvm", "bc"),
    (MACH_O, 0x0001_0005, MatcherType::App, "application/x-mach-binary", "mach"),
    (DEX, 0x0001_0006, MatcherType::App, "application/vnd.android.dex", "dex"),
    (ODEX, 0x0001_0007, MatcherType::App, "application/vnd.android.dey", "dey"),
    (DER_CERTIFICATE, 0x0001_0008, MatcherType::App, "application/x-x509-ca-cert", "der"),
    (COFF_OBJECT, 0x0001_0009, MatcherType::App, "application/x-executable", "obj"),
    (PEM_CERTIFICATE, 0x0001_000A, MatcherType::App, "application/x-x509-ca-cert", "pem"),
    (QCOW2, 0x0001_000B, MatcherType::App, "application/x-qemu-disk", "qcow2"),
    (OLE_COMPOUND_FILE, 0x0001_000C, MatcherType::Archive, "application/x-ole-storage", "ole"),
    (EPUB, 0x0001_000D, MatcherType::Book, "application/epub+zip", "epub"),
    (MOBI, 0x0001_000E, MatcherType::Book, "application/x-mobipocket-ebook", "mobi"),
    (JPEG, 0x0001_000F, MatcherType::Image, "image/jpeg", "jpg"),
    (JPEG_2000, 0x0001_0010, MatcherType::Image, "image/jp2", "jp2"),
    (PNG, 0x0001_0011, MatcherType::Image, "image/png", "png"),
    (GIF, 0x0001_0012, MatcherType::Image, "image/gif", "gif"),
    (WEBP, 0x0001_0013, MatcherType::Image, "image/webp", "webp"),
    (CANON_CR2, 0x0001_0014, MatcherType::Image, "image/x-canon-cr2", "cr2"),
    (TIFF, 0x0001_0015, MatcherType::Image, "image/tiff", "tif"),
    (BMP, 0x0001_0016, MatcherType::Image, "image/bmp", "bmp"),
    (JXR, 0x0001_0017, MatcherType::Image, "image/vnd.ms-photo", "jxr"),
    (PSD, 0x0001_0018, MatcherType::Image, "image/vnd.adobe.photoshop", "psd"),
    (ICO, 0x0001_0019, MatcherType::Image, "image/vnd.microsoft.icon", "ico"),
    (HEIF, 0x0001_001A, MatcherType::Image, "image/heif", "heif"),
    (AVIF, 0x0001_001B, MatcherType::Image, "image/avif", "avif"),
    (JPEG_XL, 0x0001_001C, MatcherType::Image, "image/jxl", "jxl"),
    (OPENRASTER, 0x0001_001D, MatcherType::Image, "image/openraster", "ora"),
    (DJVU, 0x0001_001E, MatcherType::Image, "image/vnd.djvu", "djvu"),
    (DWG, 0x0001_001F, MatcherType::Image, "image/vnd.dwg", "dwg"),
    (MP4, 0x0001_0020, MatcherType::Video, "video/mp4", "mp4"),
    (M4V, 0x0001_0021, MatcherType::Video, "video/x-m4v", "m4v"),
    (MATROSKA, 0x0001_0022, MatcherType::Video, "video/x-matroska", "mkv"),
    (WEBM, 0x0001_0023, MatcherType::Video, "video/webm", "webm"),
    (QUICKTIME, 0x0001_0024, MatcherType::Video, "video/quicktime", "mov"),
    (AVI, 0x0001_0025, MatcherType::Video, "video/x-msvideo", "avi"),
    (WMV, 0x0001_0026, MatcherType::Video, "video/x-ms-wmv", "wmv"),
    (MPEG_VIDEO, 0x0001_0027, MatcherType::Video, "video/mpeg", "mpg"),
    (FLV, 0x0001_0028, MatcherType::Video, "video/x-flv", "flv"),
    (MIDI, 0x0001_0029, MatcherType::Audio, "audio/midi", "midi"),
    (MP3, 0x0001_002A, MatcherType::Audio, "audio/mpeg", "mp3"),
    (M4A, 0x0001_002B, MatcherType::Audio, "audio/m4a", "m4a"),
    (OPUS, 0x0001_002C, MatcherType::Audio, "audio/opus", "opus"),
    (OGG, 0x0001_002D, MatcherType::Audio, "audio/ogg", "ogg"),
    (FLAC, 0x0001_002E, MatcherType::Audio, "audio/x-flac", "flac"),
    (WAV, 0x0001_002F, MatcherType::Audio, "audio/x-wav", "wav"),
    (AMR, 0x0001_0030, MatcherType::Audio, "audio/amr", "amr"),
    (AAC, 0x0001_0031, MatcherType::Audio, "audio/aac", "aac"),
    (AIFF, 0x0001_0032, MatcherType::Audio, "audio/x-aiff", "aiff"),
    (DSF, 0x0001_0033, MatcherType::Audio, "audio/x-dsf", "dsf"),
    (APE, 0x0001_0034, MatcherType::Audio, "audio/x-ape", "ape"),
    (WOFF, 0x0001_0035, MatcherType::Font, "application/font-woff", "woff"),
    (WOFF2, 0x0001_0036, MatcherType::Font, "application/font-woff", "woff2"),
    (TTF, 0x0001_0037, MatcherType::Font, "application/font-sfnt", "ttf"),
    (OTF, 0x0001_0038, MatcherType::Font, "application/font-sfnt", "otf"),
    (DOC, 0x0001_0039, MatcherType::Doc, "application/msword", "doc"),
    (
        DOCX,
        0x0001_003A,
        MatcherType::Doc,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "docx"
    ),
    (XLS, 0x0001_003B, MatcherType::Doc, "application/vnd.ms-excel", "xls"),
    (
        XLSX,
        0x0001_003C,
        MatcherType::Doc,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xlsx"
    ),
    (PPT, 0x0001_003D, MatcherType::Doc, "application/vnd.ms-powerpoint", "ppt"),
    (
        PPTX,
        0x0001_003E,
        MatcherType::Doc,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pptx"
    ),
    (ODT, 0x0001_003F, MatcherType::Doc, "application/vnd.oasis.opendocument.text", "odt"),
    (ODS, 0x0001_0040, MatcherType::Doc, "application/vnd.oasis.opendocument.spreadsheet", "ods"),
    (ODP, 0x0001_0041, MatcherType::Doc, "application/vnd.oasis.opendocument.presentation", "odp"),
    (ZIP, 0x0001_0042, MatcherType::Archive, "application/zip", "zip"),
    (TAR, 0x0001_0043, MatcherType::Archive, "application/x-tar", "tar"),
    (PAR2, 0x0001_0044, MatcherType::Archive, "application/x-par2", "par2"),
    (RAR, 0x0001_0045, MatcherType::Archive, "application/vnd.rar", "rar"),
    (GZIP, 0x0001_0046, MatcherType::Archive, "application/gzip", "gz"),
    (BZIP2, 0x0001_0047, MatcherType::Archive, "application/x-bzip2", "bz2"),
    (BZIP3, 0x0001_0048, MatcherType::Archive, "application/vnd.bzip3", "bz3"),
    (SEVEN_Z, 0x0001_0049, MatcherType::Archive, "application/x-7z-compressed", "7z"),
    (XZ, 0x0001_004A, MatcherType::Archive, "application/x-xz", "xz"),
    (PDF, 0x0001_004B, MatcherType::Archive, "application/pdf", "pdf"),
    (SWF, 0x0001_004C, MatcherType::Archive, "application/x-shockwave-flash", "swf"),
    (RTF, 0x0001_004D, MatcherType::Archive, "application/rtf", "rtf"),
    (EOT, 0x0001_004E, MatcherType::Archive, "application/octet-stream", "eot"),
    (POSTSCRIPT, 0x0001_004F, MatcherType::Archive, "application/postscript", "ps"),
    (SQLITE, 0x0001_0050, MatcherType::Archive, "application/vnd.sqlite3", "sqlite"),
    (NES_ROM, 0x0001_0051, MatcherType::Archive, "application/x-nintendo-nes-rom", "nes"),
    (CRX, 0x0001_0052, MatcherType::Archive, "application/x-google-chrome-extension", "crx"),
    (CAB, 0x0001_0053, MatcherType::Archive, "application/vnd.ms-cab-compressed", "cab"),
    (DEB, 0x0001_0054, MatcherType::Archive, "application/vnd.debian.binary-package", "deb"),
    (AR, 0x0001_0055, MatcherType::Archive, "application/x-unix-archive", "ar"),
    (COMPRESS_Z, 0x0001_0056, MatcherType::Archive, "application/x-compress", "Z"),
    (LZIP, 0x0001_0057, MatcherType::Archive, "application/x-lzip", "lz"),
    (RPM, 0x0001_0058, MatcherType::Archive, "application/x-rpm", "rpm"),
    (DICOM, 0x0001_0059, MatcherType::Archive, "application/dicom", "dcm"),
    (ZSTD, 0x0001_005A, MatcherType::Archive, "application/zstd", "zst"),
    (LZ4, 0x0001_005B, MatcherType::Archive, "application/x-lz4", "lz4"),
    (MSI, 0x0001_005C, MatcherType::Archive, "application/x-ole-storage", "msi"),
    (CPIO, 0x0001_005D, MatcherType::Archive, "application/x-cpio", "cpio"),
    (HTML, 0x0001_005E, MatcherType::Text, "text/html", "html"),
    (XML, 0x0001_005F, MatcherType::Text, "text/xml", "xml"),
    (SHELL_SCRIPT, 0x0001_0060, MatcherType::Text, "text/x-shellscript", "sh"),
);

// Frozen v1 durable registry, ordered alphabetically by canonical identity
// name. New identities append after this block; no existing value moves.
content_registry!(
    (AAC, 0x0001_0000, MatcherType::Audio, "audio/aac", "aac"),
    (AIFF, 0x0001_0001, MatcherType::Audio, "audio/x-aiff", "aiff"),
    (AMR, 0x0001_0002, MatcherType::Audio, "audio/amr", "amr"),
    (APE, 0x0001_0003, MatcherType::Audio, "audio/x-ape", "ape"),
    (AR, 0x0001_0004, MatcherType::Archive, "application/x-unix-archive", "ar"),
    (AVI, 0x0001_0005, MatcherType::Video, "video/x-msvideo", "avi"),
    (AVIF, 0x0001_0006, MatcherType::Image, "image/avif", "avif"),
    (BMP, 0x0001_0007, MatcherType::Image, "image/bmp", "bmp"),
    (BZIP2, 0x0001_0008, MatcherType::Archive, "application/x-bzip2", "bz2"),
    (BZIP3, 0x0001_0009, MatcherType::Archive, "application/vnd.bzip3", "bz3"),
    (CAB, 0x0001_000A, MatcherType::Archive, "application/vnd.ms-cab-compressed", "cab"),
    (CANON_CR2, 0x0001_000B, MatcherType::Image, "image/x-canon-cr2", "cr2"),
    (COFF_OBJECT, 0x0001_000C, MatcherType::App, "application/x-executable", "obj"),
    (COMPRESS_Z, 0x0001_000D, MatcherType::Archive, "application/x-compress", "Z"),
    (CPIO, 0x0001_000E, MatcherType::Archive, "application/x-cpio", "cpio"),
    (CRX, 0x0001_000F, MatcherType::Archive, "application/x-google-chrome-extension", "crx"),
    (DEB, 0x0001_0010, MatcherType::Archive, "application/vnd.debian.binary-package", "deb"),
    (DER_CERTIFICATE, 0x0001_0011, MatcherType::App, "application/x-x509-ca-cert", "der"),
    (DEX, 0x0001_0012, MatcherType::App, "application/vnd.android.dex", "dex"),
    (DICOM, 0x0001_0013, MatcherType::Archive, "application/dicom", "dcm"),
    (DJVU, 0x0001_0014, MatcherType::Image, "image/vnd.djvu", "djvu"),
    (DOCX, 0x0001_0015, MatcherType::Doc, "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx"),
    (DSF, 0x0001_0016, MatcherType::Audio, "audio/x-dsf", "dsf"),
    (DWG, 0x0001_0017, MatcherType::Image, "image/vnd.dwg", "dwg"),
    (ELF, 0x0001_0018, MatcherType::App, "application/x-executable", "elf"),
    (EOT, 0x0001_0019, MatcherType::Archive, "application/octet-stream", "eot"),
    (EPUB, 0x0001_001A, MatcherType::Book, "application/epub+zip", "epub"),
    (FLAC, 0x0001_001B, MatcherType::Audio, "audio/x-flac", "flac"),
    (FLV, 0x0001_001C, MatcherType::Video, "video/x-flv", "flv"),
    (GIF, 0x0001_001D, MatcherType::Image, "image/gif", "gif"),
    (GZIP, 0x0001_001E, MatcherType::Archive, "application/gzip", "gz"),
    (HEIF, 0x0001_001F, MatcherType::Image, "image/heif", "heif"),
    (HTML, 0x0001_0020, MatcherType::Text, "text/html", "html"),
    (ICO, 0x0001_0021, MatcherType::Image, "image/vnd.microsoft.icon", "ico"),
    (JAVA_CLASS, 0x0001_0022, MatcherType::App, "application/java", "class"),
    (JPEG, 0x0001_0023, MatcherType::Image, "image/jpeg", "jpg"),
    (JPEG_2000, 0x0001_0024, MatcherType::Image, "image/jp2", "jp2"),
    (JPEG_XL, 0x0001_0025, MatcherType::Image, "image/jxl", "jxl"),
    (JXR, 0x0001_0026, MatcherType::Image, "image/vnd.ms-photo", "jxr"),
    (LLVM_BITCODE, 0x0001_0027, MatcherType::App, "application/x-llvm", "bc"),
    (LZ4, 0x0001_0028, MatcherType::Archive, "application/x-lz4", "lz4"),
    (LZIP, 0x0001_0029, MatcherType::Archive, "application/x-lzip", "lz"),
    (M4A, 0x0001_002A, MatcherType::Audio, "audio/m4a", "m4a"),
    (M4V, 0x0001_002B, MatcherType::Video, "video/x-m4v", "m4v"),
    (MACH_O, 0x0001_002C, MatcherType::App, "application/x-mach-binary", "mach"),
    (MATROSKA, 0x0001_002D, MatcherType::Video, "video/x-matroska", "mkv"),
    (MIDI, 0x0001_002E, MatcherType::Audio, "audio/midi", "midi"),
    (MOBI, 0x0001_002F, MatcherType::Book, "application/x-mobipocket-ebook", "mobi"),
    (MP3, 0x0001_0030, MatcherType::Audio, "audio/mpeg", "mp3"),
    (MP4, 0x0001_0031, MatcherType::Video, "video/mp4", "mp4"),
    (MPEG_VIDEO, 0x0001_0032, MatcherType::Video, "video/mpeg", "mpg"),
    (NES_ROM, 0x0001_0033, MatcherType::Archive, "application/x-nintendo-nes-rom", "nes"),
    (ODEX, 0x0001_0034, MatcherType::App, "application/vnd.android.dey", "dey"),
    (ODP, 0x0001_0035, MatcherType::Doc, "application/vnd.oasis.opendocument.presentation", "odp"),
    (ODS, 0x0001_0036, MatcherType::Doc, "application/vnd.oasis.opendocument.spreadsheet", "ods"),
    (ODT, 0x0001_0037, MatcherType::Doc, "application/vnd.oasis.opendocument.text", "odt"),
    (OGG, 0x0001_0038, MatcherType::Audio, "audio/ogg", "ogg"),
    (OLE_COMPOUND_FILE, 0x0001_0039, MatcherType::Archive, "application/x-ole-storage", "ole"),
    (OPENRASTER, 0x0001_003A, MatcherType::Image, "image/openraster", "ora"),
    (OPUS, 0x0001_003B, MatcherType::Audio, "audio/opus", "opus"),
    (OTF, 0x0001_003C, MatcherType::Font, "application/font-sfnt", "otf"),
    (PAR2, 0x0001_003D, MatcherType::Archive, "application/x-par2", "par2"),
    (PDF, 0x0001_003E, MatcherType::Archive, "application/pdf", "pdf"),
    (PEM_CERTIFICATE, 0x0001_003F, MatcherType::App, "application/x-x509-ca-cert", "pem"),
    (PNG, 0x0001_0040, MatcherType::Image, "image/png", "png"),
    (PORTABLE_EXECUTABLE, 0x0001_0041, MatcherType::App, "application/vnd.microsoft.portable-executable", "exe"),
    (POSTSCRIPT, 0x0001_0042, MatcherType::Archive, "application/postscript", "ps"),
    (PPTX, 0x0001_0043, MatcherType::Doc, "application/vnd.openxmlformats-officedocument.presentationml.presentation", "pptx"),
    (PSD, 0x0001_0044, MatcherType::Image, "image/vnd.adobe.photoshop", "psd"),
    (QCOW2, 0x0001_0045, MatcherType::App, "application/x-qemu-disk", "qcow2"),
    (QUICKTIME, 0x0001_0046, MatcherType::Video, "video/quicktime", "mov"),
    (RAR, 0x0001_0047, MatcherType::Archive, "application/vnd.rar", "rar"),
    (RPM, 0x0001_0048, MatcherType::Archive, "application/x-rpm", "rpm"),
    (RTF, 0x0001_0049, MatcherType::Archive, "application/rtf", "rtf"),
    (SEVEN_Z, 0x0001_004A, MatcherType::Archive, "application/x-7z-compressed", "7z"),
    (SHELL_SCRIPT, 0x0001_004B, MatcherType::Text, "text/x-shellscript", "sh"),
    (SQLITE, 0x0001_004C, MatcherType::Archive, "application/vnd.sqlite3", "sqlite"),
    (SWF, 0x0001_004D, MatcherType::Archive, "application/x-shockwave-flash", "swf"),
    (TAR, 0x0001_004E, MatcherType::Archive, "application/x-tar", "tar"),
    (TIFF, 0x0001_004F, MatcherType::Image, "image/tiff", "tif"),
    (TRUEOS_BLUEPRINT, 0x0001_0050, MatcherType::App, "application/vnd.trueos.blueprint", "bp"),
    (TTF, 0x0001_0051, MatcherType::Font, "application/font-sfnt", "ttf"),
    (WASM, 0x0001_0052, MatcherType::App, "application/wasm", "wasm"),
    (WAV, 0x0001_0053, MatcherType::Audio, "audio/x-wav", "wav"),
    (WEBM, 0x0001_0054, MatcherType::Video, "video/webm", "webm"),
    (WEBP, 0x0001_0055, MatcherType::Image, "image/webp", "webp"),
    (WMV, 0x0001_0056, MatcherType::Video, "video/x-ms-wmv", "wmv"),
    (WOFF, 0x0001_0057, MatcherType::Font, "application/font-woff", "woff"),
    (WOFF2, 0x0001_0058, MatcherType::Font, "application/font-woff", "woff2"),
    (XLSX, 0x0001_0059, MatcherType::Doc, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"),
    (XML, 0x0001_005A, MatcherType::Text, "text/xml", "xml"),
    (XZ, 0x0001_005B, MatcherType::Archive, "application/x-xz", "xz"),
    (ZIP, 0x0001_005C, MatcherType::Archive, "application/zip", "zip"),
    (ZSTD, 0x0001_005D, MatcherType::Archive, "application/zstd", "zst"),
);

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum MatcherType {
    App,
    Archive,
    Audio,
    Book,
    Doc,
    Font,
    Image,
    Text,
    Video,
    Custom,
}

// This is needed until function pointers can be used in `const fn`.
// See trick and discussion at https://github.com/rust-lang/rust/issues/63997#issuecomment-616666309
#[repr(transparent)]
#[derive(Copy, Clone)]
pub struct WrapMatcher(pub Matcher);

macro_rules! matcher_map {
    ($(($mtype:expr, $mime_type:literal, $extension:literal, $matcher:expr)),*) => {
        pub const MATCHER_MAP: &[Type] = &[
            $(Type::new_static($mtype, $mime_type, $extension, WrapMatcher($matcher)),)*
        ];
    };
}

// Order: Application, Image, Video, Audio, Font, Document, Archive, Text.
// The above order should be preserved when adding new types since
// it may affect match result and/or performances.
matcher_map!(
    // Application
    (MatcherType::App, "application/wasm", "wasm", matchers::app::is_wasm),
    (MatcherType::App, "application/x-executable", "elf", matchers::app::is_elf),
    (
        MatcherType::App,
        "application/vnd.microsoft.portable-executable",
        "exe",
        matchers::app::is_exe
    ),
    (
        MatcherType::App,
        "application/vnd.microsoft.portable-executable",
        "dll",
        matchers::app::is_dll
    ),
    (MatcherType::App, "application/java", "class", matchers::app::is_java),
    (MatcherType::App, "application/x-llvm", "bc", matchers::app::is_llvm),
    (MatcherType::App, "application/x-mach-binary", "mach", matchers::app::is_mach),
    (MatcherType::App, "application/vnd.android.dex", "dex", matchers::app::is_dex),
    (MatcherType::App, "application/vnd.android.dey", "dey", matchers::app::is_dey),
    (MatcherType::App, "application/x-x509-ca-cert", "der", matchers::app::is_der),
    (MatcherType::App, "application/x-executable", "obj", matchers::app::is_coff),
    (MatcherType::App, "application/x-x509-ca-cert", "pem", matchers::app::is_pem),
    (MatcherType::App, "application/x-qemu-disk", "qcow2", matchers::app::is_qcow2),
    (
        MatcherType::App,
        "application/vnd.trueos.blueprint",
        "bp",
        matchers::app::is_trueos_blueprint
    ),
    // Book
    (MatcherType::Book, "application/epub+zip", "epub", matchers::book::is_epub),
    (MatcherType::Book, "application/x-mobipocket-ebook", "mobi", matchers::book::is_mobi),
    // Image
    (MatcherType::Image, "image/jpeg", "jpg", matchers::image::is_jpeg),
    (MatcherType::Image, "image/jp2", "jp2", matchers::image::is_jpeg2000),
    (MatcherType::Image, "image/png", "png", matchers::image::is_png),
    (MatcherType::Image, "image/gif", "gif", matchers::image::is_gif),
    (MatcherType::Image, "image/webp", "webp", matchers::image::is_webp),
    (MatcherType::Image, "image/x-canon-cr2", "cr2", matchers::image::is_cr2),
    (MatcherType::Image, "image/tiff", "tif", matchers::image::is_tiff),
    (MatcherType::Image, "image/bmp", "bmp", matchers::image::is_bmp),
    (MatcherType::Image, "image/vnd.ms-photo", "jxr", matchers::image::is_jxr),
    (MatcherType::Image, "image/vnd.adobe.photoshop", "psd", matchers::image::is_psd),
    (MatcherType::Image, "image/vnd.microsoft.icon", "ico", matchers::image::is_ico),
    (MatcherType::Image, "image/heif", "heif", matchers::image::is_heif),
    (MatcherType::Image, "image/avif", "avif", matchers::image::is_avif),
    (MatcherType::Image, "image/jxl", "jxl", matchers::image::is_jxl),
    (MatcherType::Image, "image/openraster", "ora", matchers::image::is_ora),
    (MatcherType::Image, "image/vnd.djvu", "djvu", matchers::image::is_djvu),
    (MatcherType::Image, "image/vnd.dwg", "dwg", matchers::image::is_dwg),
    // Video
    (MatcherType::Video, "video/mp4", "mp4", matchers::video::is_mp4),
    (MatcherType::Video, "video/x-m4v", "m4v", matchers::video::is_m4v),
    (MatcherType::Video, "video/x-matroska", "mkv", matchers::video::is_mkv),
    (MatcherType::Video, "video/webm", "webm", matchers::video::is_webm),
    (MatcherType::Video, "video/quicktime", "mov", matchers::video::is_mov),
    (MatcherType::Video, "video/x-msvideo", "avi", matchers::video::is_avi),
    (MatcherType::Video, "video/x-ms-wmv", "wmv", matchers::video::is_wmv),
    (MatcherType::Video, "video/mpeg", "mpg", matchers::video::is_mpeg),
    (MatcherType::Video, "video/x-flv", "flv", matchers::video::is_flv),
    // Audio
    (MatcherType::Audio, "audio/midi", "midi", matchers::audio::is_midi),
    (MatcherType::Audio, "audio/mpeg", "mp3", matchers::audio::is_mp3),
    (MatcherType::Audio, "audio/m4a", "m4a", matchers::audio::is_m4a),
    // has to come before ogg
    (MatcherType::Audio, "audio/opus", "opus", matchers::audio::is_ogg_opus),
    (MatcherType::Audio, "audio/ogg", "ogg", matchers::audio::is_ogg),
    (MatcherType::Audio, "audio/x-flac", "flac", matchers::audio::is_flac),
    (MatcherType::Audio, "audio/x-wav", "wav", matchers::audio::is_wav),
    (MatcherType::Audio, "audio/amr", "amr", matchers::audio::is_amr),
    (MatcherType::Audio, "audio/aac", "aac", matchers::audio::is_aac),
    (MatcherType::Audio, "audio/x-aiff", "aiff", matchers::audio::is_aiff),
    (MatcherType::Audio, "audio/x-dsf", "dsf", matchers::audio::is_dsf),
    (MatcherType::Audio, "audio/x-ape", "ape", matchers::audio::is_ape),
    // Font
    (MatcherType::Font, "application/font-woff", "woff", matchers::font::is_woff),
    (MatcherType::Font, "application/font-woff", "woff2", matchers::font::is_woff2),
    (MatcherType::Font, "application/font-sfnt", "ttf", matchers::font::is_ttf),
    (MatcherType::Font, "application/font-sfnt", "otf", matchers::font::is_otf),
    // Document
    (MatcherType::Doc, "application/msword", "doc", matchers::doc::is_doc),
    (
        MatcherType::Doc,
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "docx",
        matchers::doc::is_docx
    ),
    (MatcherType::Doc, "application/vnd.ms-excel", "xls", matchers::doc::is_xls),
    (
        MatcherType::Doc,
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "xlsx",
        matchers::doc::is_xlsx
    ),
    (MatcherType::Doc, "application/vnd.ms-powerpoint", "ppt", matchers::doc::is_ppt),
    (
        MatcherType::Doc,
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pptx",
        matchers::doc::is_pptx
    ),
    // OpenDocument
    (MatcherType::Doc, "application/vnd.oasis.opendocument.text", "odt", matchers::odf::is_odt),
    (
        MatcherType::Doc,
        "application/vnd.oasis.opendocument.spreadsheet",
        "ods",
        matchers::odf::is_ods
    ),
    (
        MatcherType::Doc,
        "application/vnd.oasis.opendocument.presentation",
        "odp",
        matchers::odf::is_odp
    ),
    // Archive
    (MatcherType::Archive, "application/epub+zip", "epub", matchers::archive::is_epub),
    (MatcherType::Archive, "application/zip", "zip", matchers::archive::is_zip),
    (MatcherType::Archive, "application/x-tar", "tar", matchers::archive::is_tar),
    (MatcherType::Archive, "application/x-par2", "par2", matchers::archive::is_par2),
    (MatcherType::Archive, "application/vnd.rar", "rar", matchers::archive::is_rar),
    (MatcherType::Archive, "application/gzip", "gz", matchers::archive::is_gz),
    (MatcherType::Archive, "application/x-bzip2", "bz2", matchers::archive::is_bz2),
    (MatcherType::Archive, "application/vnd.bzip3", "bz3", matchers::archive::is_bz3),
    (MatcherType::Archive, "application/x-7z-compressed", "7z", matchers::archive::is_7z),
    (MatcherType::Archive, "application/x-xz", "xz", matchers::archive::is_xz),
    (MatcherType::Archive, "application/pdf", "pdf", matchers::archive::is_pdf),
    (MatcherType::Archive, "application/x-shockwave-flash", "swf", matchers::archive::is_swf),
    (MatcherType::Archive, "application/rtf", "rtf", matchers::archive::is_rtf),
    (MatcherType::Archive, "application/octet-stream", "eot", matchers::archive::is_eot),
    (MatcherType::Archive, "application/postscript", "ps", matchers::archive::is_ps),
    (MatcherType::Archive, "application/vnd.sqlite3", "sqlite", matchers::archive::is_sqlite),
    (MatcherType::Archive, "application/x-nintendo-nes-rom", "nes", matchers::archive::is_nes),
    (
        MatcherType::Archive,
        "application/x-google-chrome-extension",
        "crx",
        matchers::archive::is_crx
    ),
    (MatcherType::Archive, "application/vnd.ms-cab-compressed", "cab", matchers::archive::is_cab),
    (
        MatcherType::Archive,
        "application/vnd.debian.binary-package",
        "deb",
        matchers::archive::is_deb
    ),
    (MatcherType::Archive, "application/x-unix-archive", "ar", matchers::archive::is_ar),
    (MatcherType::Archive, "application/x-compress", "Z", matchers::archive::is_z),
    (MatcherType::Archive, "application/x-lzip", "lz", matchers::archive::is_lz),
    (MatcherType::Archive, "application/x-rpm", "rpm", matchers::archive::is_rpm),
    (MatcherType::Archive, "application/dicom", "dcm", matchers::archive::is_dcm),
    (MatcherType::Archive, "application/zstd", "zst", matchers::archive::is_zst),
    (MatcherType::Archive, "application/x-lz4", "lz4", matchers::archive::is_lz4),
    (MatcherType::Archive, "application/x-ole-storage", "msi", matchers::archive::is_msi),
    (MatcherType::Archive, "application/x-cpio", "cpio", matchers::archive::is_cpio),
    // Text
    (MatcherType::Text, "text/html", "html", matchers::text::is_html),
    (MatcherType::Text, "text/xml", "xml", matchers::text::is_xml),
    (MatcherType::Text, "text/x-shellscript", "sh", matchers::text::is_shellscript)
);

#[inline]
fn normalized_extension(token: &str) -> Option<&str> {
    let token = token.strip_prefix('.').unwrap_or(token);
    (!token.is_empty() && !token.contains('/') && !token.contains('\\')).then_some(token)
}

pub fn content_type_from_extension(token: &str) -> Option<ContentTypeId> {
    let extension = normalized_extension(token)?;
    CONTENT_TYPES
        .iter()
        .find(|info| {
            info.preferred_extension
                .is_some_and(|value| value.eq_ignore_ascii_case(extension))
                || info
                    .aliases
                    .iter()
                    .any(|alias| alias.eq_ignore_ascii_case(extension))
        })
        .map(|info| info.id)
}

pub const fn content_type_info(id: ContentTypeId) -> Option<&'static ContentTypeInfo> {
    let mut index = 0;
    while index < CONTENT_TYPES.len() {
        let info = &CONTENT_TYPES[index];
        if info.id.raw() == id.raw() {
            return Some(info);
        }
        index += 1;
    }
    None
}

pub const fn is_registered_content_type(id: ContentTypeId) -> bool {
    content_type_info(id).is_some()
}

pub(crate) fn content_type_id_for_type(
    matcher_type: MatcherType,
    mime_type: &str,
    extension: &str,
) -> ContentTypeId {
    // Types constructed by user code must never accidentally obtain a native
    // identity just because they reuse an extension. Match every legacy field.
    if (mime_type == "application/msword" && extension == "doc")
        || (mime_type == "application/vnd.ms-excel" && extension == "xls")
        || (mime_type == "application/vnd.ms-powerpoint" && extension == "ppt")
        || (mime_type == "application/x-ole-storage" && extension == "msi")
    {
        return ContentTypeId::OLE_COMPOUND_FILE;
    }

    for info in CONTENT_TYPES {
        if info.matcher_type == Some(matcher_type)
            && info.mime_type == mime_type
            && (info.preferred_extension == Some(extension)
                || info.aliases.contains(&extension))
        {
            return info.id;
        }
    }
    ContentTypeId::NONE
}
