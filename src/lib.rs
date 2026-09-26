/*!
Small crate to infer file and MIME type by checking the
[magic number](https://en.wikipedia.org/wiki/Magic_number_(programming)) signature.

# Examples

### Get the type of a buffer

```rust
let buf = [0xFF, 0xD8, 0xFF, 0xAA];
let kind = infer::get(&buf).expect("file type is known");

assert_eq!(kind.mime_type(), "image/jpeg");
assert_eq!(kind.extension(), "jpg");
assert_eq!(kind.matcher_type(), infer::MatcherType::Image);
```

### Check file type by path

```rust
# #[cfg(feature = "std")]
# fn run() {
let kind = infer::get_from_path("testdata/sample.jpg")
    .expect("file read successfully")
    .expect("file type is known");

assert_eq!(kind.mime_type(), "image/jpeg");
assert_eq!(kind.extension(), "jpg");
# }
```

### Check for specific type

```rust
let buf = [0xFF, 0xD8, 0xFF, 0xAA];
assert!(infer::image::is_jpeg(&buf));
```

### Check for specific type class

```rust
let buf = [0xFF, 0xD8, 0xFF, 0xAA];
assert!(infer::is_image(&buf));
```

### Adds a custom file type matcher

Here we actually need to use the `Infer` struct to be able to declare custom matchers.

```rust
# #[cfg(feature = "alloc")]
# fn run() {
fn custom_matcher(buf: &[u8]) -> bool {
    return buf.len() >= 3 && buf[0] == 0x10 && buf[1] == 0x11 && buf[2] == 0x12;
}

let mut info = infer::Infer::new();
info.add("custom/foo", "foo", custom_matcher);

let buf = [0x10, 0x11, 0x12, 0x13];
let kind = info.get(&buf).unwrap();

assert_eq!(kind.mime_type(), "custom/foo");
assert_eq!(kind.extension(), "foo");
# }
```
*/

#![crate_name = "infer"]
#![doc(html_root_url = "https://docs.rs/infer/latest")]
#![forbid(unsafe_code)]
#![allow(clippy::struct_field_names)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod map;
mod matchers;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;
#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::{self, Read};
#[cfg(feature = "std")]
use std::path::Path;

pub use map::{
    content_type_from_extension, content_type_info, is_registered_content_type, ContentTypeId,
    ContentTypeInfo, MatcherType, CONTENT_TYPES,
};
use map::{content_type_id_for_type, WrapMatcher, MATCHER_MAP};

/// All the supported matchers categorized and exposed as functions
pub use matchers::*;

/// Matcher function
pub type Matcher = fn(buf: &[u8]) -> bool;

/// Generic information for a type
#[derive(Copy, Clone)]
pub struct Type {
    matcher_type: MatcherType,
    mime_type: &'static str,
    extension: &'static str,
    matcher: WrapMatcher,
}

impl Type {
    pub(crate) const fn new_static(
        matcher_type: MatcherType,
        mime_type: &'static str,
        extension: &'static str,
        matcher: WrapMatcher,
    ) -> Self {
        Self {
            matcher_type,
            mime_type,
            extension,
            matcher,
        }
    }

    /// Returns a new `Type` with matcher and extension.
    pub fn new(
        matcher_type: MatcherType,
        mime_type: &'static str,
        extension: &'static str,
        matcher: Matcher,
    ) -> Self {
        Self::new_static(matcher_type, mime_type, extension, WrapMatcher(matcher))
    }

    /// Returns the type of matcher
    ///
    /// # Examples
    ///
    /// ```rust
    /// let info = infer::Infer::new();
    /// let buf = [0xFF, 0xD8, 0xFF, 0xAA];
    /// let kind = info.get(&buf).expect("file type is known");
    ///
    /// assert_eq!(kind.matcher_type(), infer::MatcherType::Image);
    /// ```
    #[must_use]
    pub const fn matcher_type(&self) -> MatcherType {
        self.matcher_type
    }

    /// Returns the mime type
    #[must_use]
    pub const fn mime_type(&self) -> &'static str {
        self.mime_type
    }

    /// Returns the file extension
    #[must_use]
    pub const fn extension(&self) -> &'static str {
        self.extension
    }

    /// Returns the stable native content identity for this built-in matcher.
    ///
    /// Types supplied through [`Infer::add`] deliberately return
    /// [`ContentTypeId::NONE`]: user matchers do not allocate durable IDs.
    #[must_use]
    pub fn content_type_id(&self) -> ContentTypeId {
        content_type_id_for_type(self.matcher_type, self.mime_type, self.extension)
    }

    /// Checks if buf matches this Type
    fn matches(&self, buf: &[u8]) -> bool {
        (self.matcher.0)(buf)
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Type")
            .field("matcher_type", &self.matcher_type)
            .field("mime_type", &self.mime_type)
            .field("extension", &self.extension)
            .field("content_type_id", &self.content_type_id())
            // `matcher` is not exposed
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.mime_type, f)
    }
}

impl PartialEq for Type {
    fn eq(&self, other: &Self) -> bool {
        self.matcher_type == other.matcher_type
            && self.mime_type == other.mime_type
            && self.extension == other.extension
    }
}

/// Infer allows to use a custom set of `Matcher`s for infering a MIME type.
///
/// Most operations can be done by using the _top level functions_, but when custom matchers
/// are needed every call has to go through the `Infer` struct to be able
/// to see the custom matchers.
pub struct Infer {
    #[cfg(feature = "alloc")]
    mmap: Vec<Type>,
}

impl Infer {
    /// Initialize a new instance of the infer struct.
    #[must_use]
    pub const fn new() -> Infer {
        #[cfg(feature = "alloc")]
        return Infer { mmap: Vec::new() };

        #[cfg(not(feature = "alloc"))]
        return Infer {};
    }

    fn iter_matchers(&self) -> impl Iterator<Item = &Type> {
        let mmap = MATCHER_MAP.iter();

        #[cfg(feature = "alloc")]
        return self.mmap.iter().chain(mmap);

        #[cfg(not(feature = "alloc"))]
        return mmap;
    }

    /// Returns the file type of the buffer.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let info = infer::Infer::new();
    /// let buf = [0xFF, 0xD8, 0xFF, 0xAA];
    /// let kind = info.get(&buf).expect("file type is known");
    ///
    /// assert_eq!(kind.mime_type(), "image/jpeg");
    /// assert_eq!(kind.extension(), "jpg");
    /// ```
    #[must_use]
    pub fn get(&self, buf: &[u8]) -> Option<Type> {
        self.iter_matchers().find(|kind| kind.matches(buf)).copied()
    }

    /// Returns the file type of the file given a path.
    ///
    /// # Examples
    ///
    /// See [`get_from_path`](./fn.get_from_path.html).
    /// # Errors
    ///
    /// Will return `Err` if `path` does not exist or the user does not have
    /// permission to read it.
    #[cfg(feature = "std")]
    pub fn get_from_path<P: AsRef<Path>>(&self, path: P) -> io::Result<Option<Type>> {
        let file = File::open(path)?;

        let limit = file
            .metadata()
            .ok()
            .and_then(|m| usize::try_from(std::cmp::min(m.len(), 8192)).ok())
            .map_or(0, |len| len + 1);
        let mut bytes = Vec::with_capacity(limit);
        file.take(8192).read_to_end(&mut bytes)?;

        Ok(self.get(&bytes))
    }

    /// Determines whether a buffer is of given extension.
    ///
    /// # Examples
    ///
    /// See [`is`](./fn.is.html).
    #[must_use]
    pub fn is(&self, buf: &[u8], extension: &str) -> bool {
        self.iter_matchers()
            .any(|kind| kind.extension() == extension && kind.matches(buf))
    }

    /// Determines whether a buffer is of given mime type.
    ///
    /// # Examples
    ///
    /// See [`is_mime`](./fn.is_mime.html).
    #[must_use]
    pub fn is_mime(&self, buf: &[u8], mime_type: &str) -> bool {
        self.iter_matchers()
            .any(|kind| kind.mime_type() == mime_type && kind.matches(buf))
    }

    /// Returns whether an extension is supported.
    ///
    /// # Examples
    ///
    /// See [`is_supported`](./fn.is_supported.html).
    #[must_use]
    pub fn is_supported(&self, extension: &str) -> bool {
        self.iter_matchers()
            .any(|kind| kind.extension() == extension)
    }

    /// Returns whether a mime type is supported.
    ///
    /// # Examples
    ///
    /// See [`is_mime_supported`](./fn.is_mime_supported.html).
    #[must_use]
    pub fn is_mime_supported(&self, mime_type: &str) -> bool {
        self.iter_matchers()
            .any(|kind| kind.mime_type() == mime_type)
    }

    /// Determines whether a buffer is an application type.
    ///
    /// # Examples
    ///
    /// See [`is_app`](./fn.is_app.html).
    #[must_use]
    pub fn is_app(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::App)
    }

    /// Determines whether a buffer is an archive type.
    ///
    /// # Examples
    ///
    /// See [`is_archive`](./fn.is_archive.html).
    #[must_use]
    pub fn is_archive(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Archive)
    }

    /// Determines whether a buffer is an audio type.
    ///
    /// # Examples
    ///
    /// See [`is_audio`](./fn.is_audio.html).
    #[must_use]
    pub fn is_audio(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Audio)
    }

    /// Determines whether a buffer is a book type.
    ///
    /// # Examples
    ///
    /// See [`is_book`](./fn.is_book.html).
    #[must_use]
    pub fn is_book(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Book)
    }

    /// Determines whether a buffer is a document type.
    ///
    /// # Examples
    ///
    /// See [`is_document`](./fn.is_document.html).
    #[must_use]
    pub fn is_document(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Doc)
    }

    /// Determines whether a buffer is a font type.
    ///
    /// # Examples
    ///
    /// See [`is_font`](./fn.is_font.html).
    #[must_use]
    pub fn is_font(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Font)
    }

    /// Determines whether a buffer is an image type.
    ///
    /// # Examples
    ///
    /// See [`is_image`](./fn.is_image.html).
    #[must_use]
    pub fn is_image(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Image)
    }

    /// Determines whether a buffer is a video type.
    ///
    /// # Examples
    ///
    /// See [`is_video`](./fn.is_video.html).
    #[must_use]
    pub fn is_video(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Video)
    }

    /// Determines whether a buffer is one of the custom types added.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "alloc")]
    /// # fn run() {
    /// fn custom_matcher(buf: &[u8]) -> bool {
    ///     return buf.len() >= 3 && buf[0] == 0x10 && buf[1] == 0x11 && buf[2] == 0x12;
    /// }
    ///
    /// let mut info = infer::Infer::new();
    /// info.add("custom/foo", "foo", custom_matcher);
    /// let buf = [0x10, 0x11, 0x12, 0x13];
    /// assert!(info.is_custom(&buf));
    /// # }
    /// ```
    #[must_use]
    pub fn is_custom(&self, buf: &[u8]) -> bool {
        self.is_type(buf, MatcherType::Custom)
    }

    /// Adds a custom matcher.
    ///
    /// Custom matchers are matched in order of addition and before
    /// the default set of matchers.
    ///
    /// # Examples
    ///
    /// ```rust
    /// fn custom_matcher(buf: &[u8]) -> bool {
    ///     return buf.len() >= 3 && buf[0] == 0x10 && buf[1] == 0x11 && buf[2] == 0x12;
    /// }
    ///
    /// let mut info = infer::Infer::new();
    /// info.add("custom/foo", "foo", custom_matcher);
    /// let buf = [0x10, 0x11, 0x12, 0x13];
    /// let kind =  info.get(&buf).expect("file type is known");
    ///
    /// assert_eq!(kind.mime_type(), "custom/foo");
    /// assert_eq!(kind.extension(), "foo");
    /// ```
    #[cfg(feature = "alloc")]
    pub fn add(&mut self, mime_type: &'static str, extension: &'static str, m: Matcher) {
        self.mmap
            .push(Type::new_static(MatcherType::Custom, mime_type, extension, WrapMatcher(m)));
    }

    fn is_type(&self, buf: &[u8], matcher_type: MatcherType) -> bool {
        self.iter_matchers()
            .any(|kind| kind.matcher_type() == matcher_type && kind.matches(buf))
    }
}

impl Default for Infer {
    fn default() -> Self {
        Infer::new()
    }
}

static INFER: Infer = Infer::new();

/// Returns the file type of the buffer.
///
/// # Examples
///
/// ```rust
/// let info = infer::Infer::new();
/// let buf = [0xFF, 0xD8, 0xFF, 0xAA];
/// let kind = info.get(&buf).expect("file type is known");
///
/// assert_eq!(kind.mime_type(), "image/jpeg");
/// assert_eq!(kind.extension(), "jpg");
/// ```
#[must_use]
pub fn get(buf: &[u8]) -> Option<Type> {
    INFER.get(buf)
}

/// Return the one stable content identity evidenced by `buf`.
///
/// This is a signature detector, not a complete parser or security validator.
/// `BLOB` is never inferred. Strict UTF-8 is recognised only as the final
/// fallback after every more-specific matcher, and an empty byte sequence has
/// no inferred identity.
#[must_use]
pub fn detect_content_type(buf: &[u8]) -> Option<ContentTypeId> {
    // `get` retains its historic std-assisted DOC/XLS/PPT classification for
    // compatibility. Native content identity must not vary with features, and
    // the CFB magic alone proves only the generic container.
    if archive::is_ole_compound(buf) {
        return Some(ContentTypeId::OLE_COMPOUND_FILE);
    }
    if let Some(kind) = get(buf) {
        let id = kind.content_type_id();
        if id != ContentTypeId::NONE {
            return Some(id);
        }
    }
    (!buf.is_empty() && core::str::from_utf8(buf).is_ok()).then_some(ContentTypeId::UTF8_TEXT)
}

/// Return whether `buf` detects as exactly `expected`.
///
/// This intentionally compares the selected detection result rather than
/// calling an individual broad matcher: an EPUB is not accepted as ZIP, and a
/// CR2 is not accepted as generic TIFF.
#[must_use]
pub fn matches_content_type(buf: &[u8], expected: ContentTypeId) -> bool {
    detect_content_type(buf) == Some(expected)
}

/// Return all registered native content types in frozen-ID order.
#[must_use]
pub const fn content_types() -> &'static [ContentTypeInfo] {
    CONTENT_TYPES
}

/// Returns the file type of the file given a path.
///
/// # Errors
///
/// Returns an error if we fail to read the path.
///
/// # Examples
///
/// ```rust
/// let kind = infer::get_from_path("testdata/sample.jpg")
///     .expect("file read successfully")
///     .expect("file type is known");
///
/// assert_eq!(kind.mime_type(), "image/jpeg");
/// assert_eq!(kind.extension(), "jpg");
/// ```
#[cfg(feature = "std")]
pub fn get_from_path<P: AsRef<Path>>(path: P) -> io::Result<Option<Type>> {
    INFER.get_from_path(path)
}

/// Determines whether a buffer is of given extension.
///
/// # Examples
///
/// ```rust
/// let buf = [0xFF, 0xD8, 0xFF, 0xAA];
/// assert!(infer::is(&buf, "jpg"));
/// ```
#[must_use]
pub fn is(buf: &[u8], extension: &str) -> bool {
    INFER.is(buf, extension)
}

/// Determines whether a buffer is of given mime type.
///
/// # Examples
///
/// ```rust
/// let buf = [0xFF, 0xD8, 0xFF, 0xAA];
/// assert!(infer::is_mime(&buf, "image/jpeg"));
/// ```
#[must_use]
pub fn is_mime(buf: &[u8], mime_type: &str) -> bool {
    INFER.is_mime(buf, mime_type)
}

/// Returns whether an extension is supported.
///
/// # Examples
///
/// ```rust
/// assert!(infer::is_supported("jpg"));
/// ```
#[must_use]
pub fn is_supported(extension: &str) -> bool {
    INFER.is_supported(extension)
}

/// Returns whether a mime type is supported.
///
/// # Examples
///
/// ```rust
/// assert!(infer::is_mime_supported("image/jpeg"));
/// ```
#[must_use]
pub fn is_mime_supported(mime_type: &str) -> bool {
    INFER.is_mime_supported(mime_type)
}

/// Determines whether a buffer is an application type.
///
/// # Examples
///
/// ```rust
/// use std::fs;
/// assert!(infer::is_app(&fs::read("testdata/sample.wasm").unwrap()));
/// ```
#[must_use]
pub fn is_app(buf: &[u8]) -> bool {
    INFER.is_app(buf)
}

/// Determines whether a buffer is an archive type.
/// # Examples
///
/// ```rust
/// use std::fs;
/// assert!(infer::is_archive(&fs::read("testdata/sample.pdf").unwrap()));
/// ```
#[must_use]
pub fn is_archive(buf: &[u8]) -> bool {
    INFER.is_archive(buf)
}

/// Determines whether a buffer is an audio type.
///
/// # Examples
///
/// ```rust
/// // mp3
/// let v = [0xff, 0xfb, 0x90, 0x44, 0x00];
/// assert!(infer::is_audio(&v));
/// ```
#[must_use]
pub fn is_audio(buf: &[u8]) -> bool {
    INFER.is_audio(buf)
}

/// Determines whether a buffer is a book type.
///
/// # Examples
///
/// ```rust
/// use std::fs;
/// assert!(infer::is_book(&fs::read("testdata/sample.epub").unwrap()));
/// ```
#[must_use]
pub fn is_book(buf: &[u8]) -> bool {
    INFER.is_book(buf)
}

/// Determines whether a buffer is a document type.
///
/// # Examples
///
/// ```rust
/// use std::fs;
/// assert!(infer::is_document(&fs::read("testdata/sample.docx").unwrap()));
/// ```
#[must_use]
pub fn is_document(buf: &[u8]) -> bool {
    INFER.is_document(buf)
}

/// Determines whether a buffer is a font type.
///
/// # Examples
///
/// ```rust
/// use std::fs;
/// assert!(infer::is_font(&fs::read("testdata/sample.ttf").unwrap()));
/// ```
#[must_use]
pub fn is_font(buf: &[u8]) -> bool {
    INFER.is_font(buf)
}

/// Determines whether a buffer is an image type.
///
/// # Examples
///
/// ```rust
/// let v = [0xFF, 0xD8, 0xFF, 0xAA];
/// assert!(infer::is_image(&v));
/// ```
#[must_use]
pub fn is_image(buf: &[u8]) -> bool {
    INFER.is_image(buf)
}

/// Determines whether a buffer is a video type.
///
/// # Examples
///
/// ```rust
/// use std::fs;
/// assert!(infer::is_video(&fs::read("testdata/sample.mov").unwrap()));
/// ```
#[must_use]
pub fn is_video(buf: &[u8]) -> bool {
    INFER.is_video(buf)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "alloc")]
    use super::Infer;

    #[test]
    fn test_get_unknown() {
        let buf = [];
        assert!(crate::get(&buf).is_none());
    }

    #[test]
    fn test_get_jpeg() {
        let buf = [0xFF, 0xD8, 0xFF, 0xAA];
        let kind = crate::get(&buf).expect("file type is known");
        assert_eq!(kind.extension(), "jpg");
        assert_eq!(kind.mime_type(), "image/jpeg");
    }

    #[test]
    fn test_matcher_type() {
        let buf = [0xFF, 0xD8, 0xFF, 0xAA];
        let kind = crate::get(&buf).expect("file type is known");
        assert_eq!(kind.matcher_type(), crate::MatcherType::Image);
    }

    #[test]
    fn content_registry_is_frozen_and_unique() {
        const FROZEN_V1: &[(&str, u32)] = &[
            ("BLOB", 0x0000_0001),
            ("UTF8_TEXT", 0x0000_0002),
            ("AAC", 0x0001_0000),
            ("AIFF", 0x0001_0001),
            ("AMR", 0x0001_0002),
            ("APE", 0x0001_0003),
            ("AR", 0x0001_0004),
            ("AVI", 0x0001_0005),
            ("AVIF", 0x0001_0006),
            ("BMP", 0x0001_0007),
            ("BZIP2", 0x0001_0008),
            ("BZIP3", 0x0001_0009),
            ("CAB", 0x0001_000A),
            ("CANON_CR2", 0x0001_000B),
            ("COFF_OBJECT", 0x0001_000C),
            ("COMPRESS_Z", 0x0001_000D),
            ("CPIO", 0x0001_000E),
            ("CRX", 0x0001_000F),
            ("DEB", 0x0001_0010),
            ("DER_CERTIFICATE", 0x0001_0011),
            ("DEX", 0x0001_0012),
            ("DICOM", 0x0001_0013),
            ("DJVU", 0x0001_0014),
            ("DOCX", 0x0001_0015),
            ("DSF", 0x0001_0016),
            ("DWG", 0x0001_0017),
            ("ELF", 0x0001_0018),
            ("EOT", 0x0001_0019),
            ("EPUB", 0x0001_001A),
            ("FLAC", 0x0001_001B),
            ("FLV", 0x0001_001C),
            ("GIF", 0x0001_001D),
            ("GZIP", 0x0001_001E),
            ("HEIF", 0x0001_001F),
            ("HTML", 0x0001_0020),
            ("ICO", 0x0001_0021),
            ("JAVA_CLASS", 0x0001_0022),
            ("JPEG", 0x0001_0023),
            ("JPEG_2000", 0x0001_0024),
            ("JPEG_XL", 0x0001_0025),
            ("JXR", 0x0001_0026),
            ("LLVM_BITCODE", 0x0001_0027),
            ("LZ4", 0x0001_0028),
            ("LZIP", 0x0001_0029),
            ("M4A", 0x0001_002A),
            ("M4V", 0x0001_002B),
            ("MACH_O", 0x0001_002C),
            ("MATROSKA", 0x0001_002D),
            ("MIDI", 0x0001_002E),
            ("MOBI", 0x0001_002F),
            ("MP3", 0x0001_0030),
            ("MP4", 0x0001_0031),
            ("MPEG_VIDEO", 0x0001_0032),
            ("NES_ROM", 0x0001_0033),
            ("ODEX", 0x0001_0034),
            ("ODP", 0x0001_0035),
            ("ODS", 0x0001_0036),
            ("ODT", 0x0001_0037),
            ("OGG", 0x0001_0038),
            ("OLE_COMPOUND_FILE", 0x0001_0039),
            ("OPENRASTER", 0x0001_003A),
            ("OPUS", 0x0001_003B),
            ("OTF", 0x0001_003C),
            ("PAR2", 0x0001_003D),
            ("PDF", 0x0001_003E),
            ("PEM_CERTIFICATE", 0x0001_003F),
            ("PNG", 0x0001_0040),
            ("PORTABLE_EXECUTABLE", 0x0001_0041),
            ("POSTSCRIPT", 0x0001_0042),
            ("PPTX", 0x0001_0043),
            ("PSD", 0x0001_0044),
            ("QCOW2", 0x0001_0045),
            ("QUICKTIME", 0x0001_0046),
            ("RAR", 0x0001_0047),
            ("RPM", 0x0001_0048),
            ("RTF", 0x0001_0049),
            ("SEVEN_Z", 0x0001_004A),
            ("SHELL_SCRIPT", 0x0001_004B),
            ("SQLITE", 0x0001_004C),
            ("SWF", 0x0001_004D),
            ("TAR", 0x0001_004E),
            ("TIFF", 0x0001_004F),
            ("TRUEOS_BLUEPRINT", 0x0001_0050),
            ("TTF", 0x0001_0051),
            ("WASM", 0x0001_0052),
            ("WAV", 0x0001_0053),
            ("WEBM", 0x0001_0054),
            ("WEBP", 0x0001_0055),
            ("WMV", 0x0001_0056),
            ("WOFF", 0x0001_0057),
            ("WOFF2", 0x0001_0058),
            ("XLSX", 0x0001_0059),
            ("XML", 0x0001_005A),
            ("XZ", 0x0001_005B),
            ("ZIP", 0x0001_005C),
            ("ZSTD", 0x0001_005D),
            ("WARCRAFT3_MAP", 0x0001_005E),
        ];

        assert_eq!(crate::ContentTypeId::NONE.raw(), 0);
        assert_eq!(crate::ContentTypeId::BLOB.raw(), 1);
        assert_eq!(crate::ContentTypeId::UTF8_TEXT.raw(), 2);
        assert_eq!(crate::ContentTypeId::HTML.raw(), 0x0001_0020);
        assert_eq!(crate::ContentTypeId::PNG.raw(), 0x0001_0040);
        assert_eq!(crate::ContentTypeId::WAV.raw(), 0x0001_0053);
        assert_eq!(crate::ContentTypeId::TRUEOS_BLUEPRINT.raw(), 0x0001_0050);
        assert_eq!(crate::content_types().len(), FROZEN_V1.len());
        for (info, &(canonical_name, raw)) in crate::content_types().iter().zip(FROZEN_V1) {
            assert_eq!(info.canonical_name, canonical_name);
            assert_eq!(info.id.raw(), raw);
        }
        for (index, info) in crate::content_types().iter().enumerate() {
            assert_eq!(crate::content_type_info(info.id), Some(info));
            assert!(crate::is_registered_content_type(info.id));
            assert!(info.id.is_registered());
            assert!(crate::content_types()[..index]
                .iter()
                .all(|earlier| earlier.id != info.id));
        }
        assert!(!crate::is_registered_content_type(crate::ContentTypeId::NONE));
        assert!(!crate::is_registered_content_type(crate::ContentTypeId::from_raw(0xD00D_F00D)));
        let mut previous: Option<&crate::ContentTypeInfo> = None;
        for info in crate::content_types()
            .iter()
            .filter(|info| info.id.raw() >= 0x0001_0000)
        {
            if let Some(previous) = previous {
                // The original registry was alphabetical. New identities are
                // appended without renumbering those frozen on-disk IDs.
                if info.id.raw() <= crate::ContentTypeId::ZSTD.raw() {
                    assert!(previous.canonical_name < info.canonical_name);
                }
                assert_eq!(previous.id.raw() + 1, info.id.raw());
            }
            previous = Some(info);
        }
    }

    #[test]
    fn extension_lookup_is_explicit_and_case_insensitive() {
        assert_eq!(crate::content_type_from_extension(".PNG"), Some(crate::ContentTypeId::PNG));
        assert_eq!(crate::content_type_from_extension("jpeg"), Some(crate::ContentTypeId::JPEG));
        assert_eq!(
            crate::content_type_from_extension("dll"),
            Some(crate::ContentTypeId::PORTABLE_EXECUTABLE)
        );
        assert_eq!(
            crate::content_type_from_extension("doc"),
            Some(crate::ContentTypeId::OLE_COMPOUND_FILE)
        );
        assert_eq!(
            crate::content_type_from_extension("msi"),
            Some(crate::ContentTypeId::OLE_COMPOUND_FILE)
        );
        assert_eq!(crate::content_type_from_extension(".bin"), Some(crate::ContentTypeId::BLOB));
        assert_eq!(crate::content_type_from_extension("unknown"), None);
        assert_eq!(crate::content_type_from_extension("dir/png"), None);
    }

    #[test]
    fn type_exposes_stable_identity() {
        let kind = crate::get(b"\x89PNG\r\n\x1A\n").unwrap();
        assert_eq!(kind.content_type_id(), crate::ContentTypeId::PNG);
    }

    #[test]
    fn strict_detection_never_infers_blob_and_uses_utf8_last() {
        assert_eq!(crate::detect_content_type(b""), None);
        assert_eq!(crate::detect_content_type(&[0xFF]), None);
        assert_eq!(
            crate::detect_content_type(b"plain text"),
            Some(crate::ContentTypeId::UTF8_TEXT)
        );
        assert_eq!(
            crate::detect_content_type(b"<html>ok</html>"),
            Some(crate::ContentTypeId::HTML)
        );
        assert!(!crate::matches_content_type(b"plain text", crate::ContentTypeId::BLOB));
        assert!(!crate::matches_content_type(b"<html>ok</html>", crate::ContentTypeId::UTF8_TEXT));
    }

    #[test]
    fn strict_pe_and_generic_ole_are_feature_invariant() {
        let mut pe = [0u8; 0x80];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x40u32).to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(
            crate::detect_content_type(&pe),
            Some(crate::ContentTypeId::PORTABLE_EXECUTABLE)
        );
        pe[0x56..0x58].copy_from_slice(&(0x2000u16).to_le_bytes());
        assert_eq!(
            crate::detect_content_type(&pe),
            Some(crate::ContentTypeId::PORTABLE_EXECUTABLE)
        );
        assert_ne!(
            crate::detect_content_type(b"MZ"),
            Some(crate::ContentTypeId::PORTABLE_EXECUTABLE)
        );
        assert_eq!(
            crate::detect_content_type(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
            Some(crate::ContentTypeId::OLE_COMPOUND_FILE)
        );
    }

    #[test]
    fn equality_uses_selected_identity_not_a_broad_predicate() {
        let mut epub = [0u8; 58];
        epub[..4].copy_from_slice(b"PK\x03\x04");
        epub[30..58].copy_from_slice(b"mimetypeapplication/epub+zip");
        assert_eq!(crate::detect_content_type(&epub), Some(crate::ContentTypeId::EPUB));
        assert!(crate::matches_content_type(&epub, crate::ContentTypeId::EPUB));
        assert!(!crate::matches_content_type(&epub, crate::ContentTypeId::ZIP));
    }

    #[test]
    fn trueos_blueprint_requires_a_complete_v1_container() {
        let mut blueprint = [0u8; 27];
        blueprint[..4].copy_from_slice(b"TRBP");
        blueprint[4..6].copy_from_slice(&(1u16).to_le_bytes());
        blueprint[16..20].copy_from_slice(&(3u32).to_le_bytes());
        blueprint[20..24].copy_from_slice(&(3u32).to_le_bytes());
        assert_eq!(
            crate::detect_content_type(&blueprint),
            Some(crate::ContentTypeId::TRUEOS_BLUEPRINT)
        );
        blueprint[16..20].copy_from_slice(&(4u32).to_le_bytes());
        assert_ne!(
            crate::detect_content_type(&blueprint),
            Some(crate::ContentTypeId::TRUEOS_BLUEPRINT)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn test_custom_matcher_ordering() {
        // overrides jpeg matcher
        fn foo_matcher(buf: &[u8]) -> bool {
            buf.len() > 2 && buf[0] == 0xFF && buf[1] == 0xD8 && buf[2] == 0xFF
        }

        // overrides png matcher
        fn bar_matcher(buf: &[u8]) -> bool {
            buf.len() > 3 && buf[0] == 0x89 && buf[1] == 0x50 && buf[2] == 0x4E && buf[3] == 0x47
        }

        let mut info = Infer::new();
        info.add("custom/foo", "foo", foo_matcher);
        info.add("custom/bar", "bar", bar_matcher);

        let buf_foo = &[0xFF, 0xD8, 0xFF];
        let typ = info.get(buf_foo).expect("type is matched");
        assert_eq!(typ.mime_type(), "custom/foo");
        assert_eq!(typ.extension(), "foo");
        assert_eq!(typ.content_type_id(), crate::ContentTypeId::NONE);

        let buf_bar = &[0x89, 0x50, 0x4E, 0x47];
        let typ = info.get(buf_bar).expect("type is matched");
        assert_eq!(typ.mime_type(), "custom/bar");
        assert_eq!(typ.extension(), "bar");
    }
}
