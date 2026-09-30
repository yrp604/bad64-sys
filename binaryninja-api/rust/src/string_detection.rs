//! Raw string detection using the same logic as the core strings analysis.

use binaryninjacore_sys::*;

use crate::binary_view::StringReference;
use crate::rc::Array;
use crate::settings::Settings;
use crate::string::IntoCStr;

/// Parameters controlling raw string detection, as used by the core strings analysis.
#[derive(Clone, Debug)]
pub struct StringDetectionParameters {
    pub min_string_length: usize,
    pub utf8_enabled: bool,
    pub utf16_enabled: bool,
    pub utf32_enabled: bool,
    /// Unicode block names as accepted by the `analysis.unicode.blocks` setting.
    pub unicode_block_names: Vec<String>,
}

impl StringDetectionParameters {
    /// Builds parameters from the standard string-analysis settings:
    /// `analysis.limits.minStringLength` and `analysis.unicode.{blocks,utf8,utf16,utf32}`.
    pub fn from_settings(settings: &Settings) -> Self {
        Self {
            min_string_length: settings.get_integer("analysis.limits.minStringLength") as usize,
            utf8_enabled: settings.get_bool("analysis.unicode.utf8"),
            utf16_enabled: settings.get_bool("analysis.unicode.utf16"),
            utf32_enabled: settings.get_bool("analysis.unicode.utf32"),
            unicode_block_names: settings
                .get_string_list("analysis.unicode.blocks")
                .iter()
                .map(|name| name.to_string())
                .collect(),
        }
    }
}

impl Default for StringDetectionParameters {
    fn default() -> Self {
        Self {
            min_string_length: 4,
            utf8_enabled: true,
            utf16_enabled: true,
            utf32_enabled: true,
            unicode_block_names: Vec::new(),
        }
    }
}

/// A compiled string detector using the same detection logic as the core strings analysis.
///
/// The detector is immutable once constructed, so a single instance may be shared across threads.
pub struct StringDetector {
    handle: *mut BNStringDetector,
}

impl StringDetector {
    pub fn new(params: &StringDetectionParameters) -> Self {
        let block_names: Vec<_> = params
            .unicode_block_names
            .iter()
            .map(|name| name.as_str().to_cstr())
            .collect();
        let block_name_ptrs: Vec<*const _> = block_names.iter().map(|name| name.as_ptr()).collect();
        let raw_params = BNStringDetectionParameters {
            minStringLength: params.min_string_length,
            utf8Enabled: params.utf8_enabled,
            utf16Enabled: params.utf16_enabled,
            utf32Enabled: params.utf32_enabled,
            unicodeBlockNames: block_name_ptrs.as_ptr(),
            unicodeBlockNameCount: block_name_ptrs.len(),
        };
        let handle = unsafe { BNCreateStringDetector(&raw_params) };
        Self { handle }
    }

    /// Detects strings in a raw data buffer.
    ///
    /// Strings must start within the first `block_len` bytes of `data` but may extend to the end
    /// of `data`, allowing large buffers to be scanned in chunks with a `BN_MAX_STRING_LENGTH`
    /// overlap tail. `last_found` (optional, in/out, zero-initialized before the first call)
    /// carries overlap state across consecutive chunk calls so strings spanning a chunk boundary
    /// are not reported twice. Result addresses are relative to `base_address`.
    pub fn detect_strings(
        &self,
        data: &[u8],
        block_len: usize,
        base_address: u64,
        last_found: Option<&mut StringReference>,
    ) -> Array<StringReference> {
        let mut count = 0;
        match last_found {
            Some(last) => {
                let mut raw_last: BNStringReference = (*last).into();
                let strings = unsafe {
                    BNStringDetectorDetectStrings(
                        self.handle,
                        data.as_ptr(),
                        data.len(),
                        block_len,
                        base_address,
                        &mut raw_last,
                        &mut count,
                    )
                };
                *last = raw_last.into();
                unsafe { Array::new(strings, count, ()) }
            }
            None => {
                let strings = unsafe {
                    BNStringDetectorDetectStrings(
                        self.handle,
                        data.as_ptr(),
                        data.len(),
                        block_len,
                        base_address,
                        std::ptr::null_mut(),
                        &mut count,
                    )
                };
                unsafe { Array::new(strings, count, ()) }
            }
        }
    }
}

impl Drop for StringDetector {
    fn drop(&mut self) {
        unsafe { BNFreeStringDetector(self.handle) };
    }
}

// SAFETY: A StringDetector is immutable once created. The core performs no internal mutation
// during BNStringDetectorDetectStrings.
unsafe impl Send for StringDetector {}
unsafe impl Sync for StringDetector {}
