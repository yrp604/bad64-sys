use binaryninjacore_sys::BNLlvmServicesDisasmInstruction;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

pub fn disas_instruction(triplet: &str, data: &[u8], address64: u64) -> Option<(usize, String)> {
    unsafe {
        let triplet = CString::new(triplet).ok()?;
        let mut src = data.to_vec();
        let mut buf = vec![0u8; 256];
        let instr_len = BNLlvmServicesDisasmInstruction(
            triplet.as_ptr(),
            src.as_mut_ptr(),
            src.len() as c_int,
            address64,
            buf.as_mut_ptr() as *mut c_char,
            buf.len(),
        );

        if instr_len > 0 {
            // Convert buf (u8) → &CStr by finding the first NUL
            if let Some(z) = buf.iter().position(|&b| b == 0) {
                let s = CStr::from_bytes_with_nul(&buf[..=z])
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                Some((instr_len as usize, s))
            } else {
                // Callee didn't NULL terminate, return an empty string
                Some((instr_len as usize, String::new()))
            }
        } else {
            None
        }
    }
}
