use std::ffi::CString;
use winapi::um::debugapi::OutputDebugStringA;

pub fn debug_log(message: &str) {
    if let Ok(c_message) = CString::new(message) {
      println!("{}", message);
        unsafe {
            OutputDebugStringA(c_message.as_ptr());
        }
    }
}