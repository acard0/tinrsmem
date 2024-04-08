use std::sync::Arc;


pub trait CStringLike {
    fn as_c_char_mut_ptr(&self) -> *mut std::ffi::c_char; 
    fn as_c_char_ptr(&self) -> *const std::ffi::c_char; 
    
    fn as_ptr_nul(&self) -> *const u8;
    fn as_mut_ptr_nul(&self) -> *mut u8;
}

impl CStringLike for String {
    fn as_c_char_mut_ptr(&self) -> *mut std::ffi::c_char {
        c_str(self)
    }

    fn as_c_char_ptr(&self) -> *const std::ffi::c_char {
        c_str(self)    
    }

    fn as_mut_ptr_nul(&self) -> *mut u8 {
        self.as_c_char_mut_ptr() as *mut u8
    }

    fn as_ptr_nul(&self) -> *const u8 {
        self.as_c_char_mut_ptr() as *const u8
    }
}

impl CStringLike for &str {
    fn as_c_char_mut_ptr(&self) -> *mut std::ffi::c_char {
        c_str(self)
    }

    fn as_c_char_ptr(&self) -> *const std::ffi::c_char {
        c_str(self)
    }

    fn as_mut_ptr_nul(&self) -> *mut u8 {
        self.as_c_char_mut_ptr() as *mut u8
    }

    fn as_ptr_nul(&self) -> *const u8 {
        self.as_c_char_mut_ptr() as *const u8
    }
}

impl CStringLike for Box<str> {
    fn as_c_char_mut_ptr(&self) -> *mut std::ffi::c_char {
        c_str(self)
    }

    fn as_c_char_ptr(&self) -> *const std::ffi::c_char {
        c_str(self)
    }

    fn as_ptr_nul(&self) -> *const u8 {
        self.as_c_char_mut_ptr() as *const u8
    }

    fn as_mut_ptr_nul(&self) -> *mut u8 {
        self.as_c_char_mut_ptr() as *mut u8
    }
}

impl CStringLike for Arc<str> {
    fn as_c_char_mut_ptr(&self) -> *mut std::ffi::c_char {
        c_str(self)
    }

    fn as_c_char_ptr(&self) -> *const std::ffi::c_char {
        c_str(self)
    }

    fn as_ptr_nul(&self) -> *const u8 {
        self.as_c_char_mut_ptr() as *const u8
    }

    fn as_mut_ptr_nul(&self) -> *mut u8 {
        self.as_c_char_mut_ptr() as *mut u8
    }
}

fn c_str(str: &str) -> *mut std::ffi::c_char {
    std::ffi::CString::new(str).unwrap().into_raw()
}