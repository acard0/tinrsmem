use core::panic;
// Alias types
// -------------------------------------------------------
use std::{collections::HashMap, ffi::{c_char, CStr}, marker::PhantomData, ops::{Deref, DerefMut, FromResidual}, sync::Arc};

use rust_i18n::{error::ErrorDetails, Backend};
use udbg::memory::MemoryPage;

use crate::helpers::like::CStringLike;

pub type ArcM<T> = Arc<parking_lot::Mutex<T>>;

pub type IEngine = dyn udbg::target::UDbgEngine;
pub type ITarget = dyn udbg::target::UDbgTarget;

pub type TargetHandle = usize;
pub type Targets = Vec<Arc<ITarget>>;

pub type EngineHandleArc = ArcM<IEngineHandle>;
pub type TargetsArcM = ArcM<Targets>;

// dyn UDbgEngine handle
// -------------------------------------------------------
pub struct IEngineHandle {
    ptr: Option<*mut IEngine>
}

unsafe impl Send for IEngineHandle {}
unsafe impl Sync for IEngineHandle {}

impl Deref for IEngineHandle {
    type Target = IEngine;

    fn deref(&self) -> &Self::Target {
        match self.ptr {
            Some(addr) => unsafe { &mut *(addr as *mut IEngine) }
            None => panic!("") // should never happen anyways
        }
    }
}

impl DerefMut for IEngineHandle {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self.ptr {
            Some(addr) => unsafe { &mut *(addr as *mut IEngine) }
            None => panic!("") // should never happen anyways
        }
    }
}

impl Default for IEngineHandle {
    fn default() -> Self {
        let engine = udbg::os::DefaultEngine::default();
        let leaked = Box::into_raw(Box::new(engine));

        IEngineHandle {
            ptr: Some(leaked),
        }
    }
}

impl Drop for IEngineHandle {
    fn drop(&mut self) {

        if self.ptr.is_some() {
            let _ = unsafe {
                Box::from_raw(self.ptr.unwrap())
            };
        }
    }
}

// Custom I18n backend
// ---------------------------------------------------------------
#[derive(Debug, Clone)]
pub struct I18n {
    inner: I18nHolder,
}

impl Deref for I18n {
    type Target = I18nHolder;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl I18n {
    pub fn new() -> Self {
        Self { inner: I18nHolder::new() }
    }

    pub fn get(&self, key: &str) -> String {
        self.translate(&rust_i18n::locale(), key)
            .unwrap_or(key.to_owned())
    }
}

impl rust_i18n::Backend for I18n {
    fn available_locales(&self) -> Vec<String> {
        self.trs.lock().keys().cloned().collect()
    }

    fn translate(&self, locale: &str, key: &str) -> Option<String> {
        self.trs.lock().get(locale)?.get(key).cloned()
    }

    fn add(&mut self, locale: &str, key: &str, value: &str) {
        let mut trs = self.trs.lock();
        let locale = trs.entry(locale.to_string())
            .or_insert_with(HashMap::new);

        locale.insert(key.to_string(), value.to_string());
    }
}

#[derive(Debug, Clone)]
pub struct I18nHolder {
    trs: Arc<parking_lot::Mutex<HashMap<String, HashMap<String, String>>>>,
}

impl I18nHolder {
    pub fn new() -> Self {
        Self { 
            trs: Arc::new(parking_lot::Mutex::new(HashMap::new()))
        }
    }
}

// C extern call result
// ---------------------------------------------------------------
#[repr(C)]
pub struct CallResult<T> {
    pub result: usize,
    pub error: *const c_char,
    _err: bool,
    _pht: PhantomData<T>
}

impl<T> CallResult<T> {
    pub fn new(result: Option<usize>, error: Option<&str>) -> Self {
        let err = match error {
            None => std::ptr::null(),
            Some(s) => s.as_c_char_ptr()
        };

        CallResult::<T> { 
            result: match result {
                Some(result) => result,
                None => 0,
            },
            error: err,
            _err: error.is_some(),
            _pht: PhantomData,
        }
    }

    pub fn empty() -> Self {
        CallResult::<T>::new(None, None)
    }
 
    pub fn into_raw(self) -> usize {
        Box::into_raw(Box::new(self)) as usize
    }

    pub fn is_err(&self) -> bool {
        self._err
    }
}

impl<T> CallResult<Vec<T>> {
    pub fn unwrap(self) -> Vec<T> {
        if self.is_err() {
            panic!("attempting to unwrap an error type");
        }

        let buffer = unsafe { Box::from_raw(self.result as *mut ByteBuffer) };
        unsafe { buffer.into_sized_vec() }
    }
}

impl<T> Into<CallResult<Vec<T>>> for Vec<T> {
    fn into(self) -> CallResult<Vec<T>> {
        let buffer = unsafe { ByteBuffer::from_sized_vec(self) };
        let buffer_ptr = Box::into_raw(Box::new(buffer));
        CallResult::new(Some(buffer_ptr as usize), None)
    }
}

impl<T> From<ErrorDetails> for CallResult<T> {
    fn from(value: ErrorDetails) -> Self {
        CallResult::<T>::new(None, Some(&value.message))
    }
}

impl<T> From<rust_i18n::error::Error> for CallResult<T> {
    fn from(value: rust_i18n::error::Error) -> Self {
        CallResult::from(value.get_details().clone())
    }
}

impl<T> FromResidual<Result<T, rust_i18n::error::Error>> for CallResult<T> {
    fn from_residual(residual: Result<T, rust_i18n::error::Error>) -> Self {
        match residual {
            Err(error) => CallResult::<T>::from(error),
            Ok(next) => CallResult::new(Some(Box::into_raw(Box::new(next)) as usize), None)
        }
    }
}

// C extern ByteBuffer
// ---------------------------------------------------------------
#[repr(C)]
pub struct ByteBuffer {
    ptr: *mut u8,
    count: usize,
    capacity: usize,
    size: usize
}

impl ByteBuffer {
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
            .try_into()
            .expect("invalid pointer")
    }

    pub fn cap(&self) -> usize {
        self.capacity
            .try_into()
            .expect("buffer cap negative or overflowed")
    }

    pub fn len(&self) -> usize {
        self.count
            .try_into()
            .expect("buffer length negative or overflowed")
    }

    pub unsafe fn from_slice(bytes: &[u8]) -> Self {
        Self::from_vec(bytes.to_vec())
    }

    pub unsafe fn from_vec(bytes: Vec<u8>) -> Self {
        let mut v = std::mem::ManuallyDrop::new(bytes);
        let elem_size = std::mem::size_of::<u8>();

        Self {
            ptr: v.as_mut_ptr(),
            count: v.len(),
            capacity: v.capacity(),
            size: elem_size * v.len(),
        }
    }

    pub unsafe fn from_sized_vec<T: Sized>(vec: Vec<T>) -> Self {
        let mut v = std::mem::ManuallyDrop::new(vec);
        let bytes = std::mem::size_of::<T>();

        Self {
            ptr: v.as_mut_ptr() as *mut u8,
            count: v.len(),
            capacity: v.capacity(),
            size: bytes * v.len()
        }
    }

    pub unsafe fn into_string(self) -> String {
        unsafe { CStr::from_ptr(self.ptr as *const i8).to_str().unwrap().to_string() }
    }

    pub unsafe fn into_sized_slice<T: Sized>(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.ptr() as *mut T, self.len()) }
    }

    pub unsafe fn into_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr(), self.len()) }
    }

    pub unsafe fn into_string_vec(&self) -> Vec<String> {
        self.into_sized_slice::<*mut c_char>()
            .iter().map(|f| unsafe { CStr::from_ptr(*f).to_str().unwrap().to_string() })
            .collect::<Vec<_>>()
    }

    pub unsafe fn into_vec(self) -> Vec<u8> {
        if self.ptr.is_null() {
            vec![]
        } else {
            let capacity: usize = self
                .capacity
                .try_into()
                .expect("buffer capacity negative or overflowed");
            let length: usize = self
                .count
                .try_into()
                .expect("buffer length negative or overflowed");

            unsafe { Vec::from_raw_parts(self.ptr, length, capacity) }
        }
    }

    pub unsafe fn into_sized_vec<T: Sized>(self) -> Vec<T> {
        if self.ptr.is_null() {
            vec![]
        } else {

            unsafe { Vec::from_raw_parts(self.ptr as *mut T, self.count, self.capacity) }
        }
    }

    pub unsafe fn into_raw(self) -> *mut ByteBuffer {
        Box::into_raw(Box::new(self))
    }
}

// Memory page
// ----------------------------------------------------
#[repr(C)]
pub struct CMemoryPageInfo {
    pub base: usize,
    pub size: usize,
    pub flags: u32,
    pub mem_type: *const i8,
    pub mem_protect: *const i8,
    pub mem_usage: *const i8,
    pub alloc_base: usize,
}

impl From<&MemoryPage> for CMemoryPageInfo {
    fn from(value: &MemoryPage) -> Self {
        let usage = match value.info.as_ref() {
            Some(usg) => usg.as_c_char_ptr(),
            None => unsafe { std::mem::zeroed() }
        };

        CMemoryPageInfo {
            base: value.base,
            size: value.size,
            flags: value.flags.bits(),
            mem_type: value.type_().as_c_char_ptr(),
            mem_protect: value.protect().as_ref().as_c_char_ptr(),
            mem_usage: usage,
            alloc_base: value.alloc_base
        }
    }
}