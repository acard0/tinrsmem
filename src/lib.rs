#![allow(dead_code, unused_variables)]
#![feature(try_trait_v2)]

use std::{sync::atomic::{AtomicBool, Ordering}, time::Instant};

use definitions::{ByteBuffer, CallResult, I18n, ITarget, TargetHandle};
use error::MemoryError;
use log::{info, warn, LevelFilter};
use once_cell::sync::Lazy;
use lazy_static::lazy_static;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rust_i18n::error::AsDetails;
use udbg::{memory::{MemoryPage, ReadMemoryUtils}, pe::*, target::{TargetUtil, UDbgTarget}};

use crate::definitions::{CMemoryPageInfo, EngineHandleArc, TargetsArcM};

pub use convert_case::*;
pub use rust_i18n::{t, t_add};

mod definitions;
mod helpers;
mod error;

rust_i18n::i18n!("locales", backend = I18n::new());

lazy_static! {
    static ref ENGINE: Lazy<EngineHandleArc> = Lazy::new(|| EngineHandleArc::default());
}

lazy_static! {
    static ref TARGETS: Lazy<TargetsArcM> = Lazy::new(|| TargetsArcM::new(Vec::new().into()));
}

#[no_mangle] 
pub extern "C" fn attach(pid: u32) -> CallResult<usize> {
    let mut collection = TARGETS.lock();
    
    match collection.iter().filter(|n| n.pid() == pid).next() {
        Some(_) => {    
            warn!("failed to attach the process with id {:?}. already attached.", pid);
            CallResult::from(MemoryError::ProcessAlreadyAttached.as_details())
        },
        None => {
            let mut engine = ENGINE.lock();
            let target = engine.open(pid).unwrap();  
            collection.push(target);

            let target_handle = collection.len() - 1;

            info!("attached the process with id {:?}, handle: {:?}", pid, target_handle);
            CallResult::new(Some(target_handle), None)
        } 
    }
}

#[no_mangle] 
pub extern "C" fn detach(pid: u32) -> CallResult<bool> {
    let mut collection = TARGETS.lock();
    let found = AtomicBool::new(false);

    collection.retain(|n| {
        if n.pid() == pid {
            _ = n.detach();
            found.store(true, Ordering::Relaxed);
            return false;
        }
        
        true
    });

    match found.load(Ordering::Relaxed) {
        false => {
            warn!("failed to detach the process #{:?}. not attached.", pid);
            CallResult::from(MemoryError::ProcessNotAttached.as_details())
        },
        true => {
            info!("detached the process #{:?}.", pid);
            CallResult::new(Some(1), None)
        }
    }
}

#[no_mangle] 
pub unsafe extern "C" fn aob_query(target_handle: TargetHandle, pattern_buffer: ByteBuffer, mapped: bool, readable: bool, writable: bool, executable: bool) -> CallResult<Vec<usize>> {
    let target_opt = validate_target_handle(target_handle);
    if target_opt.is_err() {
        return CallResult::from(target_opt.err().unwrap());
    }
    
    let target = target_opt.unwrap();
    let pattern = pattern_buffer.into_string();
    let pages = filter_pages(&target, mapped, readable, writable, executable);
    let pattern = parse_pattern(&pattern);

    info!("searching for pattern: {:?}", pattern);
    let start_time = Instant::now();

    let addresses: Vec<usize> = pages
        .par_iter()
        .flat_map_iter(|page| {
            let buff = target.read_bytes(page.base, page.size);
            find_all_occurrences(&buff, &pattern)
                .into_iter()
                .map(move |addr| page.base + addr)
        })
        .collect();

    let end_time = Instant::now();
    let duration = end_time - start_time;
    info!("search is completed. found {:?} occurrences in total. took {:?}", addresses.len(), duration);

    addresses.into()
}

#[no_mangle] 
pub unsafe extern "C" fn collect_pages(target: TargetHandle) -> CallResult<Vec<CMemoryPageInfo>> {
    match  validate_target_handle(target) {
        Ok(target) => {
            let pages = target.collect_memory_info()
                .iter()
                .map(|page| CMemoryPageInfo::from(page))
                .collect::<Vec<CMemoryPageInfo>>();

            pages.into()
        },
        Err(err) => {
            err.into()
        }
    }
}

#[no_mangle] 
pub unsafe extern "C" fn write_memory(target: TargetHandle, address: usize, buffer_repr: ByteBuffer) -> CallResult<usize> {
    match  validate_target_handle(target) {
        Ok(target) => {
            let buffer = buffer_repr.into_slice();
            let written = target.write_memory(address, buffer)
                .and_then(|bytes| {
                    if bytes == 0 {
                        return None;
                    }

                    Some(bytes)
                });

            CallResult::new(written, None)
        },
        Err(err) => {
            err.into()
        }
    }  
}

#[no_mangle] 
pub unsafe extern "C" fn write_bytes(target: TargetHandle, address: usize, buffer_repr: ByteBuffer) -> usize {
    match  validate_target_handle(target) {
        Ok(target) => {
            let buffer = buffer_repr.into_slice();
            let written = target.write_memory(address, buffer).unwrap_or_default();
            written
        },
        Err(err) => {
            0
        }
    }  
}

#[no_mangle] 
pub unsafe 
extern "C" fn read_bytes(target: TargetHandle, address: usize, size: usize) -> CallResult<Vec<u8>> {
    match validate_target_handle(target) {
        Ok(target) => {           
            let mut buffer: Vec<u8> = vec![0u8; size];
            let len = match target.read_memory(address, &mut buffer) {
                Some(slice) => slice.len(),
                None => 0,
            };
            buffer.resize(len, 0);

            CallResult::new(Some(ByteBuffer::from_vec(buffer).into_raw() as usize), None)
        },
        Err(err) => {
            err.into()
        }
    } 
}

#[no_mangle] 
pub unsafe 
extern "C" fn read_memory<'a>(target: TargetHandle, address: usize, destination: *mut u8, size: usize) -> usize {
    match validate_target_handle(target) {
        Ok(target) => {           
            let buffer = target.read_bytes(address, size);
            std::ptr::copy_nonoverlapping(buffer.as_ptr(), destination, size);
            buffer.len()
        },
        Err(err) => {
            0
        }
    } 
}

fn filter_pages(target: &Arc<dyn UDbgTarget>, mapped: bool, readable: bool, writable: bool, executable: bool) -> Vec<MemoryPage> {
    let pages = target.collect_memory_info();
    let collected = pages
        .iter()
        .filter(|page| {
            let is_valid = page.state == MEM_COMMIT
            && page.base < 140737488355327usize // todo use address space, eg: sysinfo in win32
            && (page.protect & PAGE_GUARD) == 0
            && (page.protect & PAGE_NOACCESS) == 0
            && (page.type_ == MEM_PRIVATE || page.type_ == MEM_IMAGE)
            && (!mapped || page.type_ == MEM_MAPPED);
    
            if !is_valid {
                return false
            }

            let is_readable = (page.protect & PAGE_READONLY) > 0;
        
            let is_writable = (page.protect & PAGE_READWRITE) > 0
                || (page.protect & PAGE_WRITECOPY) > 0
                || (page.protect & PAGE_EXECUTE_READWRITE) > 0
                || (page.protect & PAGE_EXECUTE_WRITECOPY) > 0;
    
            let is_executable = (page.protect & PAGE_EXECUTE) > 0
                || (page.protect & PAGE_EXECUTE_READ) > 0
                || (page.protect & PAGE_EXECUTE_READWRITE) > 0
                || (page.protect & PAGE_EXECUTE_WRITECOPY) > 0;
        
            is_valid && (is_readable && readable || is_writable && writable || is_executable && executable)
        })
        .cloned()
        .collect::<Vec<_>>();

    collected
}

#[no_mangle] 
pub extern "C" fn set_log_level(level: usize) {
    log::set_max_level(match level {
        0 => Some(LevelFilter::Off),
        1 => Some(LevelFilter::Error),
        2 => Some(LevelFilter::Warn),
        3 => Some(LevelFilter::Info),
        4 => Some(LevelFilter::Debug),
        5 => Some(LevelFilter::Trace),
        _ => None,
    }.unwrap_or(LevelFilter::Off));
}

#[no_mangle] 
pub extern "C" fn log_to_file(level: usize) {
    _ = simple_logging::log_to_file("rsmem.log", LevelFilter::Trace);
    set_log_level(level);

    info!("log level has been set to level #{:?}", level)
}

fn parse_pattern(pattern_str: &str) -> Vec<Vec<u8>> {
    pattern_str
        .split_whitespace()
        .map(|s| {
            if s == "??" {
                Vec::new()
            } else {
                let byte = u8::from_str_radix(&s, 16)
                    .expect("could not parse byte pattern");
                vec![byte]
            }
        })
        .collect()
}

fn compare_func(window: &[u8], pattern: &[Vec<u8>]) -> bool {
    window.iter().zip(pattern.iter()).all(|(byte, pat)| {
        if pat.is_empty() {
            true
        } else {
            pat.contains(byte)
        }
    })
}

fn find_all_occurrences(buff: &[u8], pattern: &[Vec<u8>]) -> Vec<usize> {
    let mut occurrences = Vec::new();
    let mut start = 0;

    while start + pattern.len() <= buff.len() {
        if let Some(index) = buff[start..]
            .windows(pattern.len())
            .position(|window| compare_func(window, pattern))
        {
            occurrences.push(start + index);
            start += index + 1;
        } else {
            break;
        }
    }

    occurrences
}

fn validate_target_handle(target_handle: TargetHandle) -> Result<Arc<ITarget>, rust_i18n::error::Error> {
    match TARGETS.lock().get(target_handle) {
        None => {
            warn!("invalid target handle supplied: ({:?})", target_handle);
            Result::Err(MemoryError::InvalidTargetHandle.into())
        }
        Some(target) => {
            Result::Ok(target.clone())
        }
    }
}