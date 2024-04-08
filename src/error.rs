
use crate::*;

use rust_i18n::error::*;

#[derive(thiserror::Error, rust_i18n::AsDetails, strum::AsRefStr, Debug)]
pub enum MemoryError {
    #[error("process-not-attached")]
    ProcessNotAttached,

    #[error("process-already-attached")]
    ProcessAlreadyAttached,

    #[error("failed_to_write_process_memory")]
    FailedToWriteProcessMemory,

    #[error("failed_to_read_process_memory")]
    FailedtoReadProcessMemory,

    #[error("invalid-target-handle")]
    InvalidTargetHandle,
}