//! Kernel status and typed error mapping.
//!
//! The kernel keeps a richer internal error enum while exposing the stable
//! status values specified for the kernel/user ABI.

/// Stable status values returned across the kernel ABI boundary.
///
/// These discriminants match the draft ABI status table and are intentionally
/// represented as `u32` for FFI and syscall result stability.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// The caller provided malformed or out-of-range input.
    InvalidArgument = 1,
    /// The caller lacks authority for the requested operation.
    PermissionDenied = 2,
    /// The requested object does not exist.
    NotFound = 3,
    /// The subsystem is temporarily unable to make progress.
    Busy = 4,
    /// A declared deadline or budget was exceeded.
    DeadlineExceeded = 5,
    /// A kernel invariant failed or an internal subsystem fault occurred.
    Internal = 0xffff_ffff,
}

impl KernelStatus {
    /// Returns `true` when the status represents success.
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// Internal kernel error taxonomy.
///
/// Public APIs return this enum inside Rust so tests and host-mode callers can
/// distinguish validation, authority, capacity, and invariant failures without
/// relying on ad hoc strings. Convert to [`KernelStatus`] at syscall boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelError {
    /// A syscall number or operation code is not known to the current table.
    UnknownSyscall,
    /// A general argument validation check failed.
    InvalidArgument,
    /// User memory pointer, length, direction, or alignment validation failed.
    InvalidUserBuffer,
    /// A buffer length exceeded the configured kernel copy/pin limit.
    BufferTooLarge,
    /// A pointer range crossed outside the current user address range.
    BufferOutOfRange,
    /// Reserved bits were set in an ABI flags field.
    ReservedBits,
    /// The caller did not hold the required capability.
    MissingCapability,
    /// Access was denied by policy.
    PermissionDenied,
    /// The requested object was not found.
    NotFound,
    /// A bounded registry or table has no free slots.
    CapacityExceeded,
    /// A subsystem is temporarily busy.
    Busy,
    /// A declared deadline or budget was exceeded.
    DeadlineExceeded,
    /// A state transition was invalid for the target object.
    InvalidState,
    /// A range overlapped a protected or already-registered range.
    Overlap,
    /// A sealed object was modified.
    Sealed,
    /// A duplicate identifier was supplied to a registry.
    Duplicate,
    /// An internal invariant failed.
    Internal,
}

impl KernelError {
    /// Maps the internal error to the stable syscall status code.
    pub const fn status(self) -> KernelStatus {
        match self {
            Self::UnknownSyscall
            | Self::InvalidArgument
            | Self::InvalidUserBuffer
            | Self::BufferTooLarge
            | Self::BufferOutOfRange
            | Self::ReservedBits
            | Self::InvalidState
            | Self::Overlap
            | Self::Sealed
            | Self::Duplicate => KernelStatus::InvalidArgument,
            Self::MissingCapability | Self::PermissionDenied => KernelStatus::PermissionDenied,
            Self::NotFound => KernelStatus::NotFound,
            Self::CapacityExceeded | Self::Busy => KernelStatus::Busy,
            Self::DeadlineExceeded => KernelStatus::DeadlineExceeded,
            Self::Internal => KernelStatus::Internal,
        }
    }

    /// Short stable reason label for audit and diagnostic events.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::UnknownSyscall => "unknown_syscall",
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidUserBuffer => "invalid_user_buffer",
            Self::BufferTooLarge => "buffer_too_large",
            Self::BufferOutOfRange => "buffer_out_of_range",
            Self::ReservedBits => "reserved_bits",
            Self::MissingCapability => "missing_capability",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::Busy => "busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::InvalidState => "invalid_state",
            Self::Overlap => "overlap",
            Self::Sealed => "sealed",
            Self::Duplicate => "duplicate",
            Self::Internal => "internal",
        }
    }
}

impl From<KernelError> for KernelStatus {
    fn from(error: KernelError) -> Self {
        error.status()
    }
}

/// Result alias used by kernel subsystem APIs.
pub type KernelResult<T> = Result<T, KernelError>;
