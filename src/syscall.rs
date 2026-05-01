//! Versioned syscall table and ABI-safe syscall data structures.
//!
//! The dispatcher layer is intentionally table-driven: validation of syscall
//! number, execution context, and required capability happens before subsystem
//! handlers are reached.

use crate::audit::AuditEventKind;
use crate::capability::{Capability, CapabilitySet, TaskId};
use crate::error::{KernelError, KernelResult, KernelStatus};

/// Draft ABI version exposed by `sys_info`.
pub const ALANI_ABI_VERSION: AbiVersion = AbiVersion {
    major: 0,
    minor: 1,
    patch: 0,
    flags: 0,
};

/// Version of the syscall descriptor table itself.
pub const SYSCALL_TABLE_VERSION: AbiVersion = AbiVersion {
    major: 0,
    minor: 1,
    patch: 0,
    flags: 0,
};

/// Maximum userspace buffer length accepted by default host-mode syscalls.
pub const DEFAULT_MAX_SYSCALL_BUFFER_SIZE: u64 = 16 * 1024 * 1024;

/// Buffer must be readable by the kernel.
pub const USER_BUFFER_READ: u32 = 1 << 0;

/// Buffer must be writable by the kernel.
pub const USER_BUFFER_WRITE: u32 = 1 << 1;

/// Buffer may be pinned instead of copied by a future implementation.
pub const USER_BUFFER_PINNABLE: u32 = 1 << 2;

/// All known [`UserBuffer`] flag bits.
pub const USER_BUFFER_KNOWN_FLAGS: u32 =
    USER_BUFFER_READ | USER_BUFFER_WRITE | USER_BUFFER_PINNABLE;

/// ABI version structure used by kernel/user feature negotiation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiVersion {
    /// Major ABI version. Incompatible changes require a bump.
    pub major: u16,
    /// Minor ABI version. Backward-compatible additions require a bump.
    pub minor: u16,
    /// Patch ABI version.
    pub patch: u16,
    /// Reserved feature flags. Unknown bits must be ignored by readers.
    pub flags: u16,
}

impl AbiVersion {
    /// Encodes the version into a compact integer for register returns.
    pub const fn packed(self) -> u64 {
        ((self.major as u64) << 48)
            | ((self.minor as u64) << 32)
            | ((self.patch as u64) << 16)
            | self.flags as u64
    }
}

/// User buffer descriptor passed through syscall register arguments.
///
/// The pointer is represented as an integer because raw pointers and Rust
/// references are not stable ABI fields.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserBuffer {
    /// Userspace virtual address.
    pub ptr: u64,
    /// Buffer length in bytes.
    pub len: u64,
    /// Direction and pinning flags.
    pub flags: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl UserBuffer {
    /// Creates a buffer descriptor with `reserved` set to zero.
    pub const fn new(ptr: u64, len: u64, flags: u32) -> Self {
        Self {
            ptr,
            len,
            flags,
            reserved: 0,
        }
    }

    /// Returns `true` when the descriptor contains reserved flag bits.
    pub const fn has_unknown_flags(self) -> bool {
        self.flags & !USER_BUFFER_KNOWN_FLAGS != 0
    }

    /// Returns `true` when the descriptor declares kernel-read access.
    pub const fn is_readable(self) -> bool {
        self.flags & USER_BUFFER_READ != 0
    }

    /// Returns `true` when the descriptor declares kernel-write access.
    pub const fn is_writable(self) -> bool {
        self.flags & USER_BUFFER_WRITE != 0
    }
}

/// Cross-component trace context propagated through syscall frames.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Stable trace identifier.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
    /// Parent span identifier, or zero when absent.
    pub parent_span_id: u64,
    /// Reserved trace flags.
    pub flags: u32,
    /// Reserved padding for ABI evolution.
    pub reserved: u32,
}

impl TraceContext {
    /// Returns an empty context for callers without tracing.
    pub const fn empty() -> Self {
        Self {
            trace_id: 0,
            span_id: 0,
            parent_span_id: 0,
            flags: 0,
            reserved: 0,
        }
    }
}

/// Budget descriptor carried by cognitive syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferenceBudget {
    /// Maximum output tokens allowed by policy.
    pub max_tokens: u32,
    /// Maximum compute units allowed by policy.
    pub max_compute_units: u32,
    /// Absolute deadline in monotonic nanoseconds, or zero when unset.
    pub deadline_ns: u64,
    /// Reserved flags for future schedulers.
    pub flags: u32,
    /// Reserved padding for ABI evolution.
    pub reserved: u32,
}

impl InferenceBudget {
    /// Returns `true` when this budget declares a bounded workload.
    pub const fn is_bounded(self) -> bool {
        self.max_tokens != 0 || self.max_compute_units != 0 || self.deadline_ns != 0
    }
}

/// Syscall groups defined by the syscall interface document.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallGroup {
    /// System and versioning calls.
    System = 0x0000,
    /// Task lifecycle calls.
    Task = 0x0100,
    /// Memory mapping and sharing calls.
    Memory = 0x0200,
    /// Device mediation calls.
    Device = 0x0300,
    /// Cognitive model and memory calls.
    Cognition = 0x0400,
    /// Security and capability calls.
    Security = 0x0500,
    /// Audit calls.
    Audit = 0x0600,
    /// Debug and tracing calls.
    Debug = 0x0700,
}

/// Stable syscall numbers for the MVK and near-term expansion table.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallNumber {
    /// Query ABI version, table version, and buffer limits.
    SysInfo = 0x0000,
    /// Cooperatively yield the current task.
    SysYield = 0x0001,
    /// Exit the current task.
    SysExit = 0x0002,
    /// Query monotonic time.
    SysTime = 0x0003,
    /// Create or update the current trace context.
    SysTraceContext = 0x0004,
    /// Spawn a task from a manifest buffer.
    SysTaskSpawn = 0x0100,
    /// Join a task.
    SysTaskJoin = 0x0101,
    /// Cancel a task.
    SysTaskCancel = 0x0102,
    /// Query task status.
    SysTaskStatus = 0x0103,
    /// Map a userspace memory range.
    SysMemMap = 0x0200,
    /// Unmap a userspace memory range.
    SysMemUnmap = 0x0201,
    /// Query memory statistics or a mapping.
    SysMemQuery = 0x0202,
    /// Share a userspace range.
    SysMemShare = 0x0203,
    /// Seal a shared memory handle.
    SysMemSeal = 0x0204,
    /// List devices.
    SysDeviceList = 0x0300,
    /// Open a device.
    SysDeviceOpen = 0x0301,
    /// Call a device operation.
    SysDeviceCall = 0x0302,
    /// Close a device.
    SysDeviceClose = 0x0303,
    /// List cognitive models.
    SysModelList = 0x0400,
    /// Open a cognitive model handle.
    SysModelOpen = 0x0401,
    /// Invoke deterministic model-device mediation.
    SysInfer = 0x0402,
    /// Query cognitive memory.
    SysMemoryQuery = 0x0403,
    /// Put a cognitive memory record.
    SysMemoryPut = 0x0404,
    /// Derive a child capability.
    SysCapDerive = 0x0500,
    /// Revoke a capability.
    SysCapRevoke = 0x0501,
    /// Query attestation material.
    SysAttest = 0x0502,
    /// Request kernel-mediated random bytes.
    SysRandom = 0x0503,
    /// Append an audit record.
    SysAuditAppend = 0x0600,
    /// Query audit records.
    SysAuditQuery = 0x0601,
    /// Verify audit chain ranges.
    SysAuditVerify = 0x0602,
}

impl SyscallNumber {
    /// Converts a raw register value into a known syscall number.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0x0000 => Some(Self::SysInfo),
            0x0001 => Some(Self::SysYield),
            0x0002 => Some(Self::SysExit),
            0x0003 => Some(Self::SysTime),
            0x0004 => Some(Self::SysTraceContext),
            0x0100 => Some(Self::SysTaskSpawn),
            0x0101 => Some(Self::SysTaskJoin),
            0x0102 => Some(Self::SysTaskCancel),
            0x0103 => Some(Self::SysTaskStatus),
            0x0200 => Some(Self::SysMemMap),
            0x0201 => Some(Self::SysMemUnmap),
            0x0202 => Some(Self::SysMemQuery),
            0x0203 => Some(Self::SysMemShare),
            0x0204 => Some(Self::SysMemSeal),
            0x0300 => Some(Self::SysDeviceList),
            0x0301 => Some(Self::SysDeviceOpen),
            0x0302 => Some(Self::SysDeviceCall),
            0x0303 => Some(Self::SysDeviceClose),
            0x0400 => Some(Self::SysModelList),
            0x0401 => Some(Self::SysModelOpen),
            0x0402 => Some(Self::SysInfer),
            0x0403 => Some(Self::SysMemoryQuery),
            0x0404 => Some(Self::SysMemoryPut),
            0x0500 => Some(Self::SysCapDerive),
            0x0501 => Some(Self::SysCapRevoke),
            0x0502 => Some(Self::SysAttest),
            0x0503 => Some(Self::SysRandom),
            0x0600 => Some(Self::SysAuditAppend),
            0x0601 => Some(Self::SysAuditQuery),
            0x0602 => Some(Self::SysAuditVerify),
            _ => None,
        }
    }

    /// Returns the stable syscall name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SysInfo => "sys_info",
            Self::SysYield => "sys_yield",
            Self::SysExit => "sys_exit",
            Self::SysTime => "sys_time",
            Self::SysTraceContext => "sys_trace_context",
            Self::SysTaskSpawn => "sys_task_spawn",
            Self::SysTaskJoin => "sys_task_join",
            Self::SysTaskCancel => "sys_task_cancel",
            Self::SysTaskStatus => "sys_task_status",
            Self::SysMemMap => "sys_mem_map",
            Self::SysMemUnmap => "sys_mem_unmap",
            Self::SysMemQuery => "sys_mem_query",
            Self::SysMemShare => "sys_mem_share",
            Self::SysMemSeal => "sys_mem_seal",
            Self::SysDeviceList => "sys_device_list",
            Self::SysDeviceOpen => "sys_device_open",
            Self::SysDeviceCall => "sys_device_call",
            Self::SysDeviceClose => "sys_device_close",
            Self::SysModelList => "sys_model_list",
            Self::SysModelOpen => "sys_model_open",
            Self::SysInfer => "sys_infer",
            Self::SysMemoryQuery => "sys_memory_query",
            Self::SysMemoryPut => "sys_memory_put",
            Self::SysCapDerive => "sys_cap_derive",
            Self::SysCapRevoke => "sys_cap_revoke",
            Self::SysAttest => "sys_attest",
            Self::SysRandom => "sys_random",
            Self::SysAuditAppend => "sys_audit_append",
            Self::SysAuditQuery => "sys_audit_query",
            Self::SysAuditVerify => "sys_audit_verify",
        }
    }

    /// Returns the high-level group for this syscall.
    pub const fn group(self) -> SyscallGroup {
        match (self as u32) & 0xff00 {
            0x0100 => SyscallGroup::Task,
            0x0200 => SyscallGroup::Memory,
            0x0300 => SyscallGroup::Device,
            0x0400 => SyscallGroup::Cognition,
            0x0500 => SyscallGroup::Security,
            0x0600 => SyscallGroup::Audit,
            0x0700 => SyscallGroup::Debug,
            _ => SyscallGroup::System,
        }
    }
}

/// Calling context used to reject unsafe early-boot or interrupt-time calls.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionContext {
    /// The kernel is still in deterministic initialization.
    EarlyBoot,
    /// A normal task context is active.
    Task,
    /// Interrupt top-half context is active.
    Interrupt,
}

/// Syscall arguments captured from the architecture calling convention.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallFrame {
    /// Syscall number. On x86_64 this corresponds to `rax`.
    pub number: u64,
    /// Up to six integer arguments. On x86_64 these map to `rdi`, `rsi`,
    /// `rdx`, `r10`, `r8`, and `r9` by the syscall ABI.
    pub args: [u64; 6],
    /// Trace context associated with this call.
    pub trace: TraceContext,
}

impl SyscallFrame {
    /// Creates a frame with no trace context.
    pub const fn new(number: SyscallNumber, args: [u64; 6]) -> Self {
        Self {
            number: number as u64,
            args,
            trace: TraceContext::empty(),
        }
    }

    /// Creates a frame from a raw syscall number.
    pub const fn raw(number: u64, args: [u64; 6]) -> Self {
        Self {
            number,
            args,
            trace: TraceContext::empty(),
        }
    }
}

/// Caller metadata used by the dispatcher before touching subsystem state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchContext {
    /// Task responsible for the call.
    pub task_id: TaskId,
    /// Capabilities already resolved for the task or syscall handle.
    pub capabilities: CapabilitySet,
    /// Current execution context.
    pub execution: ExecutionContext,
}

impl DispatchContext {
    /// Creates a task-context dispatch record.
    pub const fn task(task_id: TaskId, capabilities: CapabilitySet) -> Self {
        Self {
            task_id,
            capabilities,
            execution: ExecutionContext::Task,
        }
    }
}

/// Result register payload returned by the kernel dispatcher.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallResult {
    /// Stable ABI status.
    pub status: KernelStatus,
    /// Primary integer value or handle.
    pub value: u64,
    /// Secondary count, commonly bytes written.
    pub detail: u64,
}

impl SyscallResult {
    /// Successful syscall result with a primary value and detail count.
    pub const fn ok(value: u64, detail: u64) -> Self {
        Self {
            status: KernelStatus::Ok,
            value,
            detail,
        }
    }

    /// Error syscall result converted from a typed kernel error.
    pub const fn error(error: KernelError) -> Self {
        Self {
            status: error.status(),
            value: 0,
            detail: 0,
        }
    }
}

/// Static descriptor for one syscall table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallDescriptor {
    /// Stable syscall number.
    pub number: SyscallNumber,
    /// Stable syscall name.
    pub name: &'static str,
    /// Required capability, if any.
    pub required_capability: Option<Capability>,
    /// Audit event emitted for successful or failed authority-sensitive calls.
    pub audit_event: Option<AuditEventKind>,
    /// Whether the syscall may run during early boot.
    pub early_boot_safe: bool,
    /// Whether the syscall may run from interrupt context.
    pub interrupt_safe: bool,
}

impl SyscallDescriptor {
    /// Returns `true` when `context` is allowed to invoke the descriptor.
    pub const fn allows_context(self, context: ExecutionContext) -> bool {
        match context {
            ExecutionContext::EarlyBoot => self.early_boot_safe,
            ExecutionContext::Interrupt => self.interrupt_safe,
            ExecutionContext::Task => true,
        }
    }
}

/// Static syscall descriptor table.
pub const SYSCALL_DESCRIPTORS: &[SyscallDescriptor] = &[
    SyscallDescriptor {
        number: SyscallNumber::SysInfo,
        name: "sys_info",
        required_capability: None,
        audit_event: None,
        early_boot_safe: true,
        interrupt_safe: true,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysYield,
        name: "sys_yield",
        required_capability: None,
        audit_event: None,
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysExit,
        name: "sys_exit",
        required_capability: None,
        audit_event: Some(AuditEventKind::TaskStateChanged),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTime,
        name: "sys_time",
        required_capability: None,
        audit_event: None,
        early_boot_safe: true,
        interrupt_safe: true,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTraceContext,
        name: "sys_trace_context",
        required_capability: None,
        audit_event: None,
        early_boot_safe: true,
        interrupt_safe: true,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskSpawn,
        name: "sys_task_spawn",
        required_capability: Some(Capability::TaskSpawn),
        audit_event: Some(AuditEventKind::TaskSpawn),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskJoin,
        name: "sys_task_join",
        required_capability: Some(Capability::TaskManage),
        audit_event: Some(AuditEventKind::TaskStateChanged),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskCancel,
        name: "sys_task_cancel",
        required_capability: Some(Capability::TaskManage),
        audit_event: Some(AuditEventKind::TaskStateChanged),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskStatus,
        name: "sys_task_status",
        required_capability: Some(Capability::TaskManage),
        audit_event: None,
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemMap,
        name: "sys_mem_map",
        required_capability: Some(Capability::MemoryMap),
        audit_event: Some(AuditEventKind::MemoryMap),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemUnmap,
        name: "sys_mem_unmap",
        required_capability: Some(Capability::MemoryMap),
        audit_event: Some(AuditEventKind::MemoryMap),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemQuery,
        name: "sys_mem_query",
        required_capability: None,
        audit_event: None,
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemShare,
        name: "sys_mem_share",
        required_capability: Some(Capability::MemoryShare),
        audit_event: Some(AuditEventKind::MemoryShare),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemSeal,
        name: "sys_mem_seal",
        required_capability: Some(Capability::MemoryShare),
        audit_event: Some(AuditEventKind::MemoryShare),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceList,
        name: "sys_device_list",
        required_capability: Some(Capability::DeviceList),
        audit_event: None,
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceOpen,
        name: "sys_device_open",
        required_capability: Some(Capability::DeviceOpen),
        audit_event: Some(AuditEventKind::DeviceOpen),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceCall,
        name: "sys_device_call",
        required_capability: Some(Capability::DeviceCall),
        audit_event: Some(AuditEventKind::DeviceCall),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceClose,
        name: "sys_device_close",
        required_capability: Some(Capability::DeviceCall),
        audit_event: Some(AuditEventKind::DeviceCall),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysModelList,
        name: "sys_model_list",
        required_capability: None,
        audit_event: None,
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysModelOpen,
        name: "sys_model_open",
        required_capability: Some(Capability::CognitionInfer),
        audit_event: Some(AuditEventKind::CognitionInfer),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysInfer,
        name: "sys_infer",
        required_capability: Some(Capability::CognitionInfer),
        audit_event: Some(AuditEventKind::CognitionInfer),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemoryQuery,
        name: "sys_memory_query",
        required_capability: Some(Capability::CognitionMemory),
        audit_event: Some(AuditEventKind::CognitiveMemory),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemoryPut,
        name: "sys_memory_put",
        required_capability: Some(Capability::CognitionMemory),
        audit_event: Some(AuditEventKind::CognitiveMemory),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysCapDerive,
        name: "sys_cap_derive",
        required_capability: Some(Capability::SecurityManage),
        audit_event: Some(AuditEventKind::CapabilityChanged),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysCapRevoke,
        name: "sys_cap_revoke",
        required_capability: Some(Capability::SecurityManage),
        audit_event: Some(AuditEventKind::CapabilityChanged),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAttest,
        name: "sys_attest",
        required_capability: Some(Capability::SecurityManage),
        audit_event: Some(AuditEventKind::SecurityDecision),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysRandom,
        name: "sys_random",
        required_capability: None,
        audit_event: None,
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditAppend,
        name: "sys_audit_append",
        required_capability: Some(Capability::AuditAppend),
        audit_event: Some(AuditEventKind::AuditAppend),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditQuery,
        name: "sys_audit_query",
        required_capability: Some(Capability::AuditQuery),
        audit_event: Some(AuditEventKind::AuditQuery),
        early_boot_safe: false,
        interrupt_safe: false,
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditVerify,
        name: "sys_audit_verify",
        required_capability: Some(Capability::AuditVerify),
        audit_event: Some(AuditEventKind::AuditVerify),
        early_boot_safe: false,
        interrupt_safe: false,
    },
];

/// Syscall table metadata returned by `sys_info` and host tests.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallTableInfo {
    /// Kernel/user ABI version.
    pub abi_version: AbiVersion,
    /// Syscall table version.
    pub table_version: AbiVersion,
    /// Maximum accepted user buffer length.
    pub max_buffer_size: u64,
    /// Number of descriptors in the table.
    pub descriptor_count: u32,
    /// Reserved field for feature bitmap expansion.
    pub features: u32,
}

impl SyscallTableInfo {
    /// Returns the default table information for this crate version.
    pub const fn current() -> Self {
        Self {
            abi_version: ALANI_ABI_VERSION,
            table_version: SYSCALL_TABLE_VERSION,
            max_buffer_size: DEFAULT_MAX_SYSCALL_BUFFER_SIZE,
            descriptor_count: SYSCALL_DESCRIPTORS.len() as u32,
            features: 0,
        }
    }
}

/// Table-driven syscall validator.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SyscallDispatcher;

impl SyscallDispatcher {
    /// Looks up a syscall descriptor by raw number.
    pub fn lookup(&self, raw: u64) -> Option<&'static SyscallDescriptor> {
        let number = SyscallNumber::from_raw(raw)?;
        SYSCALL_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.number == number)
    }

    /// Validates number, context, and capability before subsystem dispatch.
    pub fn validate(
        &self,
        frame: &SyscallFrame,
        context: DispatchContext,
    ) -> KernelResult<&'static SyscallDescriptor> {
        let descriptor = self
            .lookup(frame.number)
            .ok_or(KernelError::UnknownSyscall)?;
        if !descriptor.allows_context(context.execution) {
            return Err(KernelError::Busy);
        }
        if let Some(required) = descriptor.required_capability {
            context.capabilities.require(required)?;
        }
        Ok(descriptor)
    }
}
