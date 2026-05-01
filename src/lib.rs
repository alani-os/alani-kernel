#![cfg_attr(not(feature = "std"), no_std)]

//! Authority-bearing kernel skeleton for the Alani MVK.
//!
//! This crate intentionally remains dependency-free while sibling repository
//! APIs stabilize. It provides host-mode, no-std-compatible contracts for boot
//! ordering, syscall validation, scheduler simulation, memory validation,
//! device mediation, capabilities, audit handoff, and fault diagnostics.

pub mod audit;
pub mod boot;
pub mod capability;
pub mod device;
pub mod error;
pub mod fault;
pub mod memory;
pub mod scheduler;
pub mod syscall;

use core::mem::size_of;

use audit::{AuditEventKind, AuditLog};
use boot::{BootPhase, BootProgress, BOOT_SEQUENCE};
use capability::{CapabilitySet, TaskId};
use device::{DeviceOperation, DeviceRegistry};
use error::{KernelError, KernelResult, KernelStatus};
use fault::{FaultKind, FaultPhase, FaultReporter, FaultSeverity};
use memory::{BufferAccess, MemoryManager, MemoryPermissions, SharedMemoryHandle};
use scheduler::{BudgetAccount, Scheduler, SchedulerClass};
use syscall::{
    DispatchContext, ExecutionContext, SyscallDispatcher, SyscallFrame, SyscallNumber,
    SyscallResult, SyscallTableInfo, UserBuffer, ALANI_ABI_VERSION, USER_BUFFER_READ,
    USER_BUFFER_WRITE,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-kernel";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this skeleton.
pub const MODULES: &[&str] = &[
    "audit",
    "boot",
    "capability",
    "device",
    "error",
    "fault",
    "memory",
    "scheduler",
    "syscall",
];

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Runtime configuration for the host-mode kernel skeleton.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KernelConfig {
    /// Maximum user buffer length accepted by memory validation.
    pub max_user_buffer_len: u64,
}

impl KernelConfig {
    /// Default configuration aligned with the syscall table metadata.
    pub const fn default() -> Self {
        Self {
            max_user_buffer_len: syscall::DEFAULT_MAX_SYSCALL_BUFFER_SIZE,
        }
    }
}

/// Aggregated kernel subsystem state for host-mode tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kernel {
    /// Configuration values.
    pub config: KernelConfig,
    /// Boot phase progress tracker.
    pub boot: BootProgress,
    /// Memory manager skeleton.
    pub memory: MemoryManager,
    /// Cooperative scheduler skeleton.
    pub scheduler: Scheduler,
    /// Device registry skeleton.
    pub devices: DeviceRegistry,
    /// Audit ring buffer.
    pub audit: AuditLog,
    /// Fault diagnostic ring buffer.
    pub faults: FaultReporter,
    syscalls: SyscallDispatcher,
}

impl Kernel {
    /// Creates a new kernel skeleton with default subsystem state.
    pub const fn new() -> Self {
        Self {
            config: KernelConfig::default(),
            boot: BootProgress::new(),
            memory: MemoryManager::new(),
            scheduler: Scheduler::new(),
            devices: DeviceRegistry::new(),
            audit: AuditLog::new(),
            faults: FaultReporter::new(),
            syscalls: SyscallDispatcher,
        }
    }

    /// Completes the deterministic host-mode boot sequence.
    ///
    /// Platform-specific setup can later replace the no-op phase bodies while
    /// preserving the order enforced here.
    pub fn initialize_host(&mut self) -> KernelResult<()> {
        for phase in BOOT_SEQUENCE {
            match phase {
                BootPhase::Allocator => {
                    self.memory
                        .set_allocator_phase(memory::AllocatorPhase::BootBump)?;
                    self.memory
                        .set_allocator_phase(memory::AllocatorPhase::Frame)?;
                    self.memory
                        .set_allocator_phase(memory::AllocatorPhase::Heap)?;
                }
                BootPhase::RuntimeSpawn => {
                    let _ = self.scheduler.spawn(
                        0,
                        SchedulerClass::Runtime,
                        scheduler::DEFAULT_PRIORITY,
                        CapabilitySet::EMPTY,
                        BudgetAccount::unlimited(),
                    )?;
                }
                _ => {}
            }
            self.boot.complete(phase)?;
        }
        Ok(())
    }

    /// Dispatches a syscall through table validation, capability checks, audit,
    /// and host-mode subsystem handlers.
    pub fn handle_syscall(
        &mut self,
        frame: SyscallFrame,
        context: DispatchContext,
    ) -> SyscallResult {
        let descriptor = match self.syscalls.validate(&frame, context) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                self.record_rejected_syscall(frame, context, error);
                return SyscallResult::error(error);
            }
        };

        let result = self.dispatch_validated(descriptor.number, frame, context);
        if let Some(kind) = descriptor.audit_event {
            let reason = if result.status.is_ok() {
                "ok"
            } else {
                "syscall_failed"
            };
            self.audit.record_syscall(
                kind,
                context.task_id,
                descriptor.number,
                result.status,
                frame.trace,
                reason,
            );
        }
        if !result.status.is_ok() {
            self.faults.record_error(
                Self::fault_kind_for_status(result.status),
                FaultSeverity::Warning,
                context.task_id,
                Self::error_for_status(result.status),
                FaultPhase::Runtime,
                frame.trace,
            );
        }
        result
    }

    fn dispatch_validated(
        &mut self,
        number: SyscallNumber,
        frame: SyscallFrame,
        context: DispatchContext,
    ) -> SyscallResult {
        match number {
            SyscallNumber::SysInfo => self.sys_info(frame),
            SyscallNumber::SysYield => self.sys_yield(),
            SyscallNumber::SysExit => self.sys_exit(context.task_id),
            SyscallNumber::SysTime => SyscallResult::ok(self.scheduler.tick(), 0),
            SyscallNumber::SysTraceContext => {
                SyscallResult::ok(frame.trace.trace_id, frame.trace.span_id)
            }
            SyscallNumber::SysTaskSpawn => self.sys_task_spawn(frame, context),
            SyscallNumber::SysTaskJoin => SyscallResult::ok(frame.args[0], 0),
            SyscallNumber::SysTaskCancel => self.sys_task_cancel(frame),
            SyscallNumber::SysTaskStatus => self.sys_task_status(frame),
            SyscallNumber::SysMemMap | SyscallNumber::SysMemUnmap => self.sys_mem_range(frame),
            SyscallNumber::SysMemQuery => self.sys_mem_query(),
            SyscallNumber::SysMemShare => self.sys_mem_share(frame, context.task_id),
            SyscallNumber::SysMemSeal => self.sys_mem_seal(frame, context.task_id),
            SyscallNumber::SysDeviceList => SyscallResult::ok(self.devices.len() as u64, 0),
            SyscallNumber::SysDeviceOpen => self.sys_device_open(frame, context.capabilities),
            SyscallNumber::SysDeviceCall => self.sys_device_call(frame, context.capabilities),
            SyscallNumber::SysDeviceClose => SyscallResult::ok(frame.args[0], 0),
            SyscallNumber::SysModelList => SyscallResult::ok(0, 0),
            SyscallNumber::SysModelOpen => SyscallResult::ok(frame.args[0], 0),
            SyscallNumber::SysInfer => self.sys_infer(frame),
            SyscallNumber::SysMemoryQuery | SyscallNumber::SysMemoryPut => SyscallResult::ok(0, 0),
            SyscallNumber::SysCapDerive | SyscallNumber::SysCapRevoke => SyscallResult::ok(0, 0),
            SyscallNumber::SysAttest => SyscallResult::ok(ALANI_ABI_VERSION.packed(), 0),
            SyscallNumber::SysRandom => self.sys_random(frame),
            SyscallNumber::SysAuditAppend => SyscallResult::ok(self.audit.next_sequence(), 0),
            SyscallNumber::SysAuditQuery => SyscallResult::ok(self.audit.len() as u64, 0),
            SyscallNumber::SysAuditVerify => {
                SyscallResult::ok(self.audit.next_sequence().saturating_sub(1), 0)
            }
        }
    }

    fn sys_info(&self, frame: SyscallFrame) -> SyscallResult {
        let out = UserBuffer::new(frame.args[0], frame.args[1], frame.args[2] as u32);
        match self.memory.validate_user_buffer(out, BufferAccess::Write) {
            Ok(_) => SyscallResult::ok(
                ALANI_ABI_VERSION.packed(),
                size_of::<SyscallTableInfo>() as u64,
            ),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_yield(&mut self) -> SyscallResult {
        match self.scheduler.yield_current() {
            Ok(Some(task_id)) => SyscallResult::ok(task_id, 0),
            Ok(None) => SyscallResult::ok(0, 0),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_exit(&mut self, task_id: TaskId) -> SyscallResult {
        match self.scheduler.cancel(task_id) {
            Ok(_) => SyscallResult::ok(task_id, 0),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_task_spawn(&mut self, frame: SyscallFrame, context: DispatchContext) -> SyscallResult {
        if frame.args[1] != 0 {
            let manifest = UserBuffer::new(frame.args[0], frame.args[1], USER_BUFFER_READ);
            if let Err(error) = self
                .memory
                .validate_user_buffer(manifest, BufferAccess::Read)
            {
                return SyscallResult::error(error);
            }
        }
        let priority = if frame.args[3] <= u64::from(u8::MAX) {
            frame.args[3] as u8
        } else {
            return SyscallResult::error(KernelError::InvalidArgument);
        };
        let priority = if priority == 0 {
            scheduler::DEFAULT_PRIORITY
        } else {
            priority
        };
        match self.scheduler.spawn(
            context.task_id,
            SchedulerClass::Runtime,
            priority,
            CapabilitySet::EMPTY,
            BudgetAccount::unlimited(),
        ) {
            Ok(task_id) => SyscallResult::ok(task_id, 0),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_task_cancel(&mut self, frame: SyscallFrame) -> SyscallResult {
        match self.scheduler.cancel(frame.args[0]) {
            Ok(_) => SyscallResult::ok(frame.args[0], 0),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_task_status(&self, frame: SyscallFrame) -> SyscallResult {
        match self.scheduler.run_queue().get(frame.args[0]) {
            Some(task) => SyscallResult::ok(task.state as u64, task.context_switches),
            None => SyscallResult::error(KernelError::NotFound),
        }
    }

    fn sys_mem_range(&self, frame: SyscallFrame) -> SyscallResult {
        match self
            .memory
            .validate_user_range(frame.args[0], frame.args[1])
        {
            Ok(()) => SyscallResult::ok(frame.args[0], frame.args[1]),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_mem_query(&self) -> SyscallResult {
        let stats = self.memory.stats();
        SyscallResult::ok(stats.usable_bytes, stats.region_count as u64)
    }

    fn sys_mem_share(&mut self, frame: SyscallFrame, task_id: TaskId) -> SyscallResult {
        let permissions = match MemoryPermissions::from_bits(frame.args[2] as u32) {
            Ok(permissions) => permissions,
            Err(error) => return SyscallResult::error(error),
        };
        match self
            .memory
            .share_region(task_id, frame.args[0], frame.args[1], permissions)
        {
            Ok(handle) => SyscallResult::ok(handle.id, u64::from(handle.permissions)),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_mem_seal(&mut self, frame: SyscallFrame, task_id: TaskId) -> SyscallResult {
        let handle = SharedMemoryHandle {
            id: frame.args[0],
            owner_task: task_id,
            permissions: 0,
        };
        match self.memory.seal_shared_region(handle) {
            Ok(()) => SyscallResult::ok(frame.args[0], 0),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_device_open(&self, frame: SyscallFrame, capabilities: CapabilitySet) -> SyscallResult {
        match self.devices.authorize_open(frame.args[0], capabilities) {
            Ok(descriptor) => SyscallResult::ok(descriptor.id, descriptor.class as u64),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_device_call(&self, frame: SyscallFrame, capabilities: CapabilitySet) -> SyscallResult {
        let operation = match DeviceOperation::from_raw(frame.args[1]) {
            Some(operation) => operation,
            None => return SyscallResult::error(KernelError::InvalidArgument),
        };
        match self.devices.authorize_call(
            frame.args[0],
            operation,
            capabilities,
            frame.args[3],
            frame.args[5],
        ) {
            Ok(_) => SyscallResult::ok(0, 0),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn sys_infer(&self, frame: SyscallFrame) -> SyscallResult {
        if frame.args[3] == 0 {
            return SyscallResult::error(KernelError::DeadlineExceeded);
        }
        SyscallResult::ok(0, 0)
    }

    fn sys_random(&self, frame: SyscallFrame) -> SyscallResult {
        let out = UserBuffer::new(frame.args[0], frame.args[1], USER_BUFFER_WRITE);
        match self.memory.validate_user_buffer(out, BufferAccess::Write) {
            Ok(buffer) => SyscallResult::ok(0, buffer.len),
            Err(error) => SyscallResult::error(error),
        }
    }

    fn record_rejected_syscall(
        &mut self,
        frame: SyscallFrame,
        context: DispatchContext,
        error: KernelError,
    ) {
        let status = error.status();
        if let Some(descriptor) = self.syscalls.lookup(frame.number) {
            if let Some(kind) = descriptor.audit_event {
                self.audit.record_syscall(
                    kind,
                    context.task_id,
                    descriptor.number,
                    status,
                    frame.trace,
                    error.reason(),
                );
            } else if status == KernelStatus::PermissionDenied {
                self.audit.record_syscall(
                    AuditEventKind::SecurityDecision,
                    context.task_id,
                    descriptor.number,
                    status,
                    frame.trace,
                    error.reason(),
                );
            }
        }

        let kind = match error {
            KernelError::UnknownSyscall => FaultKind::InvalidSyscall,
            KernelError::MissingCapability | KernelError::PermissionDenied => {
                FaultKind::CapabilityDenied
            }
            _ => FaultKind::InvariantViolation,
        };
        let severity = if status == KernelStatus::PermissionDenied {
            FaultSeverity::Error
        } else {
            FaultSeverity::Warning
        };
        let phase = if context.execution == ExecutionContext::EarlyBoot {
            FaultPhase::Boot
        } else {
            FaultPhase::Runtime
        };
        self.faults
            .record_error(kind, severity, context.task_id, error, phase, frame.trace);
    }

    fn fault_kind_for_status(status: KernelStatus) -> FaultKind {
        match status {
            KernelStatus::PermissionDenied => FaultKind::CapabilityDenied,
            KernelStatus::InvalidArgument => FaultKind::InvariantViolation,
            KernelStatus::Busy | KernelStatus::DeadlineExceeded => FaultKind::InvariantViolation,
            KernelStatus::NotFound => FaultKind::InvariantViolation,
            KernelStatus::Internal => FaultKind::InvariantViolation,
            KernelStatus::Ok => FaultKind::InvariantViolation,
        }
    }

    fn error_for_status(status: KernelStatus) -> KernelError {
        match status {
            KernelStatus::Ok => KernelError::Internal,
            KernelStatus::InvalidArgument => KernelError::InvalidArgument,
            KernelStatus::PermissionDenied => KernelError::PermissionDenied,
            KernelStatus::NotFound => KernelError::NotFound,
            KernelStatus::Busy => KernelError::Busy,
            KernelStatus::DeadlineExceeded => KernelError::DeadlineExceeded,
            KernelStatus::Internal => KernelError::Internal,
        }
    }
}

impl Default for Kernel {
    fn default() -> Self {
        Self::new()
    }
}
