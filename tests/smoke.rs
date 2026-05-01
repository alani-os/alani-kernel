use alani_kernel::capability::{Capability, CapabilityRegistry, CapabilitySet};
use alani_kernel::device::{
    DeviceClass, DeviceDescriptor, DeviceLifecycle, DeviceOperation, DmaPolicy,
};
use alani_kernel::error::{KernelError, KernelStatus};
use alani_kernel::memory::{BufferAccess, MemoryPermissions, DEFAULT_USER_LOWER_BOUND};
use alani_kernel::scheduler::{BudgetAccount, Scheduler, SchedulerClass};
use alani_kernel::syscall::{
    DispatchContext, SyscallFrame, SyscallNumber, UserBuffer, USER_BUFFER_WRITE,
};
use alani_kernel::Kernel;

#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_kernel::repository_name(), "alani-kernel");
    assert!(alani_kernel::module_names().contains(&"syscall"));
    assert!(alani_kernel::module_names().contains(&"capability"));
}

#[test]
fn host_boot_sequence_completes_in_order() {
    let mut kernel = Kernel::new();
    kernel.initialize_host().unwrap();
    assert!(kernel.boot.is_complete());
    assert_eq!(
        kernel.memory.allocator_phase(),
        alani_kernel::memory::AllocatorPhase::Heap
    );
}

#[test]
fn unknown_syscall_fails_with_stable_status_and_fault() {
    let mut kernel = Kernel::new();
    let result = kernel.handle_syscall(
        SyscallFrame::raw(0xffff, [0; 6]),
        DispatchContext::task(1, CapabilitySet::EMPTY),
    );
    assert_eq!(result.status, KernelStatus::InvalidArgument);
    assert_eq!(kernel.faults.last().unwrap().reason, "unknown_syscall");
}

#[test]
fn privileged_syscall_is_denied_before_argument_validation() {
    let mut kernel = Kernel::new();
    let result = kernel.handle_syscall(
        SyscallFrame::new(SyscallNumber::SysTaskSpawn, [0, 4096, 0, 0, 0, 0]),
        DispatchContext::task(1, CapabilitySet::EMPTY),
    );
    assert_eq!(result.status, KernelStatus::PermissionDenied);
    assert_eq!(kernel.audit.last().unwrap().reason, "missing_capability");
}

#[test]
fn sys_info_validates_user_output_buffer() {
    let mut kernel = Kernel::new();
    let result = kernel.handle_syscall(
        SyscallFrame::new(
            SyscallNumber::SysInfo,
            [
                DEFAULT_USER_LOWER_BOUND,
                128,
                USER_BUFFER_WRITE as u64,
                0,
                0,
                0,
            ],
        ),
        DispatchContext::task(1, CapabilitySet::EMPTY),
    );
    assert_eq!(result.status, KernelStatus::Ok);
    assert_ne!(result.value, 0);
    assert!(result.detail > 0);
}

#[test]
fn user_buffer_validator_rejects_kernel_range() {
    let kernel = Kernel::new();
    let buffer = UserBuffer::new(0x800, 64, USER_BUFFER_WRITE);
    let error = kernel
        .memory
        .validate_user_buffer(buffer, BufferAccess::Write)
        .unwrap_err();
    assert_eq!(error, KernelError::BufferOutOfRange);
}

#[test]
fn capability_derivation_is_attenuating() {
    let mut registry = CapabilityRegistry::new();
    let parent_rights = CapabilitySet::single(Capability::TaskSpawn).with(Capability::MemoryMap);
    let parent = registry.issue(1, parent_rights).unwrap();

    let child = registry
        .derive(parent, 2, CapabilitySet::single(Capability::MemoryMap))
        .unwrap();
    assert!(registry
        .resolve(child)
        .unwrap()
        .contains(Capability::MemoryMap));

    let denied = registry.derive(parent, 2, CapabilitySet::single(Capability::AuditVerify));
    assert_eq!(denied.unwrap_err(), KernelError::MissingCapability);
}

#[test]
fn scheduler_prefers_audit_work_and_ages_ready_tasks() {
    let mut scheduler = Scheduler::new();
    let background = scheduler
        .spawn(
            0,
            SchedulerClass::Background,
            10,
            CapabilitySet::EMPTY,
            BudgetAccount::unlimited(),
        )
        .unwrap();
    let audit = scheduler
        .spawn(
            0,
            SchedulerClass::Audit,
            10,
            CapabilitySet::EMPTY,
            BudgetAccount::unlimited(),
        )
        .unwrap();

    assert_eq!(scheduler.schedule_next().unwrap(), Some(audit));
    scheduler.yield_current().unwrap();
    let background_task = scheduler.run_queue().get(background).unwrap();
    assert!(background_task.age > 0);
}

#[test]
fn shared_memory_can_be_sealed() {
    let mut kernel = Kernel::new();
    let rights = CapabilitySet::single(Capability::MemoryShare);
    let share = kernel.handle_syscall(
        SyscallFrame::new(
            SyscallNumber::SysMemShare,
            [
                DEFAULT_USER_LOWER_BOUND,
                4096,
                MemoryPermissions::READ
                    .union(MemoryPermissions::WRITE)
                    .union(MemoryPermissions::USER)
                    .bits() as u64,
                0,
                0,
                0,
            ],
        ),
        DispatchContext::task(7, rights),
    );
    assert_eq!(share.status, KernelStatus::Ok);

    let seal = kernel.handle_syscall(
        SyscallFrame::new(SyscallNumber::SysMemSeal, [share.value, 0, 0, 0, 0, 0]),
        DispatchContext::task(7, rights),
    );
    assert_eq!(seal.status, KernelStatus::Ok);
    assert!(
        kernel
            .memory
            .shared_region(alani_kernel::memory::SharedMemoryHandle {
                id: share.value,
                owner_task: 7,
                permissions: 0,
            })
            .unwrap()
            .sealed
    );
}

#[test]
fn device_registry_rejects_unsupported_operation() {
    let mut kernel = Kernel::new();
    kernel
        .devices
        .register(DeviceDescriptor {
            id: 1,
            class: DeviceClass::Console,
            lifecycle: DeviceLifecycle::Configured,
            required_capabilities: CapabilitySet::single(Capability::DeviceCall),
            supported_operations: 1 << (DeviceOperation::Query as u32),
            max_input_len: 16,
            max_output_len: 16,
            dma_policy: DmaPolicy::None,
        })
        .unwrap();

    let caps = CapabilitySet::single(Capability::DeviceCall);
    let result = kernel.handle_syscall(
        SyscallFrame::new(
            SyscallNumber::SysDeviceCall,
            [1, DeviceOperation::Write as u64, 0, 0, 0, 0],
        ),
        DispatchContext::task(1, caps),
    );
    assert_eq!(result.status, KernelStatus::InvalidArgument);
}
