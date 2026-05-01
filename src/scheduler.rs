//! Host-mode scheduler model for tasks, priorities, budgets, and yielding.
//!
//! The MVK starts with cooperative yield and a deterministic weighted
//! round-robin simulation. It records state transitions through return values
//! so callers can bridge them to audit and trace systems.

use crate::capability::{CapabilitySet, TaskId};
use crate::error::{KernelError, KernelResult};

/// Maximum task slots in the host-mode scheduler.
pub const MAX_TASKS: usize = 64;

/// Default priority used when a caller does not specify one.
pub const DEFAULT_PRIORITY: u8 = 32;

/// Task lifecycle states from the scheduling specification.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskState {
    /// Task is allocated but not yet runnable.
    New,
    /// Task is runnable and waiting in the run queue.
    Ready,
    /// Task is currently executing.
    Running,
    /// Task is blocked on an explicit wait queue.
    Blocked,
    /// Task is sleeping until a wake tick.
    Sleeping,
    /// Task is administratively suspended.
    Suspended,
    /// Task is exiting and releasing resources.
    Exiting,
    /// Task is terminal and waiting to be joined.
    Zombie,
}

/// Scheduling classes defined by the kernel architecture.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerClass {
    /// Kernel-owned work.
    Kernel,
    /// Runtime services.
    Runtime,
    /// Interactive user-facing work.
    Interactive,
    /// Cognitive model, memory, or planning work.
    Cognitive,
    /// Low-priority background work.
    Background,
    /// Audit and security evidence flushing.
    Audit,
}

impl SchedulerClass {
    /// Class boost used by the deterministic host-mode scheduler.
    pub const fn boost(self) -> u32 {
        match self {
            Self::Audit => 96,
            Self::Kernel => 80,
            Self::Runtime => 48,
            Self::Interactive => 32,
            Self::Cognitive => 16,
            Self::Background => 0,
        }
    }
}

/// Budget associated with CPU or cognitive work.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetAccount {
    /// Maximum ticks this budget may consume.
    pub max_ticks: u64,
    /// Remaining ticks before the budget is exhausted.
    pub remaining_ticks: u64,
    /// Absolute scheduler tick deadline, or zero when none is set.
    pub deadline_tick: u64,
}

impl BudgetAccount {
    /// Unbounded budget for non-cognitive or bootstrap work.
    pub const fn unlimited() -> Self {
        Self {
            max_ticks: 0,
            remaining_ticks: 0,
            deadline_tick: 0,
        }
    }

    /// Creates a bounded budget.
    pub const fn bounded(max_ticks: u64, deadline_tick: u64) -> KernelResult<Self> {
        if max_ticks == 0 && deadline_tick == 0 {
            return Err(KernelError::InvalidArgument);
        }
        Ok(Self {
            max_ticks,
            remaining_ticks: max_ticks,
            deadline_tick,
        })
    }

    /// Returns `true` when the budget has no ceiling or deadline.
    pub const fn is_unbounded(self) -> bool {
        self.max_ticks == 0 && self.deadline_tick == 0
    }

    /// Returns `true` when the deadline has passed.
    pub const fn deadline_expired(self, now: u64) -> bool {
        self.deadline_tick != 0 && now >= self.deadline_tick
    }

    /// Consumes one scheduler tick if the budget is bounded.
    pub fn consume_tick(&mut self) -> KernelResult<()> {
        if self.max_ticks == 0 {
            return Ok(());
        }
        if self.remaining_ticks == 0 {
            return Err(KernelError::DeadlineExceeded);
        }
        self.remaining_ticks -= 1;
        Ok(())
    }
}

/// Task control block tracked by the scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskControlBlock {
    /// Stable task identifier.
    pub id: TaskId,
    /// Parent task identifier, or zero when absent.
    pub parent_id: TaskId,
    /// Current task lifecycle state.
    pub state: TaskState,
    /// Scheduling class.
    pub class: SchedulerClass,
    /// Base priority assigned by the creator.
    pub base_priority: u8,
    /// Dynamic priority after aging.
    pub dynamic_priority: u8,
    /// Relative weight for round-robin simulation.
    pub weight: u16,
    /// Number of scheduling rounds spent ready without running.
    pub age: u16,
    /// CPU or cognitive budget.
    pub budget: BudgetAccount,
    /// Capabilities attached to the task.
    pub capabilities: CapabilitySet,
    /// Number of times the task was selected.
    pub context_switches: u64,
}

impl TaskControlBlock {
    /// Empty sentinel used to initialize task slots.
    pub const EMPTY: Self = Self {
        id: 0,
        parent_id: 0,
        state: TaskState::Zombie,
        class: SchedulerClass::Background,
        base_priority: 0,
        dynamic_priority: 0,
        weight: 0,
        age: 0,
        budget: BudgetAccount::unlimited(),
        capabilities: CapabilitySet::EMPTY,
        context_switches: 0,
    };

    /// Creates a runnable task control block.
    pub const fn new(
        id: TaskId,
        parent_id: TaskId,
        class: SchedulerClass,
        priority: u8,
        capabilities: CapabilitySet,
        budget: BudgetAccount,
    ) -> Self {
        Self {
            id,
            parent_id,
            state: TaskState::Ready,
            class,
            base_priority: priority,
            dynamic_priority: priority,
            weight: 1,
            age: 0,
            budget,
            capabilities,
            context_switches: 0,
        }
    }

    /// Returns `true` when this task is eligible to run now.
    pub const fn is_runnable(self) -> bool {
        matches!(self.state, TaskState::Ready | TaskState::Running)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskSlot {
    occupied: bool,
    task: TaskControlBlock,
}

impl TaskSlot {
    const EMPTY: Self = Self {
        occupied: false,
        task: TaskControlBlock::EMPTY,
    };
}

/// State transition record suitable for audit handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskStateTransition {
    /// Task whose state changed.
    pub task_id: TaskId,
    /// Previous state.
    pub from: TaskState,
    /// New state.
    pub to: TaskState,
}

/// Bounded task run queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunQueue {
    slots: [TaskSlot; MAX_TASKS],
}

impl RunQueue {
    /// Creates an empty run queue.
    pub const fn new() -> Self {
        Self {
            slots: [TaskSlot::EMPTY; MAX_TASKS],
        }
    }

    /// Inserts a task.
    pub fn insert(&mut self, task: TaskControlBlock) -> KernelResult<()> {
        if task.id == 0 {
            return Err(KernelError::InvalidArgument);
        }
        if self.get(task.id).is_some() {
            return Err(KernelError::Duplicate);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| !slot.occupied)
            .ok_or(KernelError::CapacityExceeded)?;
        *slot = TaskSlot {
            occupied: true,
            task,
        };
        Ok(())
    }

    /// Immutable task lookup.
    pub fn get(&self, task_id: TaskId) -> Option<&TaskControlBlock> {
        self.slots
            .iter()
            .find(|slot| slot.occupied && slot.task.id == task_id)
            .map(|slot| &slot.task)
    }

    /// Mutable task lookup.
    pub fn get_mut(&mut self, task_id: TaskId) -> Option<&mut TaskControlBlock> {
        self.slots
            .iter_mut()
            .find(|slot| slot.occupied && slot.task.id == task_id)
            .map(|slot| &mut slot.task)
    }

    /// Number of occupied task slots.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|slot| slot.occupied).count()
    }

    /// Returns `true` when no task slots are occupied.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over task references.
    pub fn tasks(&self) -> impl Iterator<Item = &TaskControlBlock> {
        self.slots
            .iter()
            .filter(|slot| slot.occupied)
            .map(|slot| &slot.task)
    }
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Deterministic cooperative scheduler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Scheduler {
    run_queue: RunQueue,
    current_task: Option<TaskId>,
    next_task_id: TaskId,
    tick: u64,
}

impl Scheduler {
    /// Creates an empty scheduler.
    pub const fn new() -> Self {
        Self {
            run_queue: RunQueue::new(),
            current_task: None,
            next_task_id: 1,
            tick: 0,
        }
    }

    /// Current monotonic scheduler tick.
    pub const fn tick(&self) -> u64 {
        self.tick
    }

    /// Current task identifier, if one is running.
    pub const fn current_task(&self) -> Option<TaskId> {
        self.current_task
    }

    /// Immutable run queue access for diagnostics and tests.
    pub const fn run_queue(&self) -> &RunQueue {
        &self.run_queue
    }

    /// Spawns a ready task and returns its identifier.
    pub fn spawn(
        &mut self,
        parent_id: TaskId,
        class: SchedulerClass,
        priority: u8,
        capabilities: CapabilitySet,
        budget: BudgetAccount,
    ) -> KernelResult<TaskId> {
        let task_id = self.next_task_id;
        self.next_task_id = self
            .next_task_id
            .checked_add(1)
            .ok_or(KernelError::Internal)?;
        let task = TaskControlBlock::new(task_id, parent_id, class, priority, capabilities, budget);
        self.run_queue.insert(task)?;
        Ok(task_id)
    }

    /// Transitions a task to a new state.
    pub fn transition(
        &mut self,
        task_id: TaskId,
        to: TaskState,
    ) -> KernelResult<TaskStateTransition> {
        let task = self
            .run_queue
            .get_mut(task_id)
            .ok_or(KernelError::NotFound)?;
        let from = task.state;
        if !Self::valid_transition(from, to) {
            return Err(KernelError::InvalidState);
        }
        task.state = to;
        if matches!(to, TaskState::Running) {
            self.current_task = Some(task_id);
        } else if self.current_task == Some(task_id) {
            self.current_task = None;
        }
        Ok(TaskStateTransition { task_id, from, to })
    }

    /// Cooperative yield from the current task.
    pub fn yield_current(&mut self) -> KernelResult<Option<TaskId>> {
        if let Some(current) = self.current_task {
            let task = self
                .run_queue
                .get_mut(current)
                .ok_or(KernelError::NotFound)?;
            task.budget.consume_tick()?;
            if task.state == TaskState::Running {
                task.state = TaskState::Ready;
            }
        }
        self.schedule_next()
    }

    /// Selects the next runnable task using deterministic weighted scoring.
    pub fn schedule_next(&mut self) -> KernelResult<Option<TaskId>> {
        self.tick = self.tick.checked_add(1).ok_or(KernelError::Internal)?;

        let mut best_index: Option<usize> = None;
        let mut best_score: u32 = 0;
        for (index, slot) in self.slots_iter().enumerate() {
            if !slot.occupied || !slot.task.is_runnable() {
                continue;
            }
            let score = self.score(slot.task);
            if best_index.is_none() || score > best_score {
                best_index = Some(index);
                best_score = score;
            }
        }

        let Some(selected_index) = best_index else {
            self.current_task = None;
            return Ok(None);
        };

        let selected_id = self.run_queue.slots[selected_index].task.id;
        for slot in self.run_queue.slots.iter_mut().filter(|slot| slot.occupied) {
            if slot.task.id == selected_id {
                slot.task.state = TaskState::Running;
                slot.task.age = 0;
                slot.task.dynamic_priority = slot.task.base_priority;
                slot.task.context_switches = slot
                    .task
                    .context_switches
                    .checked_add(1)
                    .ok_or(KernelError::Internal)?;
            } else if slot.task.state == TaskState::Running {
                slot.task.state = TaskState::Ready;
            } else if slot.task.state == TaskState::Ready {
                slot.task.age = slot.task.age.saturating_add(1);
                slot.task.dynamic_priority = slot
                    .task
                    .base_priority
                    .saturating_add((slot.task.age / 4) as u8);
            }
        }
        self.current_task = Some(selected_id);
        Ok(Some(selected_id))
    }

    /// Cancels a task and transitions it to `Zombie`.
    pub fn cancel(&mut self, task_id: TaskId) -> KernelResult<TaskStateTransition> {
        let task = self
            .run_queue
            .get_mut(task_id)
            .ok_or(KernelError::NotFound)?;
        let from = task.state;
        if matches!(from, TaskState::Zombie | TaskState::Exiting) {
            return Err(KernelError::InvalidState);
        }
        task.state = TaskState::Zombie;
        if self.current_task == Some(task_id) {
            self.current_task = None;
        }
        Ok(TaskStateTransition {
            task_id,
            from,
            to: TaskState::Zombie,
        })
    }

    fn slots_iter(&self) -> core::slice::Iter<'_, TaskSlot> {
        self.run_queue.slots.iter()
    }

    fn score(&self, task: TaskControlBlock) -> u32 {
        let deadline_boost = if task.budget.deadline_expired(self.tick) {
            128
        } else {
            0
        };
        u32::from(task.dynamic_priority)
            + u32::from(task.weight)
            + task.class.boost()
            + u32::from(task.age)
            + deadline_boost
    }

    const fn valid_transition(from: TaskState, to: TaskState) -> bool {
        matches!(
            (from, to),
            (TaskState::New, TaskState::Ready)
                | (TaskState::Ready, TaskState::Running)
                | (TaskState::Running, TaskState::Ready)
                | (TaskState::Running, TaskState::Blocked)
                | (TaskState::Running, TaskState::Sleeping)
                | (TaskState::Ready, TaskState::Suspended)
                | (TaskState::Suspended, TaskState::Ready)
                | (TaskState::Blocked, TaskState::Ready)
                | (TaskState::Sleeping, TaskState::Ready)
                | (TaskState::Running, TaskState::Exiting)
                | (TaskState::Exiting, TaskState::Zombie)
                | (_, TaskState::Zombie)
        )
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}
