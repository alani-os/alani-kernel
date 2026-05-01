# alani-kernel

Authority-bearing core for scheduler, memory, syscall dispatch, device mediation, capabilities, audit handoff, and fault diagnostics.

| Field | Value |
|---|---|
| Status | Experimental MVK skeleton |
| Tier | MVK required |
| Owner | Kernel team |
| Aliases | None |
| Architectural dependencies | `alani-abi`, `alani-platform`, `alani-ipc`, `alani-storage`, `alani-filesystem`, `alani-devices`, `alani-security`, `alani-audit`, `alani-observability`, `alani-policy` |

## Quick Start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-features -- -D warnings
```

## Scope

This crate is intentionally dependency-free while sibling repository APIs stabilize. It implements no-std-friendly host-mode contracts for:

- deterministic boot phase ordering;
- stable syscall numbers, ABI-safe frames, trace context, buffer descriptors, and table metadata;
- deny-by-default capability sets and attenuated capability handles;
- user-buffer and user-range validation, memory-map preservation, allocator phase tracking, and sealable shared-memory handles;
- cooperative scheduler simulation with task states, classes, budgets, priority aging, and audit-priority handling;
- device registry checks for duplicate IDs, required capabilities, supported operations, and buffer limits;
- structured audit records and bounded fault diagnostics.

## Layout

```text
src/
  audit.rs       structured audit events and host-mode ring buffer
  boot.rs        deterministic initialization phase tracking
  capability.rs  capability bitsets, handles, derivation, revocation
  device.rs      device descriptors and registry authorization checks
  error.rs       internal errors and stable ABI statuses
  fault.rs       diagnostic fault records and reporter
  lib.rs         aggregated Kernel facade and syscall handlers
  memory.rs      memory map, user-buffer validation, shared handles
  scheduler.rs   cooperative scheduler and task control blocks
  syscall.rs     ABI-safe syscall table and dispatcher validation
tests/
  smoke.rs       host-mode conformance and negative tests
```

## Specification Traceability

The first API surface is mapped to `alani-spec/docs/repositories/alani-kernel.md`, Doc 06, Doc 08, Doc 09, Doc 10, Doc 11, Doc 12, Doc 13, Doc 15, Doc 16, Doc 17, Doc 19, Doc 23, and Doc 24.

Path dependencies remain out of `Cargo.toml` until those sibling repositories publish stable public APIs, as required by the repository metadata contract.
