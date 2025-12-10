# Architecture

This document describes the conceptual architecture of intrinsic isolation: what kernel primitives are involved, how a self-isolating program works, and the design layers that make it practical.

## Kernel Primitives

Linux provides several mechanisms for process isolation. Understanding these is essential—they're the building blocks.

### Namespaces

Namespaces partition kernel resources so that different processes see different views of the system. A process in one namespace can't see or interact with resources in another.

| Namespace | Isolates | Use Case |
|-----------|----------|----------|
| **PID** | Process IDs | Process sees itself as PID 1, can't see host processes |
| **Mount** | Filesystem mounts | Process has its own root filesystem |
| **Network** | Network interfaces, ports, routing | Process has isolated network stack |
| **UTS** | Hostname, domain name | Process can have its own hostname |
| **IPC** | Inter-process communication (shared memory, semaphores) | Prevents IPC with other processes |
| **User** | User and group IDs | Map unprivileged user to root inside namespace |
| **Cgroup** | Cgroup membership | Process sees only its own cgroup hierarchy |

The `unshare(2)` syscall creates new namespaces for the calling process. The `clone(2)` syscall creates a new process in new namespaces. Both accept flags like `CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWNET`.

### Seccomp

Seccomp (secure computing mode) filters system calls. A program installs a BPF filter that the kernel evaluates on every syscall. The filter can:

- **Allow** the syscall
- **Kill** the process
- **Return an error** (EPERM, ENOSYS)
- **Trap** to a signal handler
- **Log** the syscall

A well-designed seccomp profile allows only the syscalls the program actually needs, blocking everything else. If the program never needs `ptrace()`, the filter blocks it—even if an attacker gains code execution.

### Cgroups

Control groups (cgroups) limit and account for resource usage:

- **CPU** — limit CPU time, set scheduling weight
- **Memory** — cap memory usage, trigger OOM behavior
- **I/O** — throttle disk read/write bandwidth
- **PIDs** — limit number of processes

Cgroups are managed through a filesystem interface (`/sys/fs/cgroup/`). A process joins a cgroup by writing its PID to the appropriate `cgroup.procs` file.

### Capabilities

Traditional Unix has two privilege levels: root (can do anything) and non-root (restricted). Linux capabilities split root privileges into smaller pieces:

- `CAP_NET_BIND_SERVICE` — bind to ports below 1024
- `CAP_SYS_ADMIN` — a grab-bag of admin operations (including many namespace operations)
- `CAP_NET_RAW` — use raw sockets
- `CAP_SETUID` / `CAP_SETGID` — change user/group IDs

A self-isolating program can drop capabilities it doesn't need, reducing what an attacker can do if they compromise the process.

## Self-Isolation Pattern

How does a program isolate itself at startup? The basic pattern:

```
┌─────────────────────────────────────────────────────────────────┐
│                         Program Starts                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  Already isolated?    │
                    │  (check env/marker)   │
                    └───────────────────────┘
                          │           │
                         yes          no
                          │           │
                          ▼           ▼
              ┌─────────────────┐  ┌─────────────────────────────┐
              │  Run normally   │  │  Create namespaces          │
              │  (main logic)   │  │  (unshare/clone)            │
              └─────────────────┘  └─────────────────────────────┘
                                                  │
                                                  ▼
                                   ┌─────────────────────────────┐
                                   │  Set up environment         │
                                   │  - mount rootfs             │
                                   │  - configure network        │
                                   │  - apply cgroup limits      │
                                   └─────────────────────────────┘
                                                  │
                                                  ▼
                                   ┌─────────────────────────────┐
                                   │  Install seccomp filter     │
                                   │  Drop capabilities          │
                                   └─────────────────────────────┘
                                                  │
                                                  ▼
                                   ┌─────────────────────────────┐
                                   │  Fork and exec self         │
                                   │  (with isolation marker)    │
                                   └─────────────────────────────┘
                                                  │
                                                  ▼
                                   ┌─────────────────────────────┐
                                   │  Child runs main logic      │
                                   │  Parent waits/exits         │
                                   └─────────────────────────────┘
```

### Step by Step

1. **Check if already isolated.** The program needs to know whether it's in its first invocation (pre-isolation) or running inside the isolated environment. A simple approach: set an environment variable (`N8_ISOLATED=1`) before re-executing.

2. **Create namespaces.** Call `unshare()` with the desired flags. For PID namespaces specifically, the *calling* process doesn't enter the new namespace—its *children* do. So after `unshare(CLONE_NEWPID)`, the program must fork.

3. **Set up the environment.** Mount a new root filesystem (if using mount namespace), configure network interfaces (if using network namespace), write cgroup limits.

4. **Install security filters.** Apply seccomp rules, drop unneeded capabilities. This should happen *after* setup is complete, since setup may require syscalls that the final filter blocks.

5. **Fork and re-exec.** Fork a child process that re-executes the same binary. The child enters the new PID namespace (becoming PID 1 inside it). Set the isolation marker so the child knows to skip straight to running the main logic.

6. **Run.** The child executes the actual program logic, isolated. The parent either waits for the child or exits immediately.

### Why Re-exec?

The re-exec pattern (instead of just forking) ensures that:

- The child process has a clean state
- PID namespace isolation works correctly (fork after unshare enters the new PID namespace)
- The same binary handles both the "isolate" and "run" phases

## Layered Design (Roadmap)

The full vision has three layers:

### Runtime Layer

The lowest layer. Rust code that:

- Calls `unshare()`, `clone()`, `mount()`, `pivot_root()`
- Installs seccomp filters via `seccomp()`
- Manages capabilities via `prctl()` and `capset()`
- Writes to cgroup filesystem

This layer provides safe, typed wrappers around the raw syscalls.

### Macro Layer

A declarative interface for specifying isolation requirements:

```rust
#[isolation(
    namespaces = [pid, mount, network],
    seccomp = "network-only",
    capabilities = [CAP_NET_BIND_SERVICE],
    cgroup_limits = { memory: "256M" }
)]
fn main() {
    // By here, isolation is already applied
}
```

The proc macro generates the preamble code that checks for isolation, applies it if needed, and re-execs into the isolated environment before `main()` runs.

### Discovery Layer

A standardized way to expose isolation requirements so external tools can inspect them:

- ELF section containing structured isolation config
- Sidecar manifest file (`.isolation.json`)
- Runtime introspection via `/proc/[pid]/` conventions

This enables tooling: validators that check isolation policies, AI systems that understand how programs should be deployed, security scanners that verify syscall filters.

## Current Scope

For the initial proof-of-concept, we're focusing on:

- **Runtime layer only** — direct syscall usage, no macros
- **PID + mount namespaces** — minimal viable isolation
- **No seccomp/cgroups yet** — added in subsequent iterations
- **No discovery layer yet** — deferred until the runtime is solid

The goal is a working self-isolating binary that demonstrates the core pattern.
