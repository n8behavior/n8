# Implementation Notes

Technical notes and explanations from the initial implementation.

## The Two-Fork Pattern

The `isolate()` function uses two forks, resulting in three processes: parent, child, and grandchild. This isn't accidental—it's required for unprivileged user namespace setup.

### Why Two Forks?

The constraint comes from UID/GID mapping. When a process enters a new user namespace (via `unshare(CLONE_NEWUSER)`), it cannot write its own `/proc/{pid}/uid_map` and `/proc/{pid}/gid_map` files. These must be written by a process *outside* the new user namespace.

With a single fork, if the parent called `unshare(CLONE_NEWUSER | CLONE_NEWPID)`:
- The parent enters the new user namespace
- No process remains outside to write the mappings
- The parent can't grant itself capabilities

The two-fork pattern solves this:
1. **Parent** stays in the host namespaces
2. **Child** calls `unshare()` to create new namespaces, then signals the parent
3. **Parent** writes UID/GID mappings from outside, then signals the child
4. **Child** forks again
5. **Grandchild** is PID 1 in the new PID namespace, re-execs with the isolation marker

### Process Roles

| Process | Role | Namespaces |
|---------|------|------------|
| Parent | Writes UID/GID mappings, waits for child | Host |
| Child | Namespace scaffolding, waits for grandchild | New user ns, host PID ns |
| Grandchild | Actual isolated process | New user ns, new PID ns |

The parent and child are just scaffolding—they block on `waitpid()` and propagate the exit code up the chain. The grandchild does the real work.

### PID Namespace Quirk

A process that calls `unshare(CLONE_NEWPID)` does *not* enter the new PID namespace itself. Only its subsequent children do. That's why the child must fork again to produce a grandchild that's actually PID 1 in the new namespace.

## Pipe Synchronization

The two pipes (`child_ready` and `mappings_done`) coordinate the parent and child:

```
Parent                          Child
──────                          ─────
                                unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS)
                                write(child_ready, "x")
read(child_ready) ←────────────
write_uid_gid_mappings()
write(mappings_done, "x") ─────────────→ read(mappings_done)
                                fork() → grandchild
```

When `fork()` is called, both parent and child get file descriptors to the same underlying pipes (the pipes aren't duplicated—just the file descriptor table is copied). Each process closes the ends it won't use. This is standard Unix practice:
- Prevents deadlocks (a `read()` only returns EOF when *all* write ends are closed)
- Cleans up unused resources

## Why Root Daemons Are Simpler

Docker's daemon runs as root, which sidesteps all this complexity. A root process can:
- Call `unshare()` with any namespace flags directly
- Write UID/GID mappings for any process
- Mount filesystems (including `/proc`)
- Set up cgroups and network interfaces

No multi-process coordination needed. The complexity of the two-fork pattern is the cost of unprivileged operation.

### Alternative Approaches

| Approach | Pros | Cons |
|----------|------|------|
| Root daemon (Docker) | Simple, full capabilities | Security risk, requires root |
| Setuid helpers (Podman) | Extended UID/GID ranges, unprivileged | External dependencies |
| Pure user namespace (n8) | No dependencies, unprivileged | Single UID mapping, limited mount capabilities |

We chose the pure user namespace approach to stay true to "no external runtime dependencies."

## Known Limitations

### /proc Remounting

**Status: TODO for next session**

The current implementation cannot remount `/proc` to show only the isolated namespace's processes. After isolation, `getpid()` correctly returns 1, but reading `/proc` still shows the host's process list.

This happens because mounting filesystems—even `proc`—requires `CAP_SYS_ADMIN` in the mount namespace's *owning* user namespace. The kernel restricts what unprivileged user namespaces can mount for security reasons.

The PID namespace isolation is still real—the process cannot signal or interact with processes outside its namespace—but the `/proc` view is misleading without the remount.

### Proposed Solution: Minimal tmpfs + pivot_root

For a static (musl) binary—the kind you'd put in a `FROM scratch` container—we don't need a full rootfs. We just need mount points.

A minimal rootfs on tmpfs:

```
/tmp/n8-root/
├── proc/       ← empty directory, mount point
└── n8          ← static binary (copied or bind-mounted)
```

The approach:
1. Create a tmpfs
2. `mkdir /proc` on it
3. Copy or bind-mount the static binary
4. `pivot_root()` into the tmpfs
5. Unmount the old root
6. Mount fresh `/proc`
7. `execve("/n8")`

After `pivot_root()`, the old filesystem tree is gone (not just hidden like with `chroot()`), and `/proc` is a fresh mount in a mount tree owned by our user namespace—so it shows only our PID namespace's processes.

This stays true to "no external dependencies"—we're creating empty directories on a tmpfs at runtime, not shipping a rootfs tarball. The binary must be statically linked, but that's already the target for self-contained deployment.

## Implementation Journey: pivot_root and /proc

This section documents our implementation of the tmpfs + pivot_root approach and the challenges encountered.

### What We Implemented

The `setup_pivot_root()` function in `src/main.rs` performs these steps:

1. **Make root mount private** — `mount(None, "/", None, MS_REC | MS_PRIVATE, None)` — required because `pivot_root` fails if propagation type is `MS_SHARED`
2. **Create tmpfs** — `mount("tmpfs", "/tmp/n8-root-{pid}", "tmpfs", ...)` — 10MB tmpfs for the minimal rootfs
3. **Create /proc mount point** — empty directory for later proc mount
4. **Copy static binary** — copies the executable to `/n8` in the new root
5. **Create old_root directory** — required by `pivot_root` for the old root
6. **Change to new root** — `chdir()` to the tmpfs
7. **pivot_root** — `pivot_root(".", "old_root")` swaps the root filesystem
8. **Unmount old root** — `umount2("/old_root", MNT_DETACH)` removes access to host filesystem
9. **Mount /proc** — attempted after `execve()` in the re-executed binary

### Problems Encountered

#### Problem 1: Mount Namespace Ownership

**Symptom:** `mount()` for tmpfs failed with `EACCES: Permission denied`

**Root Cause:** When `unshare(CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS)` is called in a single syscall, the mount namespace is created *before* the UID/GID mappings are written. The mount namespace's "owning user namespace" is determined at creation time, and without mappings, the process lacks `CAP_SYS_ADMIN` for mount operations.

**Solution:** Split namespace creation:
- Child: `unshare(CLONE_NEWUSER | CLONE_NEWPID)` — create user and PID namespaces
- Parent: Write UID/GID mappings
- Grandchild: `unshare(CLONE_NEWNS)` — create mount namespace *after* mappings are set

This ensures the mount namespace is owned by a fully-initialized user namespace.

#### Problem 2: Ubuntu AppArmor Restrictions

**Symptom:** `unshare(CLONE_NEWNS)` in the grandchild failed with `EPERM: Operation not permitted`

**Root Cause:** Ubuntu 23.10+ enables `kernel.apparmor_restrict_unprivileged_userns=1` by default. This restricts unprivileged processes from using user namespaces with full capabilities unless they have an AppArmor profile with `userns,` permission.

**Solution:** Create an AppArmor profile for the binary:

```bash
sudo tee /etc/apparmor.d/n8 << 'EOF'
abi <abi/4.0>,
include <tunables/global>
profile n8 /path/to/n8 flags=(unconfined) {
  userns,
}
EOF
sudo apparmor_parser -r /etc/apparmor.d/n8
```

The `userns,` rule grants permission to create user namespaces with capabilities. The `flags=(unconfined)` allows all other operations.

#### Problem 3: /proc Mount Restriction

**Symptom:** After successful `pivot_root`, mounting `/proc` fails with `EPERM: Operation not permitted`

**Root Cause:** The kernel's `mount_too_revealing()` function in `fs/proc/root.c` blocks mounting proc in certain conditions. Even with `CAP_SYS_ADMIN` in the user namespace, mounting proc requires that:
1. The process has visibility into the PID namespace
2. The existing proc (if any) is "fully visible"
3. No locked mounts restrict the view

On Ubuntu 24.04+, additional kernel hardening prevents proc mounting in unprivileged user namespaces. This is separate from AppArmor—it's a kernel-level restriction.

**Current Status:** `/proc` mounting remains blocked. The namespace isolation is functional:
- Process is PID 1 in its namespace
- Cannot signal or interact with host processes
- Has its own mount namespace with tmpfs root

But `/proc` enumeration is unavailable.

### What Works Today

```
$ ./target/x86_64-unknown-linux-musl/release/n8

n8 - Self-Isolating Process Demo
================================

=== Before isolation (host view) ===
Visible processes: 397
  PID      1: systemd
  ...

Entering PID namespace...

Note: Failed to mount /proc: EPERM: Operation not permitted
This is a known limitation on Ubuntu 24.04+ due to kernel restrictions.
The PID namespace isolation is still functional.

=== After isolation ===
Our PID (getpid): 1

We are PID 1 in our namespace!

Namespace isolation is active:
  - User namespace: UID 0 (mapped from host user)
  - PID namespace: PID 1 (isolated process tree)
  - Mount namespace: Separate filesystem view
  - Root filesystem: Minimal tmpfs with pivot_root
```

### Requirements

1. **Static binary** — must be built with musl: `cargo build --release --target x86_64-unknown-linux-musl`
2. **AppArmor profile** — required on Ubuntu 23.10+ for the `userns,` permission

### Future Work

Potential approaches to achieve full `/proc` isolation:

1. **Kernel module or eBPF** — could intercept and filter `/proc` access
2. **FUSE-based /proc** — implement a userspace proc filesystem
3. **Wait for kernel changes** — the restrictions may be relaxed in future kernels
4. **Privileged helper** — a setuid binary that mounts `/proc` then drops privileges

For now, the implementation demonstrates the core concept: a self-isolating binary that creates its own namespace isolation without external container runtimes. The `/proc` visibility limitation doesn't affect the security properties—processes are still truly isolated—it only affects the process's ability to enumerate its own namespace.

### References

- [Ubuntu 23.10 restricted unprivileged user namespaces](https://ubuntu.com/blog/ubuntu-23-10-restricted-unprivileged-user-namespaces)
- [pivot_root(2) man page](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
- [Digging into Linux namespaces](https://blog.quarkslab.com/digging-into-linux-namespaces-part-2.html)
- [Towards unprivileged container builds](https://kinvolk.io/blog/2018/04/towards-unprivileged-container-builds/)
