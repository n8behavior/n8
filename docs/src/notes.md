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
