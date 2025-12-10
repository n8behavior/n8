# Vision

## What Are Containers, Really?

When people talk about "containers," they often think of Docker, Podman, or Kubernetes—tools that feel like lightweight virtual machines. But containers aren't a single technology. They're a collection of Linux kernel features working together to create isolated environments:

- **Namespaces** isolate what a process can *see* (its own process tree, network interfaces, filesystem mounts, hostname)
- **Cgroups** limit what a process can *use* (CPU, memory, I/O bandwidth)
- **Seccomp** restricts what a process can *do* (which system calls it's allowed to make)
- **Capabilities** provide fine-grained permissions (instead of all-or-nothing root access)

These primitives have been in the Linux kernel for years. Docker didn't invent them—it made them accessible.

## The Problem: Isolation as an Afterthought

Today's container model treats isolation as something *external* to a program. You write your application, then wrap it in a container image, then run it through a container runtime (Docker, containerd, runc, Podman) that sets up the isolation on your behalf.

This works, but it has consequences:

**Dependency on external tooling.** Your program can't run in isolation without a runtime installed. The runtime becomes a hard dependency, and different runtimes have different behaviors.

**Opacity.** The isolation configuration lives in Dockerfiles, Kubernetes manifests, or runtime flags—separate from the program itself. Understanding how a program *should* be isolated requires reading external artifacts.

**Indirection.** There's a gap between "what the program needs" and "what isolation it gets." The developer knows the program only needs network access on port 443 and read-only filesystem access, but that knowledge doesn't travel with the binary.

## The Idea: Intrinsic Isolation

What if isolation wasn't bolted on, but *built in*?

Imagine a program that knows how it should be isolated—what namespaces it needs, what syscalls it uses, what resources it requires—and applies that isolation *itself* at startup. No external runtime. No container daemon. Just a binary that creates its own sandbox using the kernel primitives directly.

This is **intrinsic isolation**: the program carries its isolation requirements as an inherent property, not an external configuration.

When the program starts:
1. It checks whether it's already isolated
2. If not, it creates the necessary namespaces, applies seccomp filters, sets resource limits
3. Then it forks into the isolated environment and runs normally

The isolation configuration is defined at compile time, embedded in the binary, and executed at runtime. The program doesn't need Docker. It doesn't need Podman. It just needs Linux.

## Core Principles

**No external runtime dependencies.** A self-isolating program should run on any Linux system with the appropriate kernel features. No daemons, no container engines, no orchestrators required.

**Declarative isolation.** The isolation requirements should be expressed clearly in code—what namespaces, what syscall filters, what resource limits—not scattered across external configuration files.

**Direct kernel integration.** Instead of going through abstraction layers, the program uses kernel primitives directly: `unshare()`, `clone()`, `seccomp()`, cgroup filesystem writes.

**Inspectable by design.** The isolation configuration should be discoverable—whether by developers, operators, or automated systems—by examining the program itself.

## What This Enables

Self-isolating programs open up new possibilities:

- **Simpler deployment.** Ship a single binary that runs securely anywhere Linux runs.
- **Tighter security.** The program author knows exactly what the program needs; that knowledge can be enforced at the kernel level.
- **Better tooling.** If isolation requirements are embedded in binaries with a standard format, tools can inspect, validate, and reason about them automatically.
- **Reduced attack surface.** No container daemon means no container daemon vulnerabilities.

This isn't about replacing Kubernetes or Docker for complex orchestration scenarios. It's about giving individual programs the ability to be secure by default, without external dependencies.
