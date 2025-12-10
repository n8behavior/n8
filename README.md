# n8

Intrinsic isolation for self-containerizing programs.

## What is this?

A Rust program that isolates itself at startup using Linux kernel primitives (namespaces, seccomp, cgroups) — no Docker, no Podman, no container runtime required.

The isolation requirements are intrinsic to the program, not bolted on externally.

## Status

Early proof-of-concept. Currently demonstrates:
- Self-isolation into PID namespace
- Unprivileged operation via user namespaces (no root required)
- Two-fork pattern with UID/GID mapping

## Build & Run

```bash
cargo build
./target/debug/n8
```

## Documentation

```bash
cd docs && mdbook serve
```

See [docs/src/vision.md](docs/src/vision.md) for the project vision and [docs/src/architecture.md](docs/src/architecture.md) for technical details.

## License

MIT
