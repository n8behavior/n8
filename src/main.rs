use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};

use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, close, execve, fork, getgid, getuid, pipe, pivot_root, ForkResult, Pid};

const N8_ISOLATED: &str = "N8_ISOLATED";

fn list_processes() -> Vec<(u32, String)> {
    let mut processes = Vec::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if let Ok(pid) = name_str.parse::<u32>() {
                let comm_path = format!("/proc/{}/comm", pid);
                if let Ok(comm) = fs::read_to_string(&comm_path) {
                    processes.push((pid, comm.trim().to_string()));
                }
            }
        }
    }

    processes.sort_by_key(|(pid, _)| *pid);
    processes
}

fn print_processes(label: &str) {
    println!("\n=== {} ===", label);
    let processes = list_processes();
    println!("Visible processes: {}", processes.len());
    for (pid, name) in &processes {
        println!("  PID {:>6}: {}", pid, name);
    }
    println!();
}

/// Check if the current executable is statically linked.
/// Returns true if static (no dynamic linker), false if dynamic.
fn is_static_binary() -> bool {
    if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
        // Dynamic binaries have the dynamic linker mapped
        !maps.contains("ld-linux") && !maps.contains("ld-musl")
    } else {
        // If we can't read maps, assume static (conservative)
        true
    }
}

/// Set up a minimal tmpfs rootfs and pivot into it.
/// This enables proper /proc isolation by following the pivot_root requirements:
/// 1. Make root mount private (required - propagation must not be MS_SHARED)
/// 2. Create and mount tmpfs at a temporary location
/// 3. Bind mount it to itself (makes it a mount point, required by pivot_root)
/// 4. Copy the static binary and create /proc mount point
/// 5. Create put_old directory for the old root
/// 6. pivot_root to switch roots
/// 7. Unmount and remove the old root
/// 8. Mount fresh /proc
fn setup_pivot_root() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let pid = std::process::id();
    let new_root = format!("/tmp/n8-root-{}", pid);

    // Step 1: Make the entire mount tree private
    // pivot_root requires that propagation type is not MS_SHARED
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| format!("Failed to make root private: {}", e))?;

    // Step 2: Create the new root directory
    fs::create_dir_all(&new_root)
        .map_err(|e| format!("Failed to create new root dir: {}", e))?;

    // Step 3: Mount tmpfs on the new root
    mount(
        Some("tmpfs"),
        new_root.as_str(),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=10m,mode=755"),
    )
    .map_err(|e| format!("Failed to mount tmpfs: {}", e))?;

    // Step 4: Create /proc mount point in new root
    let new_proc = format!("{}/proc", new_root);
    fs::create_dir(&new_proc).map_err(|e| format!("Failed to create /proc dir: {}", e))?;

    // Step 5: Copy the static binary into the new root
    let exe_path =
        std::env::current_exe().map_err(|e| format!("Failed to get current exe: {}", e))?;
    let new_exe = format!("{}/n8", new_root);
    fs::copy(&exe_path, &new_exe).map_err(|e| format!("Failed to copy binary: {}", e))?;
    fs::set_permissions(&new_exe, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("Failed to set binary permissions: {}", e))?;

    // Step 6: Create put_old directory for pivot_root
    // put_old must be at or underneath new_root
    let put_old = format!("{}/old_root", new_root);
    fs::create_dir(&put_old).map_err(|e| format!("Failed to create old_root dir: {}", e))?;

    // Step 7: Change to new root directory
    chdir(new_root.as_str()).map_err(|e| format!("Failed to chdir to new root: {}", e))?;

    // Step 8: Perform pivot_root
    // new_root becomes "/" and old root is moved to put_old
    pivot_root(".", "old_root").map_err(|e| format!("pivot_root failed: {}", e))?;

    // Step 9: Change to new root after pivot
    chdir("/").map_err(|e| format!("Failed to chdir to /: {}", e))?;

    // Step 10: Unmount old root (lazy unmount since it may have busy references)
    umount2("/old_root", MntFlags::MNT_DETACH)
        .map_err(|e| format!("Failed to unmount old root: {}", e))?;

    // Step 11: Remove the old_root directory
    fs::remove_dir("/old_root").map_err(|e| format!("Failed to remove old_root: {}", e))?;

    // Note: We defer /proc mounting to after execve
    // This ensures we're properly PID 1 in the namespace
    Ok(())
}

fn write_uid_gid_mappings(pid: Pid, uid: u32, gid: u32) -> std::io::Result<()> {
    // Write UID mapping: map current uid to root (0) inside namespace
    let uid_map = format!("0 {} 1\n", uid);
    fs::write(format!("/proc/{}/uid_map", pid), uid_map)?;

    // Disable setgroups (required before writing gid_map as unprivileged user)
    fs::write(format!("/proc/{}/setgroups", pid), "deny\n")?;

    // Write GID mapping: map current gid to root (0) inside namespace
    let gid_map = format!("0 {} 1\n", gid);
    fs::write(format!("/proc/{}/gid_map", pid), gid_map)?;

    Ok(())
}

fn isolate() -> ! {
    // Capture uid/gid before entering user namespace
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();

    // Two pipes for bidirectional sync:
    // 1. child_ready: child signals parent after unshare()
    // 2. mappings_done: parent signals child after writing mappings
    let (child_ready_read, child_ready_write) = pipe().expect("Failed to create pipe");
    let (mappings_done_read, mappings_done_write) = pipe().expect("Failed to create pipe");

    // Fork first - parent stays in original namespace, child will unshare
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            // Parent: close unused ends
            close(child_ready_write).ok();
            close(mappings_done_read).ok();

            // Wait for child to signal it has unshared
            let mut ready_file =
                unsafe { std::fs::File::from_raw_fd(child_ready_read.as_raw_fd()) };
            let mut buf = [0u8; 1];
            if ready_file.read_exact(&mut buf).is_err() {
                eprintln!("Child failed before signaling ready");
                std::process::exit(1);
            }
            drop(ready_file);

            // Now child is in new user namespace, set up uid/gid mappings
            if let Err(e) = write_uid_gid_mappings(child, uid, gid) {
                eprintln!("Failed to write uid/gid mappings: {}", e);
                std::process::exit(1);
            }

            // Signal child that mappings are ready
            let mut done_file =
                unsafe { std::fs::File::from_raw_fd(mappings_done_write.as_raw_fd()) };
            done_file.write_all(b"x").ok();
            drop(done_file);

            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, code)) => std::process::exit(code),
                Ok(_) => std::process::exit(1),
                Err(e) => {
                    eprintln!("waitpid failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Ok(ForkResult::Child) => {
            // Child: close unused ends
            close(child_ready_read).ok();
            close(mappings_done_write).ok();

            // Create user namespace and PID namespace
            // Mount namespace will be created later in the grandchild, after UID/GID
            // mappings are set up, so it will be properly owned by the user namespace
            if let Err(e) = unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID) {
                eprintln!("Failed to unshare: {}", e);
                if e == nix::errno::Errno::EPERM {
                    eprintln!("Hint: Unprivileged user namespaces may be disabled.");
                    eprintln!("Try: sudo sysctl kernel.unprivileged_userns_clone=1");
                }
                std::process::exit(1);
            }

            // Signal parent that we've unshared
            let mut ready_file =
                unsafe { std::fs::File::from_raw_fd(child_ready_write.as_raw_fd()) };
            ready_file.write_all(b"x").ok();
            drop(ready_file);

            // Wait for parent to set up mappings
            let mut done_file =
                unsafe { std::fs::File::from_raw_fd(mappings_done_read.as_raw_fd()) };
            let mut buf = [0u8; 1];
            done_file.read_exact(&mut buf).ok();
            drop(done_file);

            // Fork again - grandchild enters PID namespace as PID 1
            match unsafe { fork() } {
                Ok(ForkResult::Parent { child: grandchild }) => {
                    match waitpid(grandchild, None) {
                        Ok(WaitStatus::Exited(_, code)) => std::process::exit(code),
                        Ok(_) => std::process::exit(1),
                        Err(e) => {
                            eprintln!("waitpid failed: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
                Ok(ForkResult::Child) => {
                    // Grandchild: now PID 1 in new PID namespace

                    // Create mount namespace here, after UID/GID mappings are set up
                    // This ensures the mount namespace is owned by the properly
                    // initialized user namespace with full capabilities
                    if let Err(e) = unshare(CloneFlags::CLONE_NEWNS) {
                        eprintln!("Failed to create mount namespace: {}", e);
                        if e == nix::errno::Errno::EPERM {
                            eprintln!();
                            eprintln!("This may be caused by Ubuntu's AppArmor restrictions.");
                            eprintln!("To allow this binary to use user namespaces, create an AppArmor profile:");
                            eprintln!();
                            eprintln!("  sudo tee /etc/apparmor.d/n8 << 'EOF'");
                            eprintln!("  abi <abi/4.0>,");
                            eprintln!("  include <tunables/global>");
                            eprintln!("  profile n8 /path/to/n8 flags=(unconfined) {{");
                            eprintln!("    userns,");
                            eprintln!("  }}");
                            eprintln!("  EOF");
                            eprintln!();
                            eprintln!("  sudo apparmor_parser -r /etc/apparmor.d/n8");
                        }
                        std::process::exit(1);
                    }

                    // Require static binary for pivot_root approach
                    if !is_static_binary() {
                        eprintln!("Error: Dynamic binary detected. /proc isolation requires static linking.");
                        eprintln!("Build with: cargo build --release --target x86_64-unknown-linux-musl");
                        std::process::exit(1);
                    }

                    // Set up minimal rootfs with pivot_root for proper /proc isolation
                    if let Err(e) = setup_pivot_root() {
                        eprintln!("Failed to set up pivot_root: {}", e);
                        std::process::exit(1);
                    }

                    // Re-exec from new location with isolation marker
                    // After pivot_root, our binary is at /n8
                    let exe = CString::new("/n8").unwrap();
                    let args: [CString; 1] = [exe.clone()];
                    let env: [CString; 1] =
                        [CString::new(format!("{}=1", N8_ISOLATED)).unwrap()];

                    let Err(e) = execve(&exe, &args, &env);
                    eprintln!("Failed to exec: {}", e);
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Fork (inner) failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("Fork failed: {}", e);
            std::process::exit(1);
        }
    }
}

/// Mount /proc for the isolated namespace
fn mount_proc() -> Result<(), String> {
    mount(
        Some("proc"),
        "/proc",
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(|e| format!("Failed to mount /proc: {}", e))
}

fn main() {
    if std::env::var(N8_ISOLATED).is_ok() {
        // Inside PID namespace - now mount /proc
        let proc_mounted = match mount_proc() {
            Ok(()) => true,
            Err(e) => {
                eprintln!("Note: {}", e);
                eprintln!("This is a known limitation on Ubuntu 24.04+ due to kernel restrictions.");
                eprintln!("The PID namespace isolation is still functional.\n");
                false
            }
        };

        println!("=== After isolation ===");
        println!("Our PID (getpid): {}", std::process::id());
        println!();
        println!("We are PID 1 in our namespace!");

        if proc_mounted {
            // Show /proc isolation is working
            print_processes("Isolated /proc view");
            println!("Full isolation achieved: /proc shows only this namespace's processes.");
        } else {
            println!();
            println!("Namespace isolation is active:");
            println!("  - User namespace: UID 0 (mapped from host user)");
            println!("  - PID namespace: PID 1 (isolated process tree)");
            println!("  - Mount namespace: Separate filesystem view");
            println!("  - Root filesystem: Minimal tmpfs with pivot_root");
        }
    } else {
        // Pre-isolation
        println!("n8 - Self-Isolating Process Demo");
        println!("================================");

        print_processes("Before isolation (host view)");

        println!("Entering PID namespace...\n");

        isolate();
    }
}
