use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd};

use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{close, execve, fork, getgid, getuid, pipe, ForkResult, Pid};

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

fn get_self_exe() -> CString {
    let path = std::env::current_exe().expect("Failed to get current executable path");
    CString::new(path.to_str().expect("Path is not valid UTF-8")).expect("Path contains null byte")
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

            // Create user namespace, PID namespace, and mount namespace
            if let Err(e) = unshare(
                CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS,
            ) {
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
                    // Note: We skip remounting /proc for unprivileged execution.
                    // The PID namespace isolation is still real - getpid() returns 1.
                    // /proc still shows host view because we can't remount it without
                    // additional privileges. A full container runtime would use
                    // pivot_root with a prepared rootfs.

                    // Re-exec with isolation marker
                    let exe = get_self_exe();
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

fn main() {
    if std::env::var(N8_ISOLATED).is_ok() {
        // Inside PID namespace
        println!("\n=== After isolation ===");
        println!("Our PID (getpid): {}", std::process::id());
        println!();
        println!("We are PID 1 in our namespace!");
        println!();
        println!("Note: /proc still shows host processes because remounting");
        println!("it requires additional privileges (CAP_SYS_ADMIN in the");
        println!("mount namespace). But the PID namespace isolation is real:");
        println!("this process sees itself as PID 1, and cannot signal or");
        println!("interact with processes outside its namespace.");
    } else {
        // Pre-isolation
        println!("n8 - Self-Isolating Process Demo");
        println!("================================");

        print_processes("Before isolation (host view)");

        println!("Entering PID namespace...\n");

        isolate();
    }
}
