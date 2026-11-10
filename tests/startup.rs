//! Test startup protection before executable constructors/main, without Qt.
use std::os::unix::process::CommandExt;
use std::process::Command;

#[test]
fn preload_restores_exec_reset_protections_before_ui_initialization() {
    let directory = tempfile::tempdir().unwrap();
    let guard = directory.path().join("guard.so");
    let helper = directory.path().join("helper");
    let source = directory.path().join("helper.c");
    std::fs::write(
        &source,
        r#"
#include <dlfcn.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/resource.h>
__attribute__((constructor)) static void observe_startup(void) {
    struct rlimit core;
    if (getrlimit(RLIMIT_CORE, &core) != 0) _Exit(2);
    int (*ready)(void) = (int (*)(void))dlsym(RTLD_DEFAULT, "pinentry_startup_ready");
    printf("%d %d %d %d\n", prctl(PR_GET_DUMPABLE),
        prctl(PR_GET_NO_NEW_PRIVS, 0UL, 0UL, 0UL, 0UL),
        core.rlim_cur == 0 && core.rlim_max == 0, ready ? ready() : 0);
}
int main(void) { return 0; }
"#,
    )
    .unwrap();
    for arguments in [
        vec![
            "-std=c11".into(),
            "-shared".into(),
            "-fPIC".into(),
            concat!(env!("CARGO_MANIFEST_DIR"), "/native/startup.c").into(),
            "-o".into(),
            guard.clone().into_os_string(),
        ],
        vec![
            source.into_os_string(),
            "-ldl".into(),
            "-o".into(),
            helper.clone().into_os_string(),
        ],
    ] {
        assert!(
            Command::new("cc")
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }
    let mut baseline_command = Command::new(&helper);
    baseline_command.env_remove("LD_PRELOAD");
    // SAFETY: the child hook only calls prctl with integer arguments.
    unsafe {
        baseline_command.pre_exec(|| {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let baseline = baseline_command.output().unwrap();
    assert!(baseline.status.success());
    // An ordinary exec resets dumpability even when the launching parent is
    // non-dumpable. This is the loader interval that a preload cannot eliminate.
    assert!(baseline.stdout.starts_with(b"1 "));
    let guarded = Command::new(&helper)
        .env("LD_PRELOAD", &guard)
        .output()
        .unwrap();
    assert!(guarded.status.success());
    assert_eq!(guarded.stdout, b"0 1 1 1\n");
}
