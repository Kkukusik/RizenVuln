use std::process::Command;

// Each probe has its own process environment, avoiding races between parallel tests.
fn probe(changes: &[(&str, Option<&str>)], expected: &str) {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--ignored", "--exact", "environment_probe", "--nocapture"])
        .env_clear()
        .env("ADMIN_EMAIL", "admin@example.test")
        .env("ADMIN_PASSWORD", "temporary-test-password")
        .env(
            "SESSION_SECRET",
            "temporary-test-session-secret-at-least-32",
        )
        .env("DATABASE_URL", "postgres://test@localhost/rvtest_probe")
        .env("EXPECTED", expected);
    for (k, v) in changes {
        if let Some(v) = v {
            cmd.env(k, v);
        } else {
            cmd.env_remove(k);
        }
    }
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "configuration probe failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[test]
#[ignore = "helper process; invoked by configuration_policy"]
fn environment_probe() {
    let Ok(expected) = std::env::var("EXPECTED") else {
        return;
    };
    let result = rizenvuln_config::Config::load();
    if expected == "ok" {
        let c = result.unwrap();
        assert!(!c.secure_cookie);
        assert_eq!(c.public_url, "http://localhost:8080");
    } else if expected == "https" {
        let c = result.unwrap();
        assert!(c.secure_cookie);
        assert_eq!(c.public_url, "https://monitor.example.test");
    } else if expected == "clamp" {
        let c = result.unwrap();
        assert_eq!(c.scan_interval, 3600);
        assert_eq!(c.concurrency, 8);
    } else {
        assert!(result.is_err(), "configuration should have been rejected");
    }
}
#[test]
fn configuration_policy() {
    probe(&[], "ok");
    probe(
        &[
            ("PUBLIC_BASE_URL", Some("https://monitor.example.test/path")),
            ("APP_ENV", Some("production")),
        ],
        "https",
    );
    probe(
        &[
            ("SCAN_INTERVAL_HOURS", Some("0")),
            ("MAX_CONCURRENT_SCANS", Some("99")),
        ],
        "clamp",
    );
    for key in [
        "ADMIN_EMAIL",
        "ADMIN_PASSWORD",
        "SESSION_SECRET",
        "DATABASE_URL",
    ] {
        probe(&[(key, None)], "error");
        probe(&[(key, Some("CHANGE_ME"))], "error");
    }
    for changes in [
        vec![("ADMIN_PASSWORD", Some("short"))],
        vec![("SESSION_SECRET", Some("short"))],
        vec![("APP_ENV", Some("production"))],
        vec![("PUBLIC_BASE_URL", Some("https://user:pass@example.test"))],
        vec![("PUBLIC_BASE_URL", Some("file:///etc/passwd"))],
        vec![("SCAN_INTERVAL_HOURS", Some("invalid"))],
    ] {
        probe(&changes, "error");
    }
    for flag in [
        "HARBOR_ENABLED",
        "S3_ENABLED",
        "TELEGRAM_ENABLED",
        "DOCKER_DISCOVERY_ENABLED",
        "KUBERNETES_ENABLED",
    ] {
        probe(&[(flag, Some("true"))], "error");
    }
}
