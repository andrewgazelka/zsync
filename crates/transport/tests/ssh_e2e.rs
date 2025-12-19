//! End-to-end SSH tests using testcontainers
//!
//! These tests spin up a real SSH server in Docker and test the full sync flow.
//! Run with: `cargo test --test ssh_e2e -- --ignored`
//!
//! Note: The LocalTransport tests are already covered in the library unit tests
//! (see `crates/transport/src/local.rs`). This file is reserved for Docker-based
//! SSH integration tests which require additional setup.

// Docker-based SSH tests are kept separate and ignored by default.
// They require Docker to be running and will be enabled once
// password authentication or SSH key setup is working with russh.
//
// To run: cargo test --test ssh_e2e -- --ignored
//
// Example SSH container test (for future implementation):
// ```rust
// use testcontainers::{GenericImage, ImageExt, runners::AsyncRunner};
// use testcontainers::core::{IntoContainerPort, WaitFor};
//
// #[tokio::test]
// #[ignore = "requires Docker"]
// async fn test_ssh_sync() {
//     let container = GenericImage::new("linuxserver/openssh-server", "latest")
//         .with_exposed_port(2222.tcp())
//         .with_wait_for(WaitFor::message_on_stdout("Server listening"))
//         .with_env_var("PASSWORD_ACCESS", "true")
//         .with_env_var("USER_PASSWORD", "testpass")
//         .with_env_var("USER_NAME", "testuser")
//         .start()
//         .await
//         .unwrap();
//
//     let port = container.get_host_port_ipv4(2222).await.unwrap();
//     // Connect and test...
// }
// ```

// Placeholder test to ensure the test file compiles
#[test]
fn test_placeholder() {
    // This is a placeholder. Real SSH E2E tests will be added when:
    // 1. Password auth is supported in russh, OR
    // 2. We set up SSH key-based auth in the container
}
