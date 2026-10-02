// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🔐 Offline validation uses startup's manual certificate loader.

use std::process::Command;

#[test]
fn cli_validate_loads_and_matches_manual_tls_without_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let first = rcgen::generate_simple_self_signed(vec!["validate.test".into()]).unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["validate.test".into()]).unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let config = dir.path().join("Pingclairfile");
    std::fs::write(&cert, first.cert.pem()).unwrap();
    std::fs::write(&key, other.signing_key.serialize_pem()).unwrap();
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = held.local_addr().unwrap().port();
    std::fs::write(&config, format!(
        "{{\n admin off\n http_port __PINGCLAIR_TEST_HTTP_PORT__\n}}\nhttps://validate.test:{port} {{\n tls {} {}\n respond hi\n}}\n",
        cert.display(), key.display()
    ).replace("__PINGCLAIR_TEST_HTTP_PORT__", &super::free_port().to_string())).unwrap();
    let invoke = |command| {
        Command::new(env!("CARGO_BIN_EXE_pingclair"))
            .arg(command)
            .arg(&config)
            .env("PINGCLAIR_TLS_STORE", dir.path().join("store"))
            .output()
            .unwrap()
    };
    let invalid = invoke("validate");
    assert!(
        !invalid.status.success(),
        "mismatched pair passed validation"
    );
    let error = "the private key does not match the certificate's public key";
    assert!(String::from_utf8_lossy(&invalid.stderr).contains(error));
    let startup = invoke("run");
    assert!(!startup.status.success());
    assert!(
        format!(
            "{}{}",
            String::from_utf8_lossy(&startup.stdout),
            String::from_utf8_lossy(&startup.stderr)
        )
        .contains(error)
    );
    std::fs::write(&key, first.signing_key.serialize_pem()).unwrap();
    assert!(
        invoke("validate").status.success(),
        "validation tried to bind the held port"
    );
    std::fs::write(&cert, "broken PEM").unwrap();
    assert!(!invoke("validate").status.success());
    std::fs::remove_file(&cert).unwrap();
    assert!(!invoke("validate").status.success());
}
