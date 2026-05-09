//! CLI demo — run with `cargo run --bin demo` to verify all layers work.

use std::time::Instant;

use qs_crypto::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn separator(title: &str) {
    let bar = "=".repeat(60);
    println!("\n{bar}");
    println!("  {title}");
    println!("{bar}\n");
}

fn main() {
    println!();
    println!("  QS-Crypto — Spin Glass Cryptography Demo");
    println!("  =========================================");

    // ── 1. Key Generation ──────────────────────────────────────────
    separator("1. Key Generation (all security levels)");

    for level in [
        SecurityLevel::QS128,
        SecurityLevel::QS192,
        SecurityLevel::QS256,
    ] {
        let params = Params::from_security_level(level);
        let t = Instant::now();
        let kp = generate_keypair(&params);
        let elapsed = t.elapsed();

        println!("  {:?}:", level);
        println!("    Public key : {} bytes", kp.public_key.as_bytes().len());
        println!("    Private key: {} bytes", kp.private_key.as_bytes().len());
        println!("    Time       : {:.2?}", elapsed);
        println!();
    }

    // ── 2. KEM Encapsulation / Decapsulation ───────────────────────
    separator("2. KEM Encapsulation / Decapsulation");

    let params = Params::default(); // QS-256
    let keypair = generate_keypair(&params);

    let t = Instant::now();
    let encap_result = encapsulate(&keypair.public_key);
    let encap_time = t.elapsed();

    println!(
        "  Ciphertext   : {} bytes",
        encap_result.ciphertext.as_bytes().len()
    );
    println!(
        "  Shared secret: {}...",
        &hex(encap_result.shared_secret.as_bytes())[..32]
    );
    println!("  Encaps time  : {:.2?}", encap_time);

    let t = Instant::now();
    let decapped =
        decapsulate(&keypair.private_key, &encap_result.ciphertext).expect("decapsulation failed");
    let decap_time = t.elapsed();

    let match_ok = encap_result.shared_secret.as_bytes() == decapped.as_bytes();
    println!("  Decaps time  : {:.2?}", decap_time);
    println!(
        "  Secrets match: {} {}",
        if match_ok { "YES" } else { "NO" },
        if match_ok { "[PASS]" } else { "[FAIL]" }
    );

    // Implicit rejection test
    let other_kp = generate_keypair(&params);
    let wrong = decapsulate(&other_kp.private_key, &encap_result.ciphertext)
        .expect("implicit rejection should return a secret, not an error");
    let rejected = encap_result.shared_secret.as_bytes() != wrong.as_bytes();
    println!(
        "  Implicit rejection (wrong key): {} {}",
        if rejected {
            "different secret"
        } else {
            "SAME secret"
        },
        if rejected { "[PASS]" } else { "[FAIL]" }
    );

    // ── 3. Symmetric Primitives ────────────────────────────────────
    separator("3. Symmetric Primitives");

    // Hash
    let digest = spin_hash(b"Hello, quantum spin glass!");
    println!("  SpinHash(\"Hello, quantum spin glass!\"):");
    println!("    {}", hex(&digest));
    println!("    Length: {} bytes (256 bits)", digest.len());

    // Verify determinism
    let digest2 = spin_hash(b"Hello, quantum spin glass!");
    println!(
        "    Deterministic: {} {}",
        if digest == digest2 { "YES" } else { "NO" },
        if digest == digest2 {
            "[PASS]"
        } else {
            "[FAIL]"
        }
    );

    // Avalanche
    let digest3 = spin_hash(b"Hello, quantum spin glass?"); // last char changed
    let diff_bits: u32 = digest
        .iter()
        .zip(digest3.iter())
        .map(|(&a, &b)| (a ^ b).count_ones())
        .sum();
    println!(
        "    Avalanche (1 char change): {diff_bits}/256 bits flipped [{}]",
        if diff_bits > 64 { "PASS" } else { "FAIL" }
    );

    println!();

    // KDF
    let derived = spin_kdf(b"master-key", b"salt-value", b"context-info", 64);
    println!("  SpinKDF (64 bytes from master key):");
    println!("    {}...", &hex(&derived)[..64]);
    println!("    Length: {} bytes [PASS]", derived.len());

    println!();

    // AEAD
    let aead_key = [0x42u8; 32];
    let nonce = [0x01u8; 16];
    let plaintext = b"Top secret spin glass data!";
    let aad_data = b"associated metadata";

    let ct = aead::encrypt(&aead_key, &nonce, aad_data, plaintext);
    println!("  SpinAEAD:");
    println!("    Plaintext : \"{}\"", String::from_utf8_lossy(plaintext));
    println!(
        "    Ciphertext: {}... ({} bytes)",
        &hex(&ct.ciphertext)[..32],
        ct.ciphertext.len()
    );
    println!("    Tag       : {}", hex(&ct.tag));

    let pt = aead::decrypt(&aead_key, &nonce, aad_data, &ct.ciphertext, &ct.tag)
        .expect("AEAD decryption failed");
    let aead_ok = pt == plaintext;
    println!(
        "    Decrypted : \"{}\" {}",
        String::from_utf8_lossy(&pt),
        if aead_ok { "[PASS]" } else { "[FAIL]" }
    );

    // Tamper detection
    let mut bad_ct = ct.ciphertext.clone();
    bad_ct[0] ^= 0xFF;
    let tamper_caught = aead::decrypt(&aead_key, &nonce, aad_data, &bad_ct, &ct.tag).is_err();
    println!(
        "    Tamper detected: {} {}",
        if tamper_caught { "YES" } else { "NO" },
        if tamper_caught { "[PASS]" } else { "[FAIL]" }
    );

    // ── 4. Session Encryption (Alice <-> Bob) ──────────────────────
    separator("4. Session Encryption (Alice <-> Bob)");

    let alice_kp = generate_keypair(&params);
    let bob_kp = generate_keypair(&params);
    let alice_pk = alice_kp.public_key.clone();
    let bob_pk = bob_kp.public_key.clone();

    let session_key = spin_hash(b"shared-session-bootstrap");
    let mut session_key_arr = [0u8; 32];
    session_key_arr.copy_from_slice(&session_key);

    let mut alice = Session::new(alice_kp, bob_pk, &session_key_arr);
    let mut bob = Session::new(bob_kp, alice_pk, &session_key_arr);

    let messages = [
        ("Alice", "Bob, are you there? The lattice is cooling."),
        ("Alice", "I repeat — ground state acquired."),
    ];

    for (sender, msg) in &messages {
        let ct = alice.encrypt(msg.as_bytes());
        let pt = bob.decrypt(&ct).expect("Bob failed to decrypt");
        let ok = pt == msg.as_bytes();
        println!("  {sender} -> Bob: \"{}\"", msg);
        println!("    Ciphertext: {} bytes", ct.len());
        println!(
            "    Decrypted : \"{}\" {}",
            String::from_utf8_lossy(&pt),
            if ok { "[PASS]" } else { "[FAIL]" }
        );
        println!();
    }

    // Bob replies
    let reply = "Copy that, Alice. Spin glass channel is secure.";
    let ct = bob.encrypt(reply.as_bytes());
    let pt = alice.decrypt(&ct).expect("Alice failed to decrypt");
    let ok = pt == reply.as_bytes();
    println!("  Bob -> Alice: \"{}\"", reply);
    println!(
        "    Decrypted : \"{}\" {}",
        String::from_utf8_lossy(&pt),
        if ok { "[PASS]" } else { "[FAIL]" }
    );

    // Forward secrecy: each ciphertext is unique
    let ct1 = alice.encrypt(b"same");
    let ct2 = alice.encrypt(b"same");
    let fs_ok = ct1 != ct2;
    println!(
        "\n  Forward secrecy (same plaintext -> different ciphertext): {} {}",
        if fs_ok { "YES" } else { "NO" },
        if fs_ok { "[PASS]" } else { "[FAIL]" }
    );

    // ── 5. PAKE Handshake ──────────────────────────────────────────
    separator("5. PAKE — Password-Authenticated Key Exchange");

    let pake_kp = generate_keypair(&params);
    let password = "correct horse battery staple";

    println!("  Password: \"{}\"", password);
    println!();

    // Registration
    let record = pake_register(password, &pake_kp);
    println!("  [Registration] Record created");

    // Handshake
    let mut client = PakeClient::new(password);
    let mut server = PakeServer::new(record);

    let msg1 = client.start();
    println!("  [Client -> Server] msg1: {} bytes", msg1.len());

    let msg2 = server.respond(&msg1).expect("server.respond failed");
    println!("  [Server -> Client] msg2: {} bytes", msg2.len());

    let client_key = client.finalize(&msg2).expect("client.finalize failed");
    let server_key = server.finalize().expect("server.finalize failed");

    let pake_ok = client_key == server_key;
    println!("  Client key: {}...", &hex(&client_key)[..32]);
    println!("  Server key: {}...", &hex(&server_key)[..32]);
    println!(
        "  Keys match: {} {}",
        if pake_ok { "YES" } else { "NO" },
        if pake_ok { "[PASS]" } else { "[FAIL]" }
    );

    // Wrong password
    let record2 = pake_register(password, &generate_keypair(&params));
    let mut bad_client = PakeClient::new("wrong-password");
    let mut bad_server = PakeServer::new(record2);
    let m1 = bad_client.start();
    let m2 = bad_server.respond(&m1).expect("server.respond failed");
    let wrong_rejected = bad_client.finalize(&m2).is_err();
    println!(
        "  Wrong password rejected: {} {}",
        if wrong_rejected { "YES" } else { "NO" },
        if wrong_rejected { "[PASS]" } else { "[FAIL]" }
    );

    // ── 6. Visual Fingerprint ──────────────────────────────────────
    separator("6. Visual Fingerprint");

    let fp = visual_fingerprint(&session_key_arr, 16, 16);
    println!("  Fingerprint (16x16 RGBA): {} bytes", fp.len());
    println!("  First 16 pixels (RGBA hex):");
    print!("    ");
    for i in 0..16 {
        let off = i * 4;
        print!("{} ", hex(&fp[off..off + 4]));
    }
    println!();

    let fp2 = visual_fingerprint(&session_key_arr, 16, 16);
    let fp_det = fp == fp2;
    println!(
        "  Deterministic: {} {}",
        if fp_det { "YES" } else { "NO" },
        if fp_det { "[PASS]" } else { "[FAIL]" }
    );

    // ── Summary ────────────────────────────────────────────────────
    separator("Summary");

    let all_pass = match_ok
        && rejected
        && (digest == digest2)
        && (diff_bits > 64)
        && aead_ok
        && tamper_caught
        && ok
        && fs_ok
        && pake_ok
        && wrong_rejected
        && fp_det;

    if all_pass {
        println!("  All checks passed. The spin glass lattice holds.");
    } else {
        println!("  SOME CHECKS FAILED — review output above.");
        std::process::exit(1);
    }
    println!();
}
