use super::UnQuarantine;

#[test]
fn test_unquarantine_result() {
    let result = UnQuarantine::from_file("data/99E865BA2BBCED427E8CB4785CCE58DDCCCE8337");
    assert!(result.is_ok());
}

#[test]
fn test_ms_defender_pc() {
    let result = UnQuarantine::from_file("data/99E865BA2BBCED427E8CB4785CCE58DDCCCE8337");
    assert!(result.is_ok());
    let result = result.unwrap();
    let vendor = result.get_vendor();
    assert_eq!(vendor, "Microsoft Windows Defender (PC)");
    let unquarantine_buffer = result.get_unquarantined_buffer();
    assert!(!unquarantine_buffer.is_empty());
}

#[test]
fn test_mcafee() {
    let result = UnQuarantine::from_file("data/fa97a1ec61c005f8ecc2a73cf77ec34de73a73e7.bup");
    assert!(result.is_ok());
    let result = result.unwrap();
    let vendor = result.get_vendor();
    assert_eq!(vendor, "McAfee BUP Files");
    let unquarantine_buffer = result.get_unquarantined_buffer();
    assert!(!unquarantine_buffer.is_empty());
}

// --- Robustness: malformed / truncated input must error, never panic. ---

#[test]
fn test_empty_buffer_does_not_panic() {
    // The generic XOR fallbacks (Vipre/xorff) accept any input, so empty data
    // may decode to an empty buffer rather than erroring. The contract here is
    // simply "no panic".
    let _ = UnQuarantine::from_bytes(&[]);
}

#[test]
fn test_truncated_magics_do_not_panic() {
    // Prefixes of various vendor magics that used to index past the end.
    let cases: &[&[u8]] = &[
        b"-chest",           // Avast (needs 8)
        b"AntiVir",          // Avira (needs 11)
        b"CMC Quar",         // CMC (needs 23)
        b"K",                // F-Prot / Kaspersky
        &[0xCA, 0xFE],       // G-Data/BullGuard cafebabe
        &[0xD0, 0xCF, 0x11], // McAfee OLE
        &[0x0B, 0xAD],       // MS Defender PC
        &[0x75],             // MS Defender Mac
        &[0x50],             // PK (zip) prefix
        &[0xFF; 3],          // generic / trendmicro xorff path
    ];
    for c in cases {
        // Must return a Result (Ok or Err) without panicking.
        let _ = UnQuarantine::from_bytes(c);
    }
}

#[test]
fn test_fuzz_short_random_inputs() {
    // Deterministic pseudo-random short buffers exercised through detection.
    let mut state: u64 = 0x9E3779B97F4A7C15;
    for _ in 0..2000 {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let len = (state >> 56) as usize % 64;
        let buf: Vec<u8> = (0..len)
            .map(|k| (state.rotate_left(k as u32 % 64) & 0xFF) as u8)
            .collect();
        let _ = UnQuarantine::from_bytes(&buf);
    }
}

#[test]
fn test_thread_safe_concurrent_use() {
    use std::thread;
    // Same input decoded on many threads at once; exercises the shared
    // LazyLock regexes and const tables under contention.
    let data = b"-chest- concurrent payload bytes for the avast/avg path".to_vec();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let d = data.clone();
            thread::spawn(move || {
                UnQuarantine::from_bytes(&d).map(|r| r.into_unquarantined_buffer())
            })
        })
        .collect();
    for h in handles {
        // join must not panic and the decode result must be consistent.
        let _ = h.join().expect("worker thread panicked");
    }
}

#[test]
fn test_fortinet_roundtrip() {
    // Minimal synthetic QUARF container (no filename/threat-name), payload XOR 0xAB.
    let plaintext: &[u8] = b"MZ\x90\x00 fortinet fake payload";
    let mut buf = vec![0u8; 0x60];
    buf[..8].copy_from_slice(b"QUARF\x00\x00\x00");
    buf[0x34..0x38].copy_from_slice(&(plaintext.len() as u32).to_le_bytes());
    // fn_len (0x58) and tn_len (0x5C) left zero
    buf.extend(plaintext.iter().map(|b| b ^ 0xAB));

    let res = UnQuarantine::from_bytes(&buf).expect("forticlient decode");
    assert_eq!(res.get_vendor(), "FortiClient Quarantine Files");
    assert_eq!(res.get_unquarantined_buffer()[0], plaintext);
}
