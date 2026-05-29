# UnQuarantine

Restore / decrypt / extract the original files that antivirus and security
products place into quarantine. Given a quarantined file (or its bytes), the
crate detects the producing vendor, reverses the obfuscation/encryption, and
returns the recovered file(s) along with the detected vendor name.

It also recovers Portable Executables embedded in an encrypted form within
other files using a generic one-byte-xor ("X-RAY") scan as a last resort.

- Pure Rust.
- Bounds-checked parsers: malformed or truncated input returns an error, never panics.
- Thread-safe (`Send + Sync`); safe to fan out across threads.
- Library + optional command-line binary.

## Supported formats

- AhnLab (V3B)
- Amiti (IFC)
- ASquared (EQF)
- Avast/AVG (Magic@0='-chest- ')
- Avira (QUA)
- Baidu (QV)
- BitDefender (BDQ)
- BullGuard (Q)
- Cisco AMP
- CMC Antivirus (CMC)
- Comodo &lt;GUID&gt; (not really; quarantined files are stored unencrypted)
- ESafe (VIR)
- ESET (NQF)
- F-Prot (TMP) (Magic@0='KSS')
- FortiClient (Magic@0='QUARF')
- G-Data (Q) (Magic@0=0xCAFEBABE)
- K7 Antivirus (&lt;md5&gt;.QNT)
- Kaspersky (KLQ, System Watcher's &lt;md5&gt;.bin)
- Lavasoft AdAware (BDQ) /BitDefender files really/
- Lumension LEMSS (lqf)
- MalwareBytes Data files (DATA) - 2 versions
- MalwareBytes Quarantine files (QUAR) - 2 versions
- McAfee Quarantine files (BUP) /full support for OLE format/
- Microsoft Antimalware / Microsoft Security Essentials
- Microsoft Defender PC (Magic@0=0B AD | D3 45)
- Microsoft Defender Mac (Magic@0=75 6E)
- Panda &lt;GUID&gt; Zip files
- Sentinel One (MAL)
- Spybot - Search &amp; Destroy 2 'recovery'
- SUPERAntiSpyware (SDB)
- Symantec ccSubSdk files: {GUID} files and submissions.idx
- Symantec Quarantine Data files (QBD)
- Symantec Quarantine files (VBN), including from SEP on Linux
- Symantec Quarantine Index files (QBI)
- Symantec Quarantine files on MAC (quarantine.qtn)
- Total AV ({GUID}.dat) 'infected'
- Total Defense (BDQ) /BitDefender files really/
- TrendMicro (Magic@0=A9 AC BD A7 which is a 'VSBX' string ^ 0xFF)
- QuickHeal &lt;hash&gt; files
- Vipre (&lt;GUID&gt;_ENC2)
- Zemana &lt;hash&gt; files + quarantine.db
- Any binary file (using X-RAY scanning)

## Library usage

```rust
use unquarantine::UnQuarantine;

fn main() {
    // From a path (uses both filename/extension and content for detection):
    let result = UnQuarantine::from_file("data/99E865BA2BBCED427E8CB4785CCE58DDCCCE8337")
        .expect("not a recognised quarantine file");

    println!("detected: {}", result.get_vendor());

    // Borrow the restored buffer(s) without copying:
    for buf in result.get_unquarantined_buffer() {
        println!("recovered {} bytes", buf.len());
    }

    // Or take ownership of the bytes:
    let buffers = result.into_unquarantined_buffer();
    let _ = buffers;
}
```

Working from an in-memory buffer (content/magic-based detection only):

```rust
use unquarantine::UnQuarantine;

let bytes = std::fs::read("some.bup").unwrap();
if let Ok(result) = UnQuarantine::from_bytes(&bytes) {
    println!("detected: {}", result.get_vendor());
}
```

## Command-line tool

The CLI lives behind the `cli` feature (so library consumers don't pull in
`clap`):

```bash
cargo build --release --features cli
./target/release/unquarantine <FILE>... [-o OUTDIR]
```

For each input it prints the detected vendor and writes every recovered item.
**Restored files always get a trailing `_`** in their name
(`<filename>.NN_`) so a recovered — potentially malicious — sample cannot be
executed by an accidental double-click.

```
$ unquarantine fa97a1ec61c005f8ecc2a73cf77ec34de73a73e7.bup -o ./restored
[+] fa97a1ec...bup: detected McAfee BUP Files (2 item(s))
    -> ./restored/fa97a1ec...bup.00_ (218016 bytes)
    -> ./restored/fa97a1ec...bup.01_ (96 bytes)
```

---
Inspired by:
- [Perl version (DeXRAY)](http://hexacorn.com/d/DeXRAY.pl)
- [Python version](https://github.com/brad-accuvant/cuckoo-modified/blob/master/lib/cuckoo/common/quarantine.py)

Ported by: Marirs &lt;marirs@gmail.com&gt;
