# UnQuarantine

This tool attempts to do the following:
- UnQuarantine/decrypt/extract files from various AV / security products
- Log and metadata encrypted files from various AV companies/products
- Portable Executable files embedded in an encrypted form within
  other files (using encryption relying on a one-byte xor key).
  The decryption is generic and is based on the X-RAY algorithm.
---
 > Note: The tool scans directories recursively.

File types that dexray attempts to handle:
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
- Comodo <GUID> (not really; Quarantined files are not encrypted :)
- ESafe (VIR)
- ESET (NQF)
- F-Prot (TMP) (Magic@0='KSS')
- G-Data (Q) (Magic@0=0xCAFEBABE)
- K7 Antivirus (<md5>.QNT)
- Kaspersky (KLQ, System Watcher's <md5>.bin)
- Lavasoft AdAware (BDQ) /BitDefender files really/
- Lumension LEMSS (lqf)
- MalwareBytes Data files (DATA) - 2 versions
- MalwareBytes Quarantine files (QUAR) - 2 versions
- McAfee Quarantine files (BUP) /full support for OLE format/
- Microsoft Antimalware / Microsoft Security Essentials
- Microsoft Defender PC (Magic@0=0B AD|D3 45) - D3 45 C5 99 metadata + 0B AD malicious content
- Microsoft Defender Mac (Magic@0=75 6E)
- Panda <GUID> Zip files
- Sentinel One (MAL)
- Spybot - Search & Destroy 2 'recovery' 
- SUPERAntiSpyware (SDB) 
- Symantec ccSubSdk files: {GUID} files and submissions.idx
- Symantec Quarantine Data files (QBD)
- Symantec Quarantine files (VBN), including from SEP on Linux
- Symantec Quarantine Index files (QBI)
- Symantec Quarantine files on MAC (quarantine.qtn)
- Total AV ({GUID}.dat) 'infected'
- Total Defense (BDQ) /BitDefender files really/
- TrendMicro (Magic@0=A9 AC BD A7 which is a 'VSBX' string ^ 0xFF)
- QuickHeal <hash> files
- Vipre (<GUID>_ENC2)
- Zemana <hash> files+quarantine.db
- Any binary file (using X-RAY scanning)

## Usage

```rust
 use unquarantine::UnQuarantine;
 pub fn main() {
	 let result = UnQuarantine::from_file("data/99E865BA2BBCED427E8CB4785CCE58DDCCCE8337");
	 assert!(result.is_ok());
	 let result = result.unwrap();
	 let vendor = result.get_vendor();
	 assert_eq!(vendor, "Microsoft Windows Defender (PC)");
 }
 ```

---
Inspired by:
 - [Perl version](http://hexacorn.com/d/DeXRAY.pl)
 - [Python version](https://github.com/brad-accuvant/cuckoo-modified/blob/master/lib/cuckoo/common/quarantine.py)

Ported by: Marirs <marirs@gmail.com>