// Inspired by:
// - http://hexacorn.com/d/DeXRAY.pl
// - https://github.com/brad-accuvant/cuckoo-modified/blob/master/lib/cuckoo/common/quarantine.py
#[macro_use]
extern crate lazy_static;

mod patterns;
mod utils;
mod vendors;

#[cfg(test)]
mod tests;

pub mod error;
pub type Result<T> = std::result::Result<T, Error>;

use patterns::*;
use std::{ffi::OsStr, path::Path};
use crate::error::Error;

/// This crate attempts to decrypt/restore/un-quarantine files from various AV / security products.
/// When successful - it returns the Vendor String and the file buffer.
/// The below is a comprehensive list of vendors it tries to restore quarantined files!
/// * AhnLab (V3B)
/// * Amiti (IFC)
/// * ASquared (EQF)
/// * Avast/AVG (Magic@0='-chest- ')
/// * Avira (QUA)
/// * Baidu (QV)
/// * BitDefender (BDQ)
/// * BullGuard (Q)
/// * Cisco AMP
/// * CMC Antivirus (CMC)
/// * ESafe (VIR)
/// * ESET (NQF)
/// * F-Prot (TMP) (Magic@0='KSS')
/// * G-Data (Q) (Magic@0=0xCAFEBABE)
/// * K7 Antivirus (<md5>.QNT)
/// * Kaspersky (KLQ, System Watcher's <md5>.bin)
/// * Lavasoft AdAware (BDQ) /BitDefender files really/
/// * Lumension LEMSS (lqf)
/// * MalwareBytes Data files (DATA) - 2 versions
/// * MalwareBytes Quarantine files (QUAR) - 2 versions
/// * McAfee Quarantine files (BUP) /full support for OLE format/
/// * Microsoft Antimalware / Microsoft Security Essentials
/// * Microsoft Defender PC (Magic@0=0B AD|D3 45) - D3 45 C5 99 metadata + 0B AD malicious content
/// * Microsoft Defender Mac (Magic@0=75 6E)
/// * Panda <GUID> Zip files
/// * Sentinel One (MAL)
/// * Spybot - Search & Destroy 2 'recovery'
/// * SUPERAntiSpyware (SDB)
/// * Symantec ccSubSdk files: {GUID} files and submissions.idx
/// * Symantec Quarantine Data files (QBD)
/// * Symantec Quarantine files (VBN), including from SEP on Linux
/// * Symantec Quarantine Index files (QBI)
/// * Symantec Quarantine files on MAC (quarantine.qtn)
/// * Total AV ({GUID}.dat) 'infected'
/// * Total Defense (BDQ) /BitDefender files really/
/// * TrendMicro (Magic@0=A9 AC BD A7 which is a 'VSBX' string ^ 0xFF)
/// * QuickHeal <hash> files
/// * Vipre (<GUID>_ENC2)
/// * Zemana <hash> files+quarantine.db
#[derive(Clone)]
pub struct UnQuarantine<'a> {
    /// The detected Vendor of the quarantined file
    vendor: &'a str,
    /// The buffer to save as restored file
    unquarantined_buffer: Vec<Vec<u8>>,
}

impl<'a> UnQuarantine<'a> {
    pub fn from_file(qf: &str) -> Result<Self> {
        //! Unquarantine a given quarantined file into its original file
        //!
        //! ## Example Usage
        //! ```rust
        //! use unquarantine::UnQuarantine;
        //!
        //! let result = UnQuarantine::from_file("data/99E865BA2BBCED427E8CB4785CCE58DDCCCE8337");
        //! assert!(result.is_ok());
        //! ```
        let file_extension = Path::new(qf)
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        let data = utils::read_file(&qf)?;

        // Start of Checks
        if file_extension == "v3b" || data[..16] == b"AhnLab Inc. 2006"[..] {
            return Ok(Self {
                vendor: "AhnLab V3B files",
                unquarantined_buffer: vendors::ahnlab::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("eqf") {
            return Ok(Self {
                vendor: "ASquared EQF Files",
                unquarantined_buffer: vendors::asquared::unquarantine(&data)?,
            });
        }
        if data[..8] == b"-chest- "[..] {
            return Ok(Self {
                vendor: "Avast/AVG chest files",
                unquarantined_buffer: vendors::avast::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("qua") || data[..11] == b"AntiVir Qua"[..] {
            return Ok(Self {
                vendor: "Avira QUA Files",
                unquarantined_buffer: vendors::avira::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("qv") {
            return Ok(Self {
                vendor: "Baidu QV Files",
                unquarantined_buffer: vendors::baidu::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("bdq") {
            return Ok(Self {
                vendor: "BitDefender/Lavasoft AdAware/Total Defence: BDQ Files",
                unquarantined_buffer: vendors::bitdefender::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("q") && data[..4] == vec![0xCA, 0xFE, 0xBA, 0xBE] {
            let newdata = vendors::gdata::unquarantine(&data);
            return match newdata {
                Err(_) => Ok(Self {
                    vendor: "BullGuard Q Files",
                    unquarantined_buffer: vendors::bullguard::unquarantine(&data)?,
                }),
                Ok(s) => Ok(Self {
                    vendor: "G-Data Q Files",
                    unquarantined_buffer: s,
                }),
            };
        }
        if file_extension.to_lowercase().starts_with("qrt") {
            return Ok(Self {
                vendor: "Cisco AMP",
                unquarantined_buffer: vendors::cisco::amp_unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("cmc")
            && data[..23] == b"CMC Quarantined Malware"[..]
        {
            return Ok(Self {
                vendor: "CMC Antivirus CMC Files",
                unquarantined_buffer: vendors::cmc::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("vir") {
            return Ok(Self {
                vendor: "ESafe VIR Files",
                unquarantined_buffer: vendors::esafe::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("ifc") {
            return Ok(Self {
                vendor: "Amiti IFC Files",
                unquarantined_buffer: vendors::amiti::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("nqf") {
            return Ok(Self {
                vendor: "ESET NQF Files",
                unquarantined_buffer: vendors::eset::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("tmp") || data[..3] == b"KSS"[..] {
            return Ok(Self {
                vendor: "F-Prot TMP Files",
                unquarantined_buffer: vendors::fprot::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("klq") || data[..4] == b"KLQB"[..] {
            return Ok(Self {
                vendor: "Kaspersky KLQ files",
                unquarantined_buffer: vendors::kaspersky::av_unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("QNT") {
            return Ok(Self {
                vendor: "K7 QNT files",
                unquarantined_buffer: vendors::k7::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("bin") {
            return Ok(Self {
                vendor: "Kaspersky System Watcher files",
                unquarantined_buffer: vendors::kaspersky::system_watcher_unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("lqf") {
            return Ok(Self {
                vendor: "Lumension LEMSS",
                unquarantined_buffer: vendors::lumension::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("quar")
            || file_extension.eq_ignore_ascii_case("data")
            || qf.to_lowercase().ends_with("data")
        {
            return Ok(Self {
                vendor: "MalwareBytes DATA and QUAR Files",
                unquarantined_buffer: vendors::malwarebytes::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("bup")
            && data[..8] == vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
        {
            return Ok(Self {
                vendor: "McAfee BUP Files",
                unquarantined_buffer: vendors::mcafee::unquarantine(qf)?,
            });
        }
        if MSE_PATTERN.is_match(qf) {
            return Ok(Self {
                vendor: "Microsoft Antimalware / Microsoft Security Essentials",
                unquarantined_buffer: vendors::microsoft::antimalware_unquarantine(&data)?,
            });
        }
        if DEFAULT_FILE_PATTERN.is_match(qf) && data[..2] == vec![0x75, 0x6E] {
            return Ok(Self {
                vendor: "Microsoft Defender MAC",
                unquarantined_buffer: vendors::microsoft::mac_unquarantine(&data)?,
            });
        }
        if data[..2] == vec![0xD3, 0x45] || data[..2] == vec![0x0B, 0xAD] {
            return Ok(Self {
                vendor: "Microsoft Defender PC - partially supported (D3 45 C5 99 header)",
                unquarantined_buffer: vendors::microsoft::pc_unquarantine(&data)?,
            });
        }
        if DEFAULT_FILE_PATTERN.is_match(qf) && data[..2] == b"PK"[..] {
            return Ok(Self {
                vendor: "Panda <GUID> Zip Files",
                unquarantined_buffer: vendors::panda::unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("mal") {
            return Ok(Self {
                vendor: "Sentinel One MAL files",
                unquarantined_buffer: vendors::sentinelone::unquarantine(&data)?,
            });
        }
        if NUM_PATTERN.is_match(qf) && data[..2] == b"PK"[..] {
            if GUID_DAT_PATTERN.is_match(qf) && data[..2] == b"PK"[..] {
                return Ok(Self {
                    vendor: "Total AV {GUID}.dat",
                    unquarantined_buffer: vendors::others::zip_unquarantine(&data, Some(b"infected"))?,
                });
            }
            return Ok(Self {
                vendor: "Spybot - Search & Destroy 2 Zip Files",
                unquarantined_buffer: vendors::others::zip_unquarantine(&data, Some(b"recovery"))?,
            });
        }
        if file_extension.eq_ignore_ascii_case("sdb") {
            return Ok(Self {
                vendor: "SUPERAntiSpyware (SDB)",
                unquarantined_buffer: vendors::others::data_unquarantine(&data, 0xED)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("qbd") || file_extension.eq_ignore_ascii_case("qbi")
        {
            return Ok(Self {
                vendor: "Symantec QBD and QBI Files",
                unquarantined_buffer: vendors::symantec::qbd_unquarantine(&data)?,
            });
        }
        if GUID_PATTERN.is_match(qf) {
            return Ok(Self {
                vendor: "Symantec ccSubSDK {GUID} Files",
                unquarantined_buffer: vendors::symantec::cc_sub_sdk_unquarantine(&data)?,
            });
        }
        if qf.to_ascii_lowercase().ends_with("submissions.idx") {
            return Ok(Self {
                vendor: "Symantec ccSubSDK submissions.idx Files",
                unquarantined_buffer: vendors::symantec::idx_unquarantine(&data)?,
            });
        }
        if qf.eq_ignore_ascii_case("quarantine.qtn") && data[..2] == b"PK"[..] {
            return Ok(Self {
                vendor: "Symantec quarantine.qtn",
                unquarantined_buffer: vendors::symantec::qtn_unquarantine(&data)?,
            });
        }
        if file_extension.eq_ignore_ascii_case("vbn") {
            return Ok(Self {
                vendor: "Symantec VBN Files",
                unquarantined_buffer: vendors::symantec::ep_unquarantine(&data)?,
            });
        }
        if utils::unpack_i32(&data)? == 0x58425356 {
            return Ok(Self {
                vendor: "TrendMicro VSBX files",
                unquarantined_buffer: vendors::trendmicro::unquarantine(&data)?,
            });
        }
        if QDB_PATTERN.is_match(qf) {
            if qf.eq_ignore_ascii_case("quarantine.db") {
                return Ok(Self {
                    vendor: "QuickHeal Files",
                    unquarantined_buffer: vendors::quickheal::unquarantine(&data)?,
                });
            }
            return Ok(Self {
                vendor: "Zemana Files",
                unquarantined_buffer: vendors::zemana::unquarantine(&data)?,
            });
        }

        if let Ok(s) = vendors::kaspersky::av_unquarantine(&data) {
            return Ok(Self {
                vendor: "Kaspersky Antivirus",
                unquarantined_buffer: s,
            });
        }
        if let Ok(s) = vendors::trendmicro::unquarantine(&data) {
            return Ok(Self {
                vendor: "TrendMicro",
                unquarantined_buffer: s,
            });
        }
        if let Ok(s) = vendors::symantec::ep_unquarantine(&data) {
            return Ok(Self {
                vendor: "Symantec Endpoint",
                unquarantined_buffer: s,
            });
        }
        if let Ok(s) = vendors::microsoft::pc_unquarantine(&data) {
            return Ok(Self {
                vendor: "Microsoft Windows Defender (PC)",
                unquarantined_buffer: s,
            });
        }
        if let Ok(s) = vendors::vipre::unquarantine(&data) {
            return Ok(Self {
                vendor: "Vipre <GUID>_ENC2 Files",
                unquarantined_buffer: s,
            });
        }
        if let Ok(s) = vendors::others::xorff_unquarantine(&data) {
            return Ok(Self {
                vendor: "Generic xorff",
                unquarantined_buffer: s,
            });
        }

        Err(Error::CannotUnQuarantineFile(qf.to_string()))
    }
    
    pub fn get_vendor(&self) -> &str {
        //! Gets the Vendor String of the Quarantined File
        //!
        //! ## Example Usage
        //! ```rust
        //! use unquarantine::UnQuarantine;
        //!
        //! let result = UnQuarantine::from_file("data/99E865BA2BBCED427E8CB4785CCE58DDCCCE8337");
        //! assert!(result.is_ok());
        //! let result = result.unwrap();
        //! let vendor = result.get_vendor();
        //! assert_eq!(vendor, "Microsoft Windows Defender (PC)");
        //! ```
        self.vendor
    }

    pub fn get_unquarantined_buffer(&self) -> Vec<Vec<u8>> {
        //! Gets the UnQuarantined Buffer for the quarantined file
        //!
        //! ## Example Usage
        //! ```rust
        //! use unquarantine::UnQuarantine;
        //!
        //! let result = UnQuarantine::from_file("data/99E865BA2BBCED427E8CB4785CCE58DDCCCE8337");
        //! assert!(result.is_ok());
        //! let result = result.unwrap();
        //! let unquarantine_buffer = result.get_unquarantined_buffer();
        //! assert!(!unquarantine_buffer.is_empty())
        //! ```
        self.unquarantined_buffer.to_owned()
    }
}
