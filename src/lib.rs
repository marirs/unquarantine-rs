#[macro_use]
extern crate lazy_static;

mod patterns;
mod utils;
mod vendors;

pub mod error;
pub type Result<T> = std::result::Result<T, error::Error>;

use patterns::*;
use std::{ffi::OsStr, path::Path};

#[derive(Clone)]
pub struct UnQuarantine<'a> {
    /// The detected Vendor of the quarantined file
    vendor: &'a str,
    /// The buffer to save as unquarantined file
    unquarantined_buffer: Vec<Vec<u8>>,
}

impl<'a> UnQuarantine<'a> {
    pub fn from_file(qf: &str) -> Result<Self> {
        //! Unquarantine a given quarantined file into its original file
        let file_extension = Path::new(qf)
            .extension()
            .and_then(OsStr::to_str)
            .unwrap_or_default();

        let data = utils::read_file(&qf)?;
        if file_extension == "v3b" || data[..16] == b"AhnLab Inc. 2006"[..] {
            return Ok(Self {
                vendor: "AhnLab V3B files",
                unquarantined_buffer: vendors::ahnlab::unquarantine(&data)?,
            });
        }
        if file_extension == "eqf" {
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
        if file_extension == "qua" || data[..11] == b"AntiVir Qua"[..] {
            return Ok(Self {
                vendor: "Avira QUA Files",
                unquarantined_buffer: vendors::avira::unquarantine(&data)?,
            });
        }
        if file_extension == "qv" {
            return Ok(Self {
                vendor: "Baidu QV Files",
                unquarantined_buffer: vendors::baidu::unquarantine(&data)?,
            });
        }
        if file_extension == ".bdq" {
            return Ok(Self {
                vendor: "BitDefender/Lavasoft AdAware/Total Defence: BDQ Files",
                unquarantined_buffer: vendors::bitdefender::unquarantine(&data)?,
            });
        }
        if file_extension == ".q" && data[..4] == vec![0xCA, 0xFE, 0xBA, 0xBE] {
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
        if file_extension.starts_with("qrt") {
            return Ok(Self {
                vendor: "Cisco AMP",
                unquarantined_buffer: vendors::cisco::amp_unquarantine(&data)?,
            });
        }
        if file_extension == "cmc" && data[..23] == b"CMC Quarantined Malware"[..] {
            return Ok(Self {
                vendor: "CMC Antivirus CMC Files",
                unquarantined_buffer: vendors::cmc::unquarantine(&data)?,
            });
        }
        if file_extension == "vir" {
            return Ok(Self {
                vendor: "ESafe VIR Files",
                unquarantined_buffer: vendors::esafe::unquarantine(&data)?,
            });
        }
        if file_extension == "ifc" {
            return Ok(Self {
                vendor: "Amiti IFC Files",
                unquarantined_buffer: vendors::amiti::unquarantine(&data)?,
            });
        }
        if file_extension == "nqf" {
            return Ok(Self {
                vendor: "ESET NQF Files",
                unquarantined_buffer: vendors::eset::unquarantine(&data)?,
            });
        }
        if file_extension == "tmp" || data[..3] == b"KSS"[..] {
            return Ok(Self {
                vendor: "F-Prot TMP Files",
                unquarantined_buffer: vendors::fprot::unquarantine(&data)?,
            });
        }
        if file_extension == "klq" || data[..4] == b"KLQB"[..] {
            return Ok(Self {
                vendor: "Kaspersky KLQ files",
                unquarantined_buffer: vendors::kaspersky::av_unquarantine(&data)?,
            });
        }
        if file_extension == "QNT" {
            return Ok(Self {
                vendor: "K7 QNT files",
                unquarantined_buffer: vendors::k7::unquarantine(&data)?,
            });
        }
        if file_extension == "bin" {
            return Ok(Self {
                vendor: "Kaspersky System Watcher files",
                unquarantined_buffer: vendors::kaspersky::system_watcher_unquarantine(&data)?,
            });
        }
        if file_extension == "lqf" {
            return Ok(Self {
                vendor: "Lumension LEMSS",
                unquarantined_buffer: vendors::lumension::unquarantine(&data)?,
            });
        }
        if file_extension == "quar"
            || file_extension == "data"
            || qf.to_lowercase().ends_with("data")
        {
            return Ok(Self {
                vendor: "MalwareBytes DATA and QUAR Files",
                unquarantined_buffer: vendors::malwarebytes::unquarantine(&data)?,
            });
        }
        if file_extension == "bup"
            && data[..8] == vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
        {
            return Ok(Self {
                vendor: "McAfee BUP Files",
                unquarantined_buffer: vendors::mcafee::unquarantine(&data)?,
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
        if data[..3] == vec![0xD3, 0x45, 0xAD] || data[..3] == vec![0xD3, 0x0B, 0xAD] {
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
        if file_extension == "mal" {
            return Ok(Self {
                vendor: "Sentinel One MAL files",
                unquarantined_buffer: vendors::sentinelone::unquarantine(&data)?,
            });
        }
        if NUM_PATTERN.is_match(qf) && data[..2] == b"PK"[..] {
            if GUID_DAT_PATTERN.is_match(qf) && data[..2] == b"PK"[..] {
                return Ok(Self {
                    vendor: "Total AV {GUID}.dat",
                    unquarantined_buffer: vendors::others::zip_unquarantine(&data)?,
                });
            }
            return Ok(Self {
                vendor: "Spybot - Search & Destroy 2 Zip Files",
                unquarantined_buffer: vendors::others::zip_unquarantine(&data)?,
            });
        }
        if file_extension == "sdb" {
            return Ok(Self {
                vendor: "SUPERAntiSpyware (SDB)",
                unquarantined_buffer: vendors::others::data_unquarantine(&data, 0xED)?,
            });
        }
        if file_extension == "qbd" || file_extension == "qbi" {
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
        if qf == "submissions.idx" {
            return Ok(Self {
                vendor: "Symantec ccSubSDK submissions.idx Files",
                unquarantined_buffer: vendors::symantec::idx_unquarantine(&data)?,
            });
        }
        if qf == "quarantine.qtn" && data[..2] == b"PK"[..] {
            return Ok(Self {
                vendor: "Symantec quarantine.qtn",
                unquarantined_buffer: vendors::symantec::qtn_unquarantine(&data)?,
            });
        }
        if file_extension == "vbn" {
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
            if qf == "quarantine.db" {
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

        Err(error::Error::UndefinedQuarantineMethod(qf.to_string()))
    }

    pub fn get_vendor(&self) -> &str {
        //! Gets the Vendor String of the Quarantined File
        self.vendor
    }

    pub fn get_unquarantined_buffer(&self) -> Vec<Vec<u8>> {
        //! Gets the UnQuarantined Buffer for the quarantined file
        self.unquarantined_buffer.to_owned()
    }
}
