#[macro_use]
extern crate lazy_static;

mod patterns;
mod utils;
mod vendors;

pub mod error;
pub type Result<T> = std::result::Result<T, error::Error>;

use patterns::*;

pub fn unquarantine(f: &str) -> Result<(&str, Vec<Vec<u8>>)> {
    let ext = match std::path::Path::new(f).extension() {
        Some(s) => s.to_str().unwrap_or(""),
        None => "",
    };

    let data = utils::read_file(f)?;
    if ext == "v3b" || data[..16] == b"AhnLab Inc. 2006"[..] {
        return Ok(("AhnLab V3B files", vendors::ahnlab::unquarantine(&data)?));
    }
    if ext == "eqf" {
        return Ok((
            "ASquared EQF Files",
            vendors::asquared::unquarantine(&data)?,
        ));
    }
    if data[..8] == b"-chest- "[..] {
        return Ok((
            "Avast/AVG chest files",
            vendors::avast::unquarantine(&data)?,
        ));
    }
    if ext == "qua" || data[..11] == b"AntiVir Qua"[..] {
        return Ok(("Avira QUA Files", vendors::avira::unquarantine(&data)?));
    }
    if ext == ".qv" {
        return Ok(("Baidu QV Files", vendors::baidu::unquarantine(&data)?));
    }
    if ext == ".bdq" {
        return Ok((
            "BitDefender, Lavasoft AdAware, Total Defence BDQ Files",
            vendors::bitdefender::unquarantine(&data)?,
        ));
    }
    if ext == ".q" {
        if data[..4] == vec![0xCA, 0xFE, 0xBA, 0xBE] {
            let newdata = vendors::gdata::unquarantine(&data);
            match newdata {
                Err(_) => {
                    return Ok((
                        "BullGuard Q Files",
                        vendors::bullguard::unquarantine(&data)?,
                    ));
                }
                Ok(s) => {
                    return Ok(("G-Data Q Files", s));
                }
            }
        }
    }
    if ext.starts_with("qrt") {
        return Ok(("Cisco AMP", vendors::cisco::amp_unquarantine(&data)?));
    }
    if ext == "cmc" && data[..23] == b"CMC Quarantined Malware"[..] {
        return Ok((
            "CMC Antivirus CMC Files",
            vendors::cmc::unquarantine(&data)?,
        ));
    }
    if ext == "vir" {
        return Ok(("ESafe VIR Files", vendors::esafe::unquarantine(&data)?));
    }
    if ext == "ifc" {
        return Ok(("Amiti IFC Files", vendors::amiti::unquarantine(&data)?));
    }
    if ext == "nqf" {
        return Ok(("ESET NQF Files", vendors::eset::unquarantine(&data)?));
    }
    if ext == "tmp" || data[..3] == b"KSS"[..] {
        return Ok(("F-Prot TMP Files", vendors::fprot::unquarantine(&data)?));
    }
    if ext == "klq" || data[..4] == b"KLQB"[..] {
        return Ok((
            "Kaspersky KLQ files",
            vendors::kaspersky::av_unquarantine(&data)?,
        ));
    }
    if ext == "QNT" {
        return Ok(("K7 QNT files", vendors::k7::unquarantine(&data)?));
    }
    if ext == "bin" {
        return Ok((
            "Kaspersky System Watcher files",
            vendors::kaspersky::system_watcher_unquarantine(&data)?,
        ));
    }
    if ext == "lqf" {
        return Ok(("Lumension LEMSS", vendors::lumension::unquarantine(&data)?));
    }
    if ext == "quar" || ext == "data" {
        return Ok((
            "MalwareBytes DATA and QUAR Files",
            vendors::malwarebytes::unquarantine(&data)?,
        ));
    }
    if ext == "bup" && data[..8] == vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Ok(("McAfee BUP Files", vendors::mcafee::unquarantine(&data)?));
    }
    if MSE_PATTERN.is_match(f) {
        return Ok((
            "Microsoft Antimalware / Microsoft Security Essentials",
            vendors::microsoft::antimalware_unquarantine(&data)?,
        ));
    }
    if DEFAULT_FILE_PATTERN.is_match(f) && data[..2] == vec![0x75, 0x6E] {
        return Ok((
            "Microsoft Defender MAC",
            vendors::microsoft::mac_unquarantine(&data)?,
        ));
    }
    if data[..3] == vec![0xD3, 0x45, 0xAD] || data[..3] == vec![0xD3, 0x0B, 0xAD] {
        return Ok((
            "Microsoft Defender PC - partially supported (D3 45 C5 99 header)",
            vendors::microsoft::pc_unquarantine(&data)?,
        ));
    }
    if DEFAULT_FILE_PATTERN.is_match(f) && data[..2] == b"PK"[..] {
        return Ok((
            "Panda <GUID> Zip Files",
            vendors::panda::unquarantine(&data)?,
        ));
    }
    if ext == "mal" {
        return Ok((
            "Sentinel One MAL files",
            vendors::sentinelone::unquarantine(&data)?,
        ));
    }
    if NUM_PATTERN.is_match(f) && data[..2] == b"PK"[..] {
        if GUID_DAT_PATTERN.is_match(f) && data[..2] == b"PK"[..] {
            return Ok((
                "Total AV {GUID}.dat",
                vendors::others::zip_unquarantine(&data)?,
            ));
        }
        return Ok((
            "Spybot - Search & Destroy 2 Zip Files",
            vendors::others::zip_unquarantine(&data)?,
        ));
    }
    if ext == "sdb" {
        return Ok((
            "SUPERAntiSpyware (SDB)",
            vendors::others::data_unquarantine(&data, 0xED)?,
        ));
    }
    if ext == "qbd" || ext == "qbi" {
        return Ok((
            "Symantec QBD and QBI Files",
            vendors::symantec::qbd_unquarantine(&data)?,
        ));
    }
    if GUID_PATTERN.is_match(f) {
        return Ok((
            "Symantec ccSubSDK {GUID} Files",
            vendors::symantec::cc_sub_sdk_unquarantine(&data)?,
        ));
    }
    if f == "submissions.idx" {
        return Ok((
            "Symantec ccSubSDK submissions.idx Files",
            vendors::symantec::idx_unquarantine(&data)?,
        ));
    }
    if f == "quarantine.qtn" && data[..2] == b"PK"[..] {
        return Ok((
            "Symantec quarantine.qtn",
            vendors::symantec::qtn_unquarantine(&data)?,
        ));
    }
    if ext == "vbn" {
        return Ok((
            "Symantec VBN Files",
            vendors::symantec::ep_unquarantine(&data)?,
        ));
    }
    if utils::unpack_i32(&data)? == 0x58425356 {
        return Ok((
            "TrendMicro VSBX files",
            vendors::trendmicro::unquarantine(&data)?,
        ));
    }
    if QDB_PATTERN.is_match(f) {
        if f == "quarantine.db" {
            return Ok(("QuickHeal Files", vendors::quickheal::unquarantine(&data)?));
        }
        return Ok(("Zemana Files", vendors::zemana::unquarantine(&data)?));
    }

    if let Ok(s) = vendors::kaspersky::av_unquarantine(&data) {
        return Ok(("kav", s));
    }
    if let Ok(s) = vendors::trendmicro::unquarantine(&data) {
        return Ok(("trend", s));
    }
    if let Ok(s) = vendors::symantec::ep_unquarantine(&data) {
        return Ok(("sep", s));
    }
    if let Ok(s) = vendors::microsoft::pc_unquarantine(&data) {
        return Ok(("mse", s));
    }
    if let Ok(s) = vendors::others::xorff_unquarantine(&data) {
        return Ok(("xorff", s));
    }

    Err(error::Error::UndefinedQuarantineMethod(f.to_string()))
}
