#[macro_use]
extern crate lazy_static;

mod utils;
mod vendors;

pub mod error;
use error::Error;
pub type Result<T> = std::result::Result<T, error::Error>;


fn read_trend_tag(data: &Vec<u8>, offset: usize) -> Result<(u8, Vec<u8>)> {
    let code = data[offset];
    let length = utils::unpack_i16(&data[offset + 1..])? as usize;
    Ok((code, data[offset + 3..offset + 3 + length].to_vec()))
}

pub fn kav_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut data = data.clone();
    let magic = utils::unpack_i32(&data)?;
    if magic != 0x42514C4B {
        return Err(Error::UndefinedQuarantineMethod("kav".to_string()));
    }
    let fsize = data.len();

    let headerlen = utils::unpack_i32(&data[8..])?;
    let metaoffset = utils::unpack_i32(&data[0x10..])?;
    let metalen = utils::unpack_i32(&data[0x20..])?;
    let origlen = utils::unpack_i32(&data[0x30..])?;

    if fsize < (headerlen + origlen + metalen) as usize {
        return Err(Error::UndefinedQuarantineMethod("kav".to_string()));
    }
    if metaoffset < headerlen + origlen {
        return Err(Error::UndefinedQuarantineMethod("kav".to_string()));
    }

    let key = vec![0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC];

    let mut curoffset = metaoffset as usize;
    let mut length = utils::unpack_i32(&data[curoffset..])?;
    while length > 0 {
        for i in 0..length {
            data[curoffset + 4 + i as usize] ^= key[(i % key.len() as i32) as usize];
        }
        curoffset += (4 + length) as usize;
        if curoffset >= (metaoffset + metalen) as usize {
            break;
        }
        length = utils::unpack_i32(&data[curoffset..])?;
    }
    for i in 0..origlen {
        data[(headerlen + i) as usize] ^= key[(i % key.len() as i32) as usize];
    }
    Ok(vec![data
        [headerlen as usize..(headerlen + origlen) as usize]
        .to_vec()])
}

pub fn trend_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut data = utils::bytearray_xor(data.clone(), 0xFF);
    let magic = utils::unpack_i32(&data)?;
    let mut dataoffset = utils::unpack_i32(&data[4..])? as usize;
    let numtags = utils::unpack_i16(&data[8..])?;
    if magic != 0x58425356 {
        // VSBX
        return Err(Error::UndefinedQuarantineMethod("trend".to_string()));
    }
    let mut basekey = 0x00000000;
    let mut encmethod = 0;

    if numtags > 15 {
        return Err(Error::UndefinedQuarantineMethod("trend".to_string()));
    }
    dataoffset += 10;
    let offset = 10;
    for _ in 0..numtags {
        let (code, tagdata) = read_trend_tag(&data, offset)?;
        match code {
            6 => {
                basekey = utils::unpack_i32(&tagdata)?;
            }
            7 => {
                encmethod = utils::unpack_i16(&tagdata)?;
            }
            _ => {}
        }
    }
    if encmethod != 2 {
        return Ok(vec![data[dataoffset..].to_vec()]);
    }
    let mut bytesleft = data.len() - dataoffset as usize;
    let mut unaligned = dataoffset % 4;
    let mut firstiter = true;
    let mut curoffset = dataoffset;
    while bytesleft > 0 {
        let mut off = curoffset;
        if firstiter {
            off = curoffset - unaligned;
            firstiter = false;
        }
        let keyval = basekey + off as i32;
        let cc = crc::Crc::<u32>::new(&crc::CRC_32_ISCSI);
        let crcbuf = cc.checksum(&keyval.to_le_bytes()[..]).to_le_bytes();
        for i in unaligned..4 {
            if bytesleft == 0 {
                break;
            }
            data[curoffset] ^= crcbuf[i];
            curoffset += 1;
            bytesleft -= 1;
        }
        unaligned = 0;
    }
    Ok(vec![data[dataoffset..].to_vec()])
}

pub fn xorff_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let qdata = utils::bytearray_xor(data.clone(), 0xFF);
    Ok(vec![qdata])
}

pub fn esafe_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let bytes = base64::decode(data)?;
    Ok(vec![bytes])
}

pub fn sentinelone_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    Ok(vec![utils::bytearray_xor(data.clone(), 255)])
}

pub fn k7_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let len = utils::unpack_i32(&data[0x128..])? as usize;
    if len > data.len() {
        return Err(Error::UndefinedQuarantineMethod("k7".to_string()));
    }
    let newdata = utils::bytearray_xor(data[0x178..0x178 + len].to_vec(), 0xFF);
    Ok(vec![newdata])
}

pub fn kaspersky_system_watcher_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let key = vec![0x39, 0x7b, 0x4d, 0x58, 0xc9, 0x39, 0x7b, 0x4d, 0x58, 0xc9];
    let mut newdata = vec![];
    for i in 0..data.len() {
        newdata.push(data[i] ^ key[i % key.len()]);
    }
    Ok(vec![newdata])
}


pub fn cisco_amp_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut dec = vec![];
    for i in 0..data.len() {
        dec.push(data[i] ^ 0x77);
    }
    Ok(vec![dec])
}

pub fn cmc_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let _magic = &data[..32];
    let _ffv = utils::unpack_i32(&data[0x20..])?;
    let _crc = utils::unpack_i32(&data[0x28..])?;
    let _adler = utils::unpack_i32(&data[0x2C..])?;
    let ofn = utils::unpack_i16(&data[0x50..])? as usize;
    let _us = utils::unpack_i32(&data[0x54..])?;
    let _qs = utils::unpack_i32(&data[0x58..])?;
    let tnl = utils::unpack_i16(&data[0x6C..])? as usize;

    let _fnn = &data[0x200..0x200 + ofn];
    let _tn = &data[0x200 + ofn..0x200 + ofn + tnl];
    let _md5 = &data[0x30..0x30 + 16];
    let _submitid = &data[0x40..0x40 + 16];

    let data = &data[0x200 + ofn + tnl..];
    let buflen = utils::unpack_i32(&data)? as usize;
    let data = &data[4..4 + buflen];
    let _meta_dec = utils::bytearray_xor(data.to_vec(), 30);
    let mut dec = vec![];
    let mut zip =
        zip::ZipArchive::new(std::io::BufReader::new(std::io::Cursor::new(data.to_vec())))?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let _s = file.size();
        let mut res: Vec<u8> = vec![];
        std::io::copy(&mut file, &mut res)?;
        dec.push(res);
    }
    Ok(dec)
}

pub fn lumension_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    //WANT_GZIP
    let dec2 = inflate::inflate_bytes(&data[32..]).map_err(|e| Error::InflateError(e))?;
    Ok(vec![dec2])
}

pub fn panda_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut ress = vec![];
    let mut zip =
        zip::ZipArchive::new(std::io::BufReader::new(std::io::Cursor::new(data.to_vec())))?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let mut res: Vec<u8> = vec![];
        std::io::copy(&mut file, &mut res)?;
        let key = vec![
            0x3D, 0xD8, 0x22, 0x66, 0x65, 0x16, 0xE3, 0xB8, 0xC5, 0xD6, 0x18, 0x71, 0xE7, 0x19,
            0xE0, 0x5A,
        ];
        let dec = utils::blowfishit(&res, &key)?;
        let dec2 = inflate::inflate_bytes(&dec).map_err(|e| Error::InflateError(e))?;
        ress.push(dec2);
    }
    Ok(ress)
}

pub fn zip_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut ress = vec![];
    let mut zip =
        zip::ZipArchive::new(std::io::BufReader::new(std::io::Cursor::new(data.to_vec())))?;

    for i in 0..zip.len() {
        let mut file = zip.by_index(i)?;
        let mut res: Vec<u8> = vec![];
        std::io::copy(&mut file, &mut res)?;
        ress.push(res);
    }
    Ok(ress)
}

pub fn data_unquarantine(data: &Vec<u8>, key: u8) -> Result<Vec<Vec<u8>>> {
    let newdata = utils::bytearray_xor(data.to_vec(), key);
    Ok(vec![newdata])
}

pub fn quickheal_unquarantine(data: &Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut dec = vec![];
    for i in 0..data.len() {
        let b1 = data[i];
        let b2 = b1;
        dec.push((b1 >> 4) | (b2 << 4));
    }
    Ok(vec![dec])
}

pub fn unquarantine(f: &str) -> Result<(&str, Vec<Vec<u8>>)> {
    let ext = match std::path::Path::new(f).extension() {
        Some(s) => match s.to_str() {
            Some(ss) => ss,
            None => "",
        },
        None => "",
    };

    let data = utils::read_file(f)?;
    if ext == "v3b" || data[..16] == b"AhnLab Inc. 2006"[..] {
        return Ok(("AhnLab V3B files", vendors::ahnlab::unquarantine(&data)?));
    }
    if ext == "eqf" {
        return Ok(("ASquared EQF Files", vendors::asquared::unquarantine(&data)?));
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
        if &data[..4] == &vec![0xCA, 0xFE, 0xBA, 0xBE] {
            let newdata = vendors::gdata::unquarantine(&data);
            match newdata {
                Err(_) => {
                    return Ok(("BullGuard Q Files", vendors::bullguard::unquarantine(&data)?));
                }
                Ok(s) => {
                    return Ok(("G-Data Q Files", s));
                }
            }
        }
    }
    if ext.starts_with("qrt") {
        return Ok(("Cisco AMP", cisco_amp_unquarantine(&data)?));
    }
    if ext == "cmc" && data[..23] == b"CMC Quarantined Malware"[..] {
        return Ok(("CMC Antivirus CMC Files", cmc_unquarantine(&data)?));
    }
    if ext == "vir" {
        return Ok(("ESafe VIR Files", esafe_unquarantine(&data)?));
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
        return Ok(("Kaspersky KLQ files", kav_unquarantine(&data)?));
    }
    if ext == "QNT" {
        return Ok(("K7 QNT files", k7_unquarantine(&data)?));
    }
    if ext == "bin" {
        return Ok((
            "Kaspersky System Watcher files",
            kaspersky_system_watcher_unquarantine(&data)?,
        ));
    }
    if ext == "lqf" {
        return Ok(("Lumension LEMSS", lumension_unquarantine(&data)?));
    }
    if ext == "quar" || ext == "data" {
        return Ok((
            "MalwareBytes DATA and QUAR Files",
            vendors::malwarebytes::unquarantine(&data)?,
        ));
    }
    if ext == "bup" && &data[..8] == &vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1] {
        return Ok(("McAfee BUP Files", vendors::mcafee::unquarantine(&data)?));
    }
    if regex::Regex::new(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}-.{1,}")?
        .is_match(f)
    {
        return Ok((
            "Microsoft Antimalware / Microsoft Security Essentials",
            vendors::microsoft::antimalware_unquarantine(&data)?,
        ));
    }
    if regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")?
        .is_match(f)
        && data[..2] == vec![0x75, 0x6E]
    {
        return Ok(("Microsoft Defender MAC", vendors::microsoft::mac_unquarantine(&data)?));
    }
    if &data[..3] == &vec![0xD3, 0x45, 0xAD] || &data[..3] == &vec![0xD3, 0x0B, 0xAD] {
        return Ok((
            "Microsoft Defender PC - partially supported (D3 45 C5 99 header)",
            vendors::microsoft::pc_unquarantine(&data)?,
        ));
    }
    if regex::Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")?
        .is_match(f)
        && data[..2] == b"PK"[..]
    {
        return Ok(("Panda <GUID> Zip Files", panda_unquarantine(&data)?));
    }
    if ext == "mal" {
        return Ok(("Sentinel One MAL files", sentinelone_unquarantine(&data)?));
    }
    if regex::Regex::new(r"-\d+")?.is_match(f) && data[..2] == b"PK"[..] {
        if regex::Regex::new(
            r"(^|[\/\\])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.dat",
        )?
        .is_match(f)
            && data[..2] == b"PK"[..]
        {
            return Ok(("Total AV {GUID}.dat", zip_unquarantine(&data)?));
        }
        return Ok((
            "Spybot - Search & Destroy 2 Zip Files",
            zip_unquarantine(&data)?,
        ));
    }
    if ext == "sdb" {
        return Ok(("SUPERAntiSpyware (SDB)", data_unquarantine(&data, 0xED)?));
    }
    if ext == "qbd" || ext == "qbi" {
        return Ok((
            "Symantec QBD and QBI Files",
            data_unquarantine(&data, 0xB3)?,
        ));
    }
    if regex::Regex::new(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}")?
        .is_match(f)
    {
        return Ok((
            "Symantec ccSubSDK {GUID} Files",
            vendors::symantec::sym_cc_sub_sdk_unquarantine(&data)?,
        ));
    }
    if f == "submissions.idx" {
        return Ok((
            "Symantec ccSubSDK submissions.idx Files",
            vendors::symantec::sym_submissionsidx_unquarantine(&data)?,
        ));
    }
    if f == "quarantine.qtn" && data[..2] == b"PK"[..] {
        return Ok(("Symantec quarantine.qtn", vendors::symantec::sym_qtn_unquarantine(&data)?));
    }
    if ext == "vbn" {
        return Ok((
            "Symantec VBN Files",
            vendors::symantec::ep_unquarantine(&data)?,
        ));
    }
    if utils::unpack_i32(&data)? == 0x58425356 {
        return Ok(("TrendMicro VSBX files", trend_unquarantine(&data)?));
    }
    if regex::Regex::new(r"(^|[/\\])[0-9a-f]{32}")?.is_match(f) {
        if f == "quarantine.db" {
            return Ok(("QuickHeal Files", vendors::zemana::unquarantine(&data)?));
        }
        return Ok(("Zemana Files", quickheal_unquarantine(&data)?));
    }

    if let Ok(s) = kav_unquarantine(&data) {
        return Ok(("kav", s));
    }
    if let Ok(s) = trend_unquarantine(&data) {
        return Ok(("trend", s));
    }
    if let Ok(s) = vendors::symantec::ep_unquarantine(&data) {
        return Ok(("sep", s));
    }
    if let Ok(s) = vendors::microsoft::pc_unquarantine(&data) {
        return Ok(("mse", s));
    }
    if let Ok(s) = xorff_unquarantine(&data) {
        return Ok(("xorff", s));
    }
    //    for (n, f) in unquarantine_fns{
    //        if let Ok(s) = f(&data){
    //            return Ok((n, s));
    //        }
    //    }
    Err(Error::UndefinedQuarantineMethod(f.to_string()))
}
