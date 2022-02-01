/// AhnLab (V3B) UnQuarantine
pub mod ahnlab;
/// Amiti (IFC)
pub mod amiti;
/// ASquared (EQF)
pub mod asquared;
/// Avast/AVG (Magic@0='-chest- ')
pub mod avast;
/// Avira (QUA)
pub mod avira;
/// Baidu (QV)
pub mod baidu;
/// BitDefender (BDQ)
pub mod bitdefender;
/// BullGuard (Q)
pub mod bullguard;
/// Cisco
pub mod cisco;
/// CMC Antivirus (CMC)
pub mod cmc;
/// ESafe (VIR)
pub mod esafe;
/// ESET (NQF)
pub mod eset;
/// Fprot (TMP) (Magic@0='KSS')
pub mod fprot;
/// G-Data (Q) (Magic@0=0xCAFEBABE)
pub mod gdata;
/// K7 Antivirus (<md5>.QNT)
pub mod k7;
/// Kaspersky (KLQ, System Watcher's <md5>.bin)
pub mod kaspersky;
/// Lumension LEMSS (lqf)
pub mod lumension;
/// Malwarebytes
pub mod malwarebytes;
/// McAfee Quarantine files (BUP) /full support for OLE format/
pub mod mcafee;
/// Microsoft products
pub mod microsoft;
/// Panda <GUID> Zip files
pub mod panda;
/// QuickHeal <hash> files
pub mod quickheal;
/// Sentinel One (MAL)
pub mod sentinelone;
/// Symantec products
pub mod symantec;
/// TrendMicro (Magic@0=A9 AC BD A7 which is a 'VSBX' string ^ 0xFF)
pub mod trendmicro;
/// Vipre (<GUID>_ENC2)
pub mod vipre;
/// Zemana <hash> files+quarantine.db
pub mod zemana;

/// All other different types of unquarantine methods
pub mod others;
