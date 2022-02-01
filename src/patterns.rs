use regex::Regex;

lazy_static! {
    pub static ref FILE_PATTERN: &'static str =
        "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    pub static ref NUM_PATTERN: Regex = Regex::new(r"-\d+").unwrap();
    pub static ref DEFAULT_FILE_PATTERN: Regex = Regex::new(&FILE_PATTERN).unwrap();
    pub static ref QDB_PATTERN: Regex = Regex::new(r"(^|[/\\])[0-9a-f]{32}").unwrap();
    pub static ref MSE_PATTERN: Regex =
        Regex::new(&[r"\{", &FILE_PATTERN, r"\}-.{1,}"].join("")).unwrap();
    pub static ref GUID_PATTERN: Regex =
        Regex::new(&[r"\{", &FILE_PATTERN, r"\}"].join("")).unwrap();
    pub static ref GUID_DAT_PATTERN: Regex =
        Regex::new(&[r"(^|[\/\\])", &FILE_PATTERN, r"\.dat"].join("")).unwrap();
}
