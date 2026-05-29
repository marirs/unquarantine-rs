use regex::Regex;
use std::sync::LazyLock;

const FILE_PATTERN: &str = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

pub static NUM_PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"-\d+").unwrap());
pub static DEFAULT_FILE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(FILE_PATTERN).unwrap());
pub static QDB_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|[/\\])[0-9a-f]{32}").unwrap());
pub static MSE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\{{{FILE_PATTERN}\}}-.{{1,}}")).unwrap());
pub static GUID_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"\{{{FILE_PATTERN}\}}")).unwrap());
pub static GUID_DAT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(^|[/\\]){FILE_PATTERN}\.dat")).unwrap());
