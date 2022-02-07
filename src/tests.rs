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
