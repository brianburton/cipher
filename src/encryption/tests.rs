use super::*;

#[test]
fn test_base64() {
    let source = "hello world".to_string();
    let encoded = base64_encode(&source).unwrap();
    assert_eq!(encoded, "aGVsbG8gd29ybGQ=".to_string());
    let decoded = base64_decode(&encoded).unwrap();
    assert_eq!(source, decoded);
}
