use super::*;

use im::vector;

#[test]
fn test_marker_regex() {
    let source = "<<SECURE>>I'm nobody! <</SECURE>>Who are you?
Are you nobody, too?
Then there's a <<SECURE>>pair of us - don't tell!<</SECURE>>
They'd banish us, you know.

<<CIPHER>>How dreary to be somebody!
How public, like a frog
To tell your name the livelong day<</CIPHER>>
To an admiring bog!"
        .to_string();
    let answer = parse_source(source).unwrap();
    let expected: SegmentMap = vector!(Segment::Secure("I'm nobody! ".to_string()),
            Segment::Text("Who are you?\nAre you nobody, too?\nThen there's a ".to_string()),
            Segment::Secure("pair of us - don't tell!".to_string()),
            Segment::Text("\nThey'd banish us, you know.\n\n".to_string()),
            Segment::Cipher("How dreary to be somebody!\nHow public, like a frog\nTo tell your name the livelong day".to_string()),
            Segment::Text("\nTo an admiring bog!".to_string())
        ).iter().map(|s| Rc::new(s.clone())).collect();
    assert_eq!(expected, answer);
}

#[test]
fn test_base64() {
    let source = "hello world".to_string();
    let encoded = base64_encode(&source).unwrap();
    assert_eq!(encoded, "aGVsbG8gd29ybGQ=".to_string());
    let decoded = base64_decode(&encoded).unwrap();
    assert_eq!(source, decoded);
}

#[test]
fn test_encrypt() {
    let segments = vector!(
        Rc::new(Segment::Text("abc".to_string())),
        Rc::new(Segment::Secure("def".to_string())),
        Rc::new(Segment::Cipher("ghi".to_string())),
        Rc::new(Segment::Text("xyz".to_string()))
    );
    let expected = vector!(
        Rc::new(Segment::Text("abc".to_string())),
        Rc::new(Segment::Cipher("ZGVm".to_string())),
        Rc::new(Segment::Cipher("ghi".to_string())),
        Rc::new(Segment::Text("xyz".to_string()))
    );
    let expanded = encrypt(segments, &|s| base64_encode(s)).unwrap();
    assert_eq!(expanded, expected);
}

#[test]
fn test_rewind() {
    let segments = vector!(
        Rc::new(Segment::Text("abc".to_string())),
        Rc::new(Segment::Cipher("ZGVm".to_string())),
        Rc::new(Segment::Secure("ghi".to_string())),
        Rc::new(Segment::Text("xyz".to_string()))
    );
    let expected = vector!(
        Rc::new(Segment::Text("abc".to_string())),
        Rc::new(Segment::Secure("def".to_string())),
        Rc::new(Segment::Secure("ghi".to_string())),
        Rc::new(Segment::Text("xyz".to_string()))
    );
    let expanded = rewind(segments, &|s| base64_decode(s)).unwrap();
    assert_eq!(expanded, expected);
}

#[test]
fn test_decrypt() {
    let segments = vector!(
        Rc::new(Segment::Text("abc".to_string())),
        Rc::new(Segment::Cipher("ZGVm".to_string())),
        Rc::new(Segment::Secure("ghi".to_string())),
        Rc::new(Segment::Text("xyz".to_string()))
    );
    let expected = vector!(
        Rc::new(Segment::Text("abc".to_string())),
        Rc::new(Segment::Text("def".to_string())),
        Rc::new(Segment::Text("ghi".to_string())),
        Rc::new(Segment::Text("xyz".to_string()))
    );
    let expanded = decrypt(segments, &|s| base64_decode(s)).unwrap();
    assert_eq!(expanded, expected);
}

#[test]
fn test_expand() {
    let segments = vector!(
        Rc::new(Segment::Text("abc".to_string())),
        Rc::new(Segment::Secure("def".to_string())),
        Rc::new(Segment::Text("xyz".to_string()))
    );
    let expanded = expand(segments).unwrap();
    assert_eq!(expanded, "abcdefxyz".to_string());
}
