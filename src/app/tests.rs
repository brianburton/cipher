use super::*;

use im::vector;

#[test]
fn test_split_path() {
    assert_eq!(("", "a"), split_path("a"));
    assert_eq!(("/", "a"), split_path("/a"));
    assert_eq!(("a/", "bc"), split_path("a/bc"));
    assert_eq!(("/a/", "bc"), split_path("/a/bc"));
    assert_eq!(("/a/bc/", "def"), split_path("/a/bc/def"));
}

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
    let expected: Segments = vector!(Segment::Secure("I'm nobody! ".to_string()),
            Segment::Text("Who are you?\nAre you nobody, too?\nThen there's a ".to_string()),
            Segment::Secure("pair of us - don't tell!".to_string()),
            Segment::Text("\nThey'd banish us, you know.\n\n".to_string()),
            Segment::Cipher("How dreary to be somebody!\nHow public, like a frog\nTo tell your name the livelong day".to_string()),
            Segment::Text("\nTo an admiring bog!".to_string())
        ).iter().map(|s| Rc::new(s.clone())).collect();
    assert_eq!(expected, answer);
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
    let system = crate::encryption::new_insecure_encryption().unwrap();
    let expanded = encrypt(segments, system.as_ref()).unwrap();
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
    let system = crate::encryption::new_insecure_encryption().unwrap();
    let expanded = rewind(segments, system.as_ref()).unwrap();
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
    let system = crate::encryption::new_insecure_encryption().unwrap();
    let expanded = decrypt(segments, system.as_ref()).unwrap();
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
