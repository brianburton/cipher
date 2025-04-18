use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE};
use derive_getters::Getters;
use im::{Vector, vector};
use lazy_static::lazy_static;
use regex::Captures;
use regex::Regex;
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::rc::Rc;
use std::string::FromUtf8Error;

lazy_static! {
    static ref MARKER_RE: Regex = Regex::new(r"<<(/?(SECURE|CIPHER))>>").unwrap();
}

#[derive(Debug, Getters, PartialEq, Clone)]
pub struct AppError {
    context: String,
    detail: String,
}

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "error: context: {} detail: {}",
            self.context, self.detail
        )
    }
}

impl Error for AppError {}

impl AppError {
    pub fn from_str(context: &str, detail: &str) -> Self {
        Self {
            context: context.to_string(),
            detail: detail.to_string(),
        }
    }

    pub fn from_error<E: Error>(context: &str, e: E) -> Self {
        Self {
            context: context.to_string(),
            detail: e.to_string(),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        AppError::from_error("IO Error", &error)
    }
}

impl From<DecodeError> for AppError {
    fn from(error: DecodeError) -> Self {
        AppError::from_error("base64 decode error", &error)
    }
}

impl From<FromUtf8Error> for AppError {
    fn from(error: FromUtf8Error) -> Self {
        AppError::from_error("utf8 decode error", &error)
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Segment {
    Plain(String),
    Cipher(String),
    Content(String),
}

type SegmentMap = Vector<Rc<Segment>>;
type CipherFn<'a> = dyn Fn(&String) -> Result<String, AppError> + 'a;

fn base64_encode(source: &String) -> Result<String, AppError> {
    let r = URL_SAFE.encode(source.as_bytes());
    Ok(r)
}

fn base64_decode(source: &String) -> Result<String, AppError> {
    let v = URL_SAFE.decode(source.as_bytes())?;
    let s = String::from_utf8(v)?;
    Ok(s)
}

fn encrypt(segments: SegmentMap, op: &CipherFn) -> Result<SegmentMap, AppError> {
    let mut answer: SegmentMap = Vector::new();
    for seg in segments.iter() {
        match seg.as_ref() {
            Segment::Plain(plain) => {
                let cipher = op(plain)?;
                answer.push_back(Rc::new(Segment::Cipher(cipher)));
            }
            _ => answer.push_back(Rc::clone(seg)),
        }
    }
    Ok(answer)
}

fn decrypt(segments: SegmentMap, op: &CipherFn) -> Result<SegmentMap, AppError> {
    let mut answer: SegmentMap = Vector::new();
    for seg in segments.iter() {
        match seg.as_ref() {
            Segment::Cipher(cipher) => {
                let plain = op(cipher)?;
                answer.push_back(Rc::new(Segment::Plain(plain)));
            }
            _ => answer.push_back(Rc::clone(seg)),
        }
    }
    Ok(answer)
}

fn parse_source(source: String) -> Result<SegmentMap, AppError> {
    let mut offset: usize = 0;
    let mut expected: Option<String> = None;
    let mut answer = Vector::<Rc<Segment>>::new();
    loop {
        match MARKER_RE.captures_at(source.as_str(), offset) {
            Some(captures) => {
                let m = captures.get(0).unwrap();
                let content = source[offset..m.start()].to_string();
                let marker = captures[1].to_string();
                offset = m.end();
                match &expected {
                    Some(s) => {
                        if s != &marker {
                            return Err(AppError::from_str(
                                "parsing",
                                format!("expected {} but found {}", s, marker).as_str(),
                            ));
                        }
                        let segment = if s == "/SECURE" {
                            Segment::Plain(content)
                        } else {
                            Segment::Cipher(content)
                        };
                        answer.push_back(Rc::new(segment));
                        expected = None
                    }
                    None => {
                        if content != "" {
                            let segment = Segment::Content(content);
                            answer.push_back(Rc::new(segment));
                        }
                        if marker == "SECURE" {
                            expected = Some("/SECURE".to_string())
                        } else if marker == "CIPHER" {
                            expected = Some("/CIPHER".to_string())
                        } else {
                            return Err(AppError::from_str(
                                "parsing",
                                format!("expected start tag but found {}", marker).as_str(),
                            ));
                        }
                    }
                }
            }
            None => {
                if let Some(s) = expected {
                    return Err(AppError::from_str(
                        "parsing",
                        format!("expected {} but found end of string", s).as_str(),
                    ));
                }
                if offset < source.len() {
                    let text = source[offset..].to_string();
                    let segment = Segment::Content(text);
                    answer.push_back(Rc::new(segment));
                }
                break;
            }
        }
    }
    Ok(answer)
}

fn load_file(filename: &str) -> Result<Vector<Rc<Segment>>, AppError> {
    let source = fs::read_to_string(filename)?;
    parse_source(source)
}

fn main() {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use im::Vector;

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
        let expected: SegmentMap = vector!(Segment::Plain("I'm nobody! ".to_string()),
            Segment::Content("Who are you?\nAre you nobody, too?\nThen there's a ".to_string()),
            Segment::Plain("pair of us - don't tell!".to_string()),
            Segment::Content("\nThey'd banish us, you know.\n\n".to_string()),
            Segment::Cipher("How dreary to be somebody!\nHow public, like a frog\nTo tell your name the livelong day".to_string()),
            Segment::Content("\nTo an admiring bog!".to_string())
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
}
