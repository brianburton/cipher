use derive_getters::Getters;
use im::{Vector, vector};
use lazy_static::lazy_static;
use regex::Captures;
use regex::Regex;
use std::error::Error;
use std::fmt::Display;
use std::fs;

lazy_static! {
    static ref MARKER_RE: Regex = Regex::new(r"<<(/?(SECURE|CIPHER))>>").unwrap();
}

#[derive(Debug, Getters, PartialEq)]
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

#[derive(Clone, Debug, PartialEq)]
enum Segment {
    Plain(String),
    Cipher(String),
    Content(String),
}

fn parse_source(source: String) -> Result<Vector<Segment>, AppError> {
    let mut offset: usize = 0;
    let mut expected: Option<String> = None;
    let mut answer = Vector::<Segment>::new();
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
                        if s == "/SECURE" {
                            answer.push_back(Segment::Plain(content));
                        } else {
                            answer.push_back(Segment::Cipher(content));
                        }
                        expected = None
                    }
                    None => {
                        if content != "" {
                            answer.push_back(Segment::Content(content));
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
                        format!("expected {} but end of string", s).as_str(),
                    ));
                }
                if offset < source.len() {
                    answer.push_back(Segment::Content(source[offset..].to_string()));
                }
                break;
            }
        }
    }
    Ok(answer)
}

fn load_file(filename: &str) -> Result<Vector<Segment>, AppError> {
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
        assert_eq!(vector!(Segment::Plain("I'm nobody! ".to_string()), 
            Segment::Content("Who are you?\nAre you nobody, too?\nThen there's a ".to_string()),
            Segment::Plain("pair of us - don't tell!".to_string()),
            Segment::Content("\nThey'd banish us, you know.\n\n".to_string()),
            Segment::Cipher("How dreary to be somebody!\nHow public, like a frog\nTo tell your name the livelong day".to_string()),
            Segment::Content("\nTo an admiring bog!".to_string())
), answer);
    }
}
