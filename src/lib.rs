mod tests;

#[macro_use(defer)]
extern crate scopeguard;

use base64::{DecodeError, Engine as _, engine::general_purpose::URL_SAFE};
use derive_getters::Getters;
use fs::read_to_string;
use im::Vector;
use lazy_static::lazy_static;
use rand::Rng;
use regex::Regex;
use std::error::Error;
use std::fmt::Display;
use std::fs::{OpenOptions, exists};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::Command;
use std::rc::Rc;
use std::string::FromUtf8Error;
use std::{fs, iter};

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
pub enum Segment {
    Secure(String),
    Cipher(String),
    Text(String),
}

pub type SegmentMap = Vector<Rc<Segment>>;
type CipherFn<'a> = dyn Fn(&String) -> Result<String, AppError> + 'a;

fn random_chars() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    let one_char = || CHARSET[rng.random_range(0..CHARSET.len())] as char;
    iter::repeat_with(one_char).take(7).collect()
}

fn create_temp_file(path: &str) -> Result<String, AppError> {
    let orig = OpenOptions::new().read(true).open(path)?;
    let mode = orig.metadata()?.permissions().mode();
    for _index in 0..50 {
        let temp_path = format!("_cipher_{}_{}", random_chars(), path);
        if exists(&temp_path)? {
            continue;
        }
        let _file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(mode)
            .open(&temp_path)?;
        return Ok(temp_path);
    }
    Err(AppError::from_str("output", "Failed to create temp file"))
}

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
            Segment::Secure(plain) => {
                let cipher = op(plain)?;
                answer.push_back(Rc::new(Segment::Cipher(cipher)));
            }
            _ => answer.push_back(Rc::clone(seg)),
        }
    }
    Ok(answer)
}

fn rewind(segments: SegmentMap, op: &CipherFn) -> Result<SegmentMap, AppError> {
    let mut answer: SegmentMap = Vector::new();
    for seg in segments.iter() {
        match seg.as_ref() {
            Segment::Cipher(cipher) => {
                let plain = op(cipher)?;
                answer.push_back(Rc::new(Segment::Secure(plain)));
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
                answer.push_back(Rc::new(Segment::Text(plain)));
            }
            Segment::Secure(plain) => {
                answer.push_back(Rc::new(Segment::Text(plain.clone())));
            }
            Segment::Text(_) => answer.push_back(Rc::clone(seg)),
        }
    }
    Ok(answer)
}

/// Converts a vector of segments into a String.  The vector must only contain
/// Text and Secure segments.
fn expand(segments: SegmentMap) -> Result<String, AppError> {
    let mut answer = String::new();
    for seg in segments.iter() {
        match seg.as_ref() {
            Segment::Text(text) => {
                answer += text;
            }
            Segment::Secure(plain) => {
                answer += plain;
            }
            Segment::Cipher(_) => {
                return Err(AppError::from_str(
                    "expand",
                    "Encountered Cipher segment during expansion:",
                ));
            }
        }
    }
    Ok(answer)
}

/// Combines a vector of segments into a String.  Markers are created for
/// each segment.
fn combine(segments: SegmentMap) -> Result<String, AppError> {
    let mut answer = String::new();
    for seg in segments.iter() {
        match seg.as_ref() {
            Segment::Text(text) => {
                answer += text;
            }
            Segment::Secure(plain) => {
                answer += "<<SECURE>>";
                answer += plain;
                answer += "<</SECURE>>";
            }
            Segment::Cipher(cipher) => {
                answer += "<<CIPHER>>";
                answer += cipher;
                answer += "<</CIPHER>>";
            }
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
                            Segment::Secure(content)
                        } else {
                            Segment::Cipher(content)
                        };
                        answer.push_back(Rc::new(segment));
                        expected = None
                    }
                    None => {
                        if !content.is_empty() {
                            let segment = Segment::Text(content);
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
                    let segment = Segment::Text(text);
                    answer.push_back(Rc::new(segment));
                }
                break;
            }
        }
    }
    Ok(answer)
}

fn load_file(filename: &str) -> Result<Vector<Rc<Segment>>, AppError> {
    let source = read_to_string(filename)?;
    parse_source(source)
}

fn write_file(filename: &str, contents: &String) -> Result<(), AppError> {
    Ok(fs::write(filename, contents)?)
}

fn replace_file(temp_file: &str, real_file: &str) -> Result<(), AppError> {
    Ok(fs::rename(temp_file, real_file)?)
}

fn delete_file(temp_file: &str) -> Result<(), AppError> {
    if exists(temp_file)? {
        fs::remove_file(temp_file)?;
    }
    Ok(())
}

pub fn cat_command(input_filename: &str) -> Result<(), AppError> {
    let segments = load_file(input_filename)?;
    let decrypted = decrypt(segments, &|s| base64_decode(s))?;
    let expanded = expand(decrypted)?;
    print!("{}", expanded);
    Ok(())
}

pub fn decrypt_command(input_filename: &str, output_filename: &str) -> Result<(), AppError> {
    let segments = load_file(input_filename)?;
    let decrypted = decrypt(segments, &|s| base64_decode(s))?;
    let expanded = expand(decrypted)?;
    let temp_filename = create_temp_file(input_filename)?;
    defer! {
        delete_file(&temp_filename).unwrap_or(());
    }
    write_file(&temp_filename, &expanded)?;
    replace_file(&temp_filename, output_filename)?;
    Ok(())
}

pub fn encrypt_command(input_filename: &str, output_filename: &str) -> Result<(), AppError> {
    let segments = load_file(input_filename)?;
    let encrypted = encrypt(segments, &|s| base64_encode(s))?;
    let contents = combine(encrypted)?;
    let temp_filename = create_temp_file(input_filename)?;
    defer! {
        delete_file(&temp_filename).unwrap_or(());
    }
    write_file(&temp_filename, &contents)?;
    replace_file(&temp_filename, output_filename)?;
    Ok(())
}

pub fn rewind_command(input_filename: &str, output_filename: &str) -> Result<(), AppError> {
    let segments = load_file(input_filename)?;
    let rewound = rewind(segments, &|s| base64_decode(s))?;
    let contents = combine(rewound)?;
    let temp_filename = create_temp_file(input_filename)?;
    defer! {
        delete_file(&temp_filename).unwrap_or(());
    }
    write_file(&temp_filename, &contents)?;
    replace_file(&temp_filename, output_filename)?;
    Ok(())
}

pub fn edit_command(input_filename: &str, output_filename: &str) -> Result<(), AppError> {
    // set up a rewound temp file for the editor
    let orig_segments = load_file(input_filename)?;
    let orig_rewound = rewind(orig_segments, &|s| base64_decode(s))?;
    let orig_contents = combine(orig_rewound)?;
    let temp_filename = create_temp_file(input_filename)?;
    defer! {
        delete_file(&temp_filename).unwrap_or(());
    }
    write_file(&temp_filename, &orig_contents)?;

    // run the editor on the temp file
    let status = Command::new("vi").arg(&temp_filename).spawn()?.wait()?;
    if !status.success() {
        return Err(AppError::from_str("edit command", "editor command failed"));
    }

    // see if the file was changed
    let new_segments = load_file(&temp_filename)?;
    let new_rewound = rewind(new_segments.clone(), &|s| base64_decode(s))?;
    let new_contents = combine(new_rewound)?;
    if orig_contents == new_contents {
        return Ok(());
    }

    // encrypt the modified temp file and store it as the output file
    let encrypted = encrypt(new_segments, &|s| base64_encode(s))?;
    let encrypted_contents = combine(encrypted)?;
    write_file(&temp_filename, &encrypted_contents)?;
    replace_file(&temp_filename, output_filename)?;
    Ok(())
}
