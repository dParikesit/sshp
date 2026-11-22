//! A reversible text view for the editor. OpenSSH configuration is a byte
//! stream on Unix; e.g. a legacy comment or filename need not be UTF-8.
use std::borrow::Cow;

const ESC: char = '\u{f0000}';
const BASE: u32 = 0xf0000;

fn byte_token(ch: char) -> bool {
    (BASE + 0x80..=BASE + 0xff).contains(&(ch as u32))
}

pub(crate) fn from_bytes(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for ch in chunk.valid().chars() {
            if ch == ESC || byte_token(ch) {
                text.push(ESC);
            }
            text.push(ch);
        }
        for &byte in chunk.invalid() {
            text.push(char::from_u32(BASE + u32::from(byte)).unwrap());
        }
    }
    text
}

pub(crate) fn to_bytes(text: &str) -> Cow<'_, [u8]> {
    if !text.chars().any(|c| c == ESC || byte_token(c)) {
        return Cow::Borrowed(text.as_bytes());
    }
    let mut bytes = Vec::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(mut ch) = chars.next() {
        if ch == ESC && chars.peek().is_some_and(|&c| c == ESC || byte_token(c)) {
            ch = chars.next().unwrap();
        } else if byte_token(ch) {
            bytes.push((ch as u32 - BASE) as u8);
            continue;
        }
        bytes.extend_from_slice(ch.encode_utf8(&mut [0; 4]).as_bytes());
    }
    Cow::Owned(bytes)
}

#[test]
fn arbitrary_unix_bytes_and_literal_private_use_characters_round_trip() {
    let bytes = [
        (1..=255).collect::<Vec<u8>>().as_slice(),
        "Host λ\n# \u{f0000}\u{f00ff}\u{f0000}\n".as_bytes(),
        b"\xf0\x90# truncated \xe0\xa0",
    ]
    .concat();
    assert_eq!(&*to_bytes(&from_bytes(&bytes)), bytes);
}
