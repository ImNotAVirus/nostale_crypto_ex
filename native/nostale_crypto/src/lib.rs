use rustler::{Binary, Env, NewBinary};

const LOGIN_SEPARATOR: u8 = 0xd8;

#[rustler::nif]
fn login_next<'a>(env: Env<'a>, raw: Binary<'a>) -> (Option<Binary<'a>>, Binary<'a>) {
    match next(raw.as_slice(), LOGIN_SEPARATOR) {
        Some((packet, remaining)) => {
            let mut pb = NewBinary::new(env, packet.len());
            pb.as_mut_slice().copy_from_slice(packet);
            let mut rb = NewBinary::new(env, remaining.len());
            rb.as_mut_slice().copy_from_slice(remaining);
            (Some(pb.into()), rb.into())
        }
        None => (None, raw),
    }
}

#[rustler::nif]
fn login_encrypt<'a>(env: Env<'a>, raw: String) -> Binary<'a> {
    let mut enc = Vec::with_capacity(raw.len());
    encrypt_login_packet(&mut enc, raw.as_bytes());
    let mut binary = NewBinary::new(env, enc.len());
    binary.as_mut_slice().copy_from_slice(&enc);

    binary.into()
}

fn encrypt_login_packet(dst: &mut Vec<u8>, raw: &[u8]) -> usize {
    for x in raw {
        dst.push(x.wrapping_add(0xf))
    }
    raw.len()
}

#[rustler::nif]
fn login_decrypt(raw: Binary) -> String {
    let dec: Vec<u8> = decrypt_login_packet(raw.as_slice());

    String::from_utf8(dec).unwrap()
}

fn decrypt_login_packet(raw: &[u8]) -> Vec<u8> {
    raw.into_iter()
        .map(|x| x.wrapping_sub(0xf) ^ 0xc3)
        .collect()
}

#[rustler::nif]
fn world_next<'a>(env: Env<'a>, raw: Binary<'a>, key: u16) -> (Option<Binary<'a>>, Binary<'a>) {
    let delimiter = pack_delimiter(cipher_offset(key), cipher_mode(key));
    match next(raw.as_slice(), delimiter) {
        Some((packet, remaining)) => {
            let mut pb = NewBinary::new(env, packet.len());
            pb.as_mut_slice().copy_from_slice(packet);
            let mut rb = NewBinary::new(env, remaining.len());
            rb.as_mut_slice().copy_from_slice(remaining);
            (Some(pb.into()), rb.into())
        }
        None => (None, raw),
    }
}

#[rustler::nif]
fn world_encrypt<'a>(env: Env<'a>, raw: String) -> Binary<'a> {
    let mut enc = Vec::with_capacity(raw.len() + 1);
    encrypt_world_packet(&mut enc, raw.as_bytes());
    let mut binary = NewBinary::new(env, enc.len());
    binary.as_mut_slice().copy_from_slice(&enc);
    binary.into()
}

pub fn encrypt_world_packet(dst: &mut Vec<u8>, packet: &[u8]) -> usize {
    let bytes = packet.iter().enumerate();
    let len = bytes.len();
    for (i, c) in bytes {
        if i % 0x7E != 0 {
            dst.push(!c);
        } else {
            let remaining = if len - i > 0x7E { 0x7E } else { len - i };
            dst.push(remaining.try_into().unwrap());
            dst.push(!c);
        }
    }
    dst.push(0xFF);
    packet.len()
}

#[rustler::nif]
pub fn world_session_decrypt<'a>(env: Env<'a>, packet: Binary<'a>) -> Binary<'a> {
    let mut enc = Vec::with_capacity(packet.len() * 2);
    decrypt_session_packet(&mut enc, packet.as_slice());
    let mut binary = NewBinary::new(env, enc.len());
    binary.as_mut_slice().copy_from_slice(&enc);
    binary.into()
}

fn decrypt_session_packet(dst: &mut Vec<u8>, src: &[u8]) -> usize {
    for b in src {
        let first_byte = b.wrapping_sub(0xF);
        let second_byte = first_byte & 0xF0;
        let first_key = first_byte - second_byte;
        let second_key = second_byte >> 0x4;
        dst.push(decrypt_session_byte(second_key));
        dst.push(decrypt_session_byte(first_key));
    }
    src.len()
}

#[rustler::nif]
pub fn world_channel_decrypt<'a>(env: Env<'a>, packet: Binary<'a>, key: u16) -> Binary<'a> {
    let mut dec = Vec::with_capacity(packet.len());
    decrypt_channel_packet(
        &mut dec,
        packet.as_slice(),
        cipher_offset(key),
        cipher_mode(key),
    );
    let mut binary = NewBinary::new(env, dec.len());
    binary.as_mut_slice().copy_from_slice(&dec);
    binary.into()
}

fn decrypt_channel_packet(dst: &mut Vec<u8>, packet: &[u8], offset: u8, mode: u8) -> usize {
    for b in packet {
        dst.push(match mode {
            0 => b.wrapping_sub(offset).wrapping_sub(0x40),
            1 => b.wrapping_add(offset).wrapping_add(0x40),
            2 => (b.wrapping_sub(offset).wrapping_sub(0x40)) ^ 0xC3,
            3 => (b.wrapping_add(offset).wrapping_add(0x40)) ^ 0xC3,
            _ => b.wrapping_sub(0xF),
        })
    }
    packet.len()
}

#[rustler::nif]
pub fn world_channel_unpack<'a>(env: Env<'a>, packet: Binary<'a>) -> Binary<'a> {
    let mut unpacked = Vec::with_capacity(packet.len());
    unpack_channel_packet(&mut unpacked, packet.as_slice());
    let mut binary = NewBinary::new(env, unpacked.len());
    binary.as_mut_slice().copy_from_slice(&unpacked);
    binary.into()
}

fn unpack_channel_packet(dst: &mut Vec<u8>, packet: &[u8]) -> usize {
    let mut index = 0;
    while packet.len() > index {
        index += unpack_channel_payload(dst, &packet[index..]);
    }
    index
}

fn unpack_channel_payload(dst: &mut Vec<u8>, src: &[u8]) -> usize {
    let mut index = 0;
    let len: usize = (src[index] & 0x7F).into();
    let flag = src[index] & 0x80;
    index += 1;
    index += if flag != 0 {
        unpack_channel_compact_payload(dst, &src[index..], len)
    } else {
        unpack_channel_linear_payload(dst, &src[index..], len)
    };
    index
}

const UNPACK_DECRYPTION_PERMUTATIONS: [u8; 16] = [
    0x00, 0x20, 0x2D, 0x2E, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0xFF, 0x00,
];

fn unpack_channel_compact_payload(dst: &mut Vec<u8>, src: &[u8], len: usize) -> usize {
    let mut index = 0;
    for _ in 0..((len + 1) / 2) {
        if index >= src.len() {
            break;
        }
        let two_chars = src[index];
        index += 1;
        let left_char: usize = (two_chars >> 4).into();
        dst.push(UNPACK_DECRYPTION_PERMUTATIONS[left_char]);
        let right_char: usize = (two_chars & 0xF).into();
        if right_char == 0 {
            break;
        }
        dst.push(UNPACK_DECRYPTION_PERMUTATIONS[right_char]);
    }
    index
}

fn unpack_channel_linear_payload(dst: &mut Vec<u8>, src: &[u8], len: usize) -> usize {
    dst.reserve(len);
    let mut index = 0;
    for _ in 0..len {
        if index >= src.len() {
            break;
        }
        dst.push(src[index] ^ 0xFF);
        index += 1;
    }
    index
}

fn decrypt_session_byte(key: u8) -> u8 {
    match key {
        0 => 0x20,
        1 => 0x20,
        2 => 0x2D,
        3 => 0x2E,
        _ => 0x2C + key,
    }
}

/// Decrypt the delimiter from a key.
fn pack_delimiter(offset: u8, mode: u8) -> u8 {
    match mode {
        0 => 0xFFu8.wrapping_add(offset).wrapping_add(0x40),
        1 => 0xFFu8.wrapping_sub(offset).wrapping_sub(0x40),
        2 => (0xFFu8 ^ 0xC3).wrapping_add(offset).wrapping_add(0x40),
        3 => (0xFFu8 ^ 0xC3).wrapping_sub(offset).wrapping_sub(0x40),
        _ => 0xFFu8.wrapping_add(0xF),
    }
}

/// Decrypt the offset from a key.
fn cipher_offset(key: u16) -> u8 {
    key as u8
}

/// Decrypt the mode from a key.
fn cipher_mode(key: u16) -> u8 {
    ((key >> 6) & 3) as u8
}

/// Get the next packet from a raw binary.
fn next<'a>(raw: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = raw.iter().position(|&r| r == delimiter);
    match index {
        Some(i) => Some((&raw[0..i], &raw[i + 1..])),
        _ => None,
    }
}

rustler::init!(
    "Elixir.NostaleCrypto.Native",
    [
        login_next,
        login_encrypt,
        login_decrypt,
        world_next,
        world_encrypt,
        world_session_decrypt,
        world_channel_decrypt,
        world_channel_unpack
    ]
);
