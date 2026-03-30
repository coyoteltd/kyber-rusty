use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ml_kem::{
    kem::{Encapsulate, EncapsulationKey},
    Encoded, EncodedSizeUser, MlKem768Params,
};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
const XCHACHA20POLY1305_NONCE_BYTES: usize = 24;
const BLAKE2B_512_BYTES: usize = 64;

fn js_err(msg: &str) -> JsValue {
    JsValue::from_str(msg)
}

fn blake2b(input: &[u8]) -> [u8; BLAKE2B_512_BYTES] {
    let digest = Blake2b512::digest(input);
    let mut out = [0u8; BLAKE2B_512_BYTES];
    out.copy_from_slice(&digest);
    out
}

// Must match derive_keys() in paseto.lua exactly.
fn derive_keys(shared_secret: &[u8], n: &[u8]) -> ([u8; 32], [u8; XCHACHA20POLY1305_NONCE_BYTES]) {
    let mut ek_input = Vec::new();
    ek_input.extend_from_slice(shared_secret);
    ek_input.extend_from_slice(b"paseto-encryption-key");
    ek_input.extend_from_slice(n);
    let ek_hash = blake2b(&ek_input);

    let mut ek = [0u8; 32];
    let mut nonce = [0u8; XCHACHA20POLY1305_NONCE_BYTES];
    ek.copy_from_slice(&ek_hash[..32]);
    nonce.copy_from_slice(&ek_hash[32..56]);
    (ek, nonce)
}

// Pre-Authentication Encoding.
// Must match paseto.lua's pae() exactly.
fn pae(pieces: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(pieces.len() as u64).to_le_bytes());
    for piece in pieces {
        out.extend_from_slice(&(piece.len() as u64).to_le_bytes());
        out.extend_from_slice(piece);
    }
    out
}

fn b64url_decode(s: &str) -> Result<Vec<u8>, JsValue> {
    let s = s.replace('-', "+").replace('_', "/");
    let padded = match s.len() % 4 {
        2 => format!("{}==", s),
        3 => format!("{}=", s),
        _ => s.clone(),
    };
    base64_decode(&padded).map_err(|e| js_err(&format!("base64 decode: {}", e)))
}

fn base64_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let input = input.trim_end_matches('=');
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in input.chars() {
        let val = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' => 62,
            '/' => 63,
            _ => return Err("invalid base64 character"),
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

/// Encapsulate against the server's ML-KEM-768 public key.
///
/// `public_key` must be a 1184-byte Uint8Array containing the decoded
/// ML-KEM-768 public key.
///
/// Returns an object with:
/// - `ciphertext`: Uint8Array
/// - `shared_secret`: Uint8Array
#[wasm_bindgen]
pub fn encaps(public_key: &[u8]) -> Result<js_sys::Object, JsValue> {
    if public_key.len() != MLKEM768_PUBLIC_KEY_BYTES {
        return Err(js_err(&format!(
            "public key must be {} bytes", MLKEM768_PUBLIC_KEY_BYTES
        )));
    }

    let enc: Encoded<EncapsulationKey<MlKem768Params>> = public_key
        .try_into()
        .map_err(|_| js_err("invalid public key encoding"))?;

    let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&enc);

    // OsRng delegates to getrandom, which uses crypto.getRandomValues() in WASM.
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| js_err("encapsulation failed"))?;

    let obj = js_sys::Object::new();
    let ct_arr = js_sys::Uint8Array::from(ct.as_slice());
    let ss_arr = js_sys::Uint8Array::from(ss.as_slice());
    js_sys::Reflect::set(&obj, &"ciphertext".into(), &ct_arr)?;
    js_sys::Reflect::set(&obj, &"shared_secret".into(), &ss_arr)?;
    Ok(obj)
}

/// Verify and decrypt a PASETO v4 local token.
///
/// `shared_secret` must be the 32-byte shared secret returned from `encaps`.
/// `token` must be a `v4.local.` token.
///
/// Returns the decrypted claims as a UTF-8 string.
#[wasm_bindgen]
pub fn verify_paseto(shared_secret: &[u8], token: &str) -> Result<String, JsValue> {
    const HEADER: &str = "v4.local.";

    if !token.starts_with(HEADER) {
        return Err(js_err("invalid token header"));
    }

    let rest = &token[HEADER.len()..];
    let (payload_b64, footer_b64) = match rest.find('.') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, ""),
    };

    let footer = if footer_b64.is_empty() {
        vec![]
    } else {
        b64url_decode(footer_b64)?
    };

    let payload = b64url_decode(payload_b64)?;
    if payload.len() <= 32 {
        return Err(js_err("payload too short"));
    }

    let n = &payload[..32];
    let ciphertext = &payload[32..];

    let (ek, nonce) = derive_keys(shared_secret, n);

    let aad = pae(&[HEADER.as_bytes(), n, &footer]);

    let cipher = XChaCha20Poly1305::new_from_slice(&ek)
        .map_err(|_| js_err("key error"))?;

    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload { msg: ciphertext, aad: &aad },
        )
        .map_err(|_| js_err("decryption failed: token invalid or tampered"))?;

    String::from_utf8(plaintext).map_err(|_| js_err("claims are not valid UTF-8"))
}

/// Return a Uint8Array filled with cryptographically secure random bytes.
#[wasm_bindgen]
pub fn random_bytes(n: usize) -> Result<js_sys::Uint8Array, JsValue> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| js_err(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(buf.as_slice()))
}
