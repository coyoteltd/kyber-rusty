use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ml_kem::{
    kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey},
    Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params,
};
use rand::RngCore;
use std::{panic, ptr, slice};

const OK: i32 = 0;
const ERR_NULL: i32 = -1;
const ERR_INPUT_LEN: i32 = -2;
const ERR_CRYPTO: i32 = -3;
const ERR_OUTPUT_LEN: i32 = -4;
const ERR_PANIC: i32 = -5;

const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
const MLKEM768_SECRET_KEY_BYTES: usize = 2400;
const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;
const MLKEM768_SHARED_SECRET_BYTES: usize = 32;

const XCHACHA20POLY1305_KEY_BYTES: usize = 32;
const XCHACHA20POLY1305_NONCE_BYTES: usize = 24;
const XCHACHA20POLY1305_TAG_BYTES: usize = 16;

const BLAKE2B_512_BYTES: usize = 64;

fn const_ptr_ok<T>(p: *const T, len: usize) -> bool {
    len == 0 || !p.is_null()
}

fn mut_ptr_ok<T>(p: *mut T, len: usize) -> bool {
    len == 0 || !p.is_null()
}

fn parse_mlkem768_public_key(
    bytes: &[u8],
) -> Result<EncapsulationKey<MlKem768Params>, i32> {
    if bytes.len() != MLKEM768_PUBLIC_KEY_BYTES {
        return Err(ERR_INPUT_LEN);
    }
    let enc: Encoded<EncapsulationKey<MlKem768Params>> =
        bytes.try_into().map_err(|_| ERR_INPUT_LEN)?;
    Ok(EncapsulationKey::<MlKem768Params>::from_bytes(&enc))
}

fn parse_mlkem768_secret_key(
    bytes: &[u8],
) -> Result<DecapsulationKey<MlKem768Params>, i32> {
    if bytes.len() != MLKEM768_SECRET_KEY_BYTES {
        return Err(ERR_INPUT_LEN);
    }
    let enc: Encoded<DecapsulationKey<MlKem768Params>> =
        bytes.try_into().map_err(|_| ERR_INPUT_LEN)?;
    Ok(DecapsulationKey::<MlKem768Params>::from_bytes(&enc))
}

fn parse_mlkem768_ciphertext(
    bytes: &[u8],
) -> Result<Ciphertext<MlKem768>, i32> {
    if bytes.len() != MLKEM768_CIPHERTEXT_BYTES {
        return Err(ERR_INPUT_LEN);
    }
    bytes.try_into().map_err(|_| ERR_INPUT_LEN)
}

// ── Size query functions ──────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_public_key_bytes() -> usize {
    MLKEM768_PUBLIC_KEY_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_secret_key_bytes() -> usize {
    MLKEM768_SECRET_KEY_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_ciphertext_bytes() -> usize {
    MLKEM768_CIPHERTEXT_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_shared_secret_bytes() -> usize {
    MLKEM768_SHARED_SECRET_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20poly1305_key_bytes() -> usize {
    XCHACHA20POLY1305_KEY_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20poly1305_nonce_bytes() -> usize {
    XCHACHA20POLY1305_NONCE_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20poly1305_tag_bytes() -> usize {
    XCHACHA20POLY1305_TAG_BYTES
}

#[unsafe(no_mangle)]
pub extern "C" fn blake2b_512_bytes() -> usize {
    BLAKE2B_512_BYTES
}

// ── ML-KEM 768 ────────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_keygen(
    public_key_out: *mut u8,
    public_key_out_len: usize,
    secret_key_out: *mut u8,
    secret_key_out_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !mut_ptr_ok(public_key_out, public_key_out_len)
            || !mut_ptr_ok(secret_key_out, secret_key_out_len)
        {
            return ERR_NULL;
        }
        if public_key_out_len != MLKEM768_PUBLIC_KEY_BYTES
            || secret_key_out_len != MLKEM768_SECRET_KEY_BYTES
        {
            return ERR_INPUT_LEN;
        }

        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);

        let pk = ek.as_bytes();
        let sk = dk.as_bytes();

        unsafe {
            ptr::copy_nonoverlapping(
                pk.as_slice().as_ptr(),
                public_key_out,
                MLKEM768_PUBLIC_KEY_BYTES,
            );
            ptr::copy_nonoverlapping(
                sk.as_slice().as_ptr(),
                secret_key_out,
                MLKEM768_SECRET_KEY_BYTES,
            );
        }

        OK
    });
    result.unwrap_or(ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_encaps(
    public_key: *const u8,
    public_key_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
    shared_secret_out: *mut u8,
    shared_secret_out_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !const_ptr_ok(public_key, public_key_len)
            || !mut_ptr_ok(ciphertext_out, ciphertext_out_len)
            || !mut_ptr_ok(shared_secret_out, shared_secret_out_len)
        {
            return ERR_NULL;
        }
        if ciphertext_out_len != MLKEM768_CIPHERTEXT_BYTES
            || shared_secret_out_len != MLKEM768_SHARED_SECRET_BYTES
        {
            return ERR_INPUT_LEN;
        }

        let public_key_bytes = unsafe { slice::from_raw_parts(public_key, public_key_len) };
        let ek = match parse_mlkem768_public_key(public_key_bytes) {
            Ok(v) => v,
            Err(e) => return e,
        };

        let mut rng = rand::thread_rng();
        let (ct, ss) = match ek.encapsulate(&mut rng) {
            Ok(v) => v,
            Err(_) => return ERR_CRYPTO,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                ct.as_slice().as_ptr(),
                ciphertext_out,
                MLKEM768_CIPHERTEXT_BYTES,
            );
            ptr::copy_nonoverlapping(
                ss.as_slice().as_ptr(),
                shared_secret_out,
                MLKEM768_SHARED_SECRET_BYTES,
            );
        }

        OK
    });
    result.unwrap_or(ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn mlkem768_decaps(
    secret_key: *const u8,
    secret_key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    shared_secret_out: *mut u8,
    shared_secret_out_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !const_ptr_ok(secret_key, secret_key_len)
            || !const_ptr_ok(ciphertext, ciphertext_len)
            || !mut_ptr_ok(shared_secret_out, shared_secret_out_len)
        {
            return ERR_NULL;
        }
        if shared_secret_out_len != MLKEM768_SHARED_SECRET_BYTES {
            return ERR_INPUT_LEN;
        }

        let secret_key_bytes = unsafe { slice::from_raw_parts(secret_key, secret_key_len) };
        let ciphertext_bytes = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };

        let dk = match parse_mlkem768_secret_key(secret_key_bytes) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ct = match parse_mlkem768_ciphertext(ciphertext_bytes) {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ss = match dk.decapsulate(&ct) {
            Ok(v) => v,
            Err(_) => return ERR_CRYPTO,
        };

        unsafe {
            ptr::copy_nonoverlapping(
                ss.as_slice().as_ptr(),
                shared_secret_out,
                MLKEM768_SHARED_SECRET_BYTES,
            );
        }

        OK
    });
    result.unwrap_or(ERR_PANIC)
}

// ── Blake2b-512 ───────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn blake2b_512_hash(
    input: *const u8,
    input_len: usize,
    output: *mut u8,
    output_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !const_ptr_ok(input, input_len) || !mut_ptr_ok(output, output_len) {
            return ERR_NULL;
        }
        if output_len != BLAKE2B_512_BYTES {
            return ERR_INPUT_LEN;
        }

        let input_bytes = unsafe { slice::from_raw_parts(input, input_len) };
        let digest = Blake2b512::digest(input_bytes);

        unsafe {
            ptr::copy_nonoverlapping(digest.as_slice().as_ptr(), output, BLAKE2B_512_BYTES);
        }

        OK
    });
    result.unwrap_or(ERR_PANIC)
}

// ── XChaCha20-Poly1305 ────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20poly1305_encrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut u8,
    ciphertext_out_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !const_ptr_ok(key, key_len)
            || !const_ptr_ok(nonce, nonce_len)
            || !const_ptr_ok(aad, aad_len)
            || !const_ptr_ok(plaintext, plaintext_len)
            || !mut_ptr_ok(ciphertext_out, ciphertext_out_len)
        {
            return ERR_NULL;
        }
        if key_len != XCHACHA20POLY1305_KEY_BYTES || nonce_len != XCHACHA20POLY1305_NONCE_BYTES {
            return ERR_INPUT_LEN;
        }

        let expected_out_len = plaintext_len + XCHACHA20POLY1305_TAG_BYTES;
        if ciphertext_out_len != expected_out_len {
            return ERR_OUTPUT_LEN;
        }

        let key_bytes       = unsafe { slice::from_raw_parts(key, key_len) };
        let nonce_bytes     = unsafe { slice::from_raw_parts(nonce, nonce_len) };
        let aad_bytes       = unsafe { slice::from_raw_parts(aad, aad_len) };
        let plaintext_bytes = unsafe { slice::from_raw_parts(plaintext, plaintext_len) };

        let cipher = match XChaCha20Poly1305::new_from_slice(key_bytes) {
            Ok(v) => v,
            Err(_) => return ERR_INPUT_LEN,
        };
        let ciphertext = match cipher.encrypt(
            XNonce::from_slice(nonce_bytes),
            Payload { msg: plaintext_bytes, aad: aad_bytes },
        ) {
            Ok(v) => v,
            Err(_) => return ERR_CRYPTO,
        };

        if ciphertext.len() != expected_out_len {
            return ERR_CRYPTO;
        }

        unsafe {
            ptr::copy_nonoverlapping(ciphertext.as_ptr(), ciphertext_out, expected_out_len);
        }

        OK
    });
    result.unwrap_or(ERR_PANIC)
}

#[unsafe(no_mangle)]
pub extern "C" fn xchacha20poly1305_decrypt(
    key: *const u8,
    key_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext_out: *mut u8,
    plaintext_out_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !const_ptr_ok(key, key_len)
            || !const_ptr_ok(nonce, nonce_len)
            || !const_ptr_ok(aad, aad_len)
            || !const_ptr_ok(ciphertext, ciphertext_len)
            || !mut_ptr_ok(plaintext_out, plaintext_out_len)
        {
            return ERR_NULL;
        }
        if key_len != XCHACHA20POLY1305_KEY_BYTES || nonce_len != XCHACHA20POLY1305_NONCE_BYTES {
            return ERR_INPUT_LEN;
        }
        if ciphertext_len < XCHACHA20POLY1305_TAG_BYTES {
            return ERR_INPUT_LEN;
        }

        let expected_plaintext_len = ciphertext_len - XCHACHA20POLY1305_TAG_BYTES;
        if plaintext_out_len != expected_plaintext_len {
            return ERR_OUTPUT_LEN;
        }

        let key_bytes       = unsafe { slice::from_raw_parts(key, key_len) };
        let nonce_bytes     = unsafe { slice::from_raw_parts(nonce, nonce_len) };
        let aad_bytes       = unsafe { slice::from_raw_parts(aad, aad_len) };
        let ciphertext_bytes = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len) };

        let cipher = match XChaCha20Poly1305::new_from_slice(key_bytes) {
            Ok(v) => v,
            Err(_) => return ERR_INPUT_LEN,
        };
        let plaintext = match cipher.decrypt(
            XNonce::from_slice(nonce_bytes),
            Payload { msg: ciphertext_bytes, aad: aad_bytes },
        ) {
            Ok(v) => v,
            Err(_) => return ERR_CRYPTO,
        };

        if plaintext.len() != expected_plaintext_len {
            return ERR_CRYPTO;
        }

        unsafe {
            ptr::copy_nonoverlapping(plaintext.as_ptr(), plaintext_out, expected_plaintext_len);
        }

        OK
    });
    result.unwrap_or(ERR_PANIC)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/// Fill `out` with cryptographically secure random bytes.
#[unsafe(no_mangle)]
pub extern "C" fn random_bytes(
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !mut_ptr_ok(out, out_len) {
            return ERR_NULL;
        }
        let mut rng = rand::thread_rng();
        let out_slice = unsafe { slice::from_raw_parts_mut(out, out_len) };
        rng.fill_bytes(out_slice);
        OK
    });
    result.unwrap_or(ERR_PANIC)
}

/// Constant-time byte slice comparison. Returns 1 if equal, 0 if not.
/// Never returns an error code — callers treat the return value as a boolean.
#[unsafe(no_mangle)]
pub extern "C" fn constant_time_eq(
    a: *const u8,
    a_len: usize,
    b: *const u8,
    b_len: usize,
) -> i32 {
    let result = panic::catch_unwind(|| {
        if !const_ptr_ok(a, a_len) || !const_ptr_ok(b, b_len) {
            return 0;
        }
        if a_len != b_len {
            return 0;
        }
        let a_slice = unsafe { slice::from_raw_parts(a, a_len) };
        let b_slice = unsafe { slice::from_raw_parts(b, b_len) };
        let diff = a_slice.iter().zip(b_slice.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y));
        if diff == 0 { 1 } else { 0 }
    });
    result.unwrap_or(0)
}
