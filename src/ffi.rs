// Minimal FFI surface for libOQS when `--features liboqs` is enabled.
// Robust across libOQS versions: uses generic factories with ML-* and legacy fallbacks,
// and matches the C layout of OQS_KEM and OQS_SIG so length fields are correct.

#![cfg(feature = "liboqs")]

use crate::OqsError;
use core::ffi::{c_char, c_int, c_uint};
use std::ffi::CString;

#[link(name = "oqs")]
extern "C" {
    // ---- Generic KEM factory + ops ----
    fn OQS_KEM_new(method_name: *const c_char) -> *mut OQS_KEM;
    fn OQS_KEM_free(kem: *mut OQS_KEM);
    fn OQS_KEM_keypair(kem: *const OQS_KEM, pub_key: *mut u8, sec_key: *mut u8) -> c_int;
    fn OQS_KEM_encaps(kem: *const OQS_KEM, ct: *mut u8, ss: *mut u8, pub_key: *const u8) -> c_int;
    fn OQS_KEM_decaps(kem: *const OQS_KEM, ss: *mut u8, ct: *const u8, sec_key: *const u8)
        -> c_int;

    // ---- Generic SIG factory + ops ----
    fn OQS_SIG_new(method_name: *const c_char) -> *mut OQS_SIG;
    fn OQS_SIG_free(sig: *mut OQS_SIG);
    fn OQS_SIG_keypair(sig: *const OQS_SIG, pub_key: *mut u8, sec_key: *mut u8) -> c_int;
    fn OQS_SIG_sign(
        sig: *const OQS_SIG,
        sig_out: *mut u8,
        sig_len: *mut usize,
        msg: *const u8,
        msg_len: usize,
        sec_key: *const u8,
    ) -> c_int;
    fn OQS_SIG_verify(
        sig: *const OQS_SIG,
        msg: *const u8,
        msg_len: usize,
        sig_in: *const u8,
        sig_len: usize,
        pub_key: *const u8,
    ) -> c_int;
}

/// Full C layout for OQS_KEM (per liboqs headers)
#[repr(C)]
struct OQS_KEM {
    method_name: *const c_char,
    alg_version: *const c_char,
    claimed_nist_level: c_uint,
    ind_cca: c_uint,
    length_public_key: usize,
    length_secret_key: usize,
    length_ciphertext: usize,
    length_shared_secret: usize,
    keypair_fn: *const core::ffi::c_void,
    encaps_fn: *const core::ffi::c_void,
    decaps_fn: *const core::ffi::c_void,
}

/// Full C layout for OQS_SIG (per liboqs headers)
#[repr(C)]
struct OQS_SIG {
    method_name: *const c_char,
    alg_version: *const c_char,
    claimed_nist_level: c_uint,
    euf_cma: c_uint,
    length_public_key: usize,
    length_secret_key: usize,
    length_signature: usize,
    keypair_fn: *const core::ffi::c_void,
    sign_fn: *const core::ffi::c_void,
    verify_fn: *const core::ffi::c_void,
}

// ---------- helpers: factories with fallback names ----------

unsafe fn kem_new_with_fallback() -> *mut OQS_KEM {
    for name in ["ML-KEM-768", "Kyber768"] {
        let cname = CString::new(name).expect("CString::new failed");
        let ptr = unsafe { OQS_KEM_new(cname.as_ptr()) };
        if !ptr.is_null() {
            return ptr;
        }
    }
    core::ptr::null_mut()
}

unsafe fn sig_new_with_fallback() -> *mut OQS_SIG {
    for name in ["ML-DSA-44", "Dilithium2", "ML-DSA-2"] {
        let cname = CString::new(name).expect("CString::new failed");
        let ptr = unsafe { OQS_SIG_new(cname.as_ptr()) };
        if !ptr.is_null() {
            return ptr;
        }
    }
    core::ptr::null_mut()
}

// ----------------- KEM (Kyber/ML-KEM-768) -----------------

pub fn kyber768_keypair() -> Result<(Vec<u8>, Vec<u8>), OqsError> {
    unsafe {
        let kem = kem_new_with_fallback();
        if kem.is_null() {
            return Err(OqsError::Internal("kem new"));
        }
        let lengths = &*kem;
        let mut pk = vec![0u8; lengths.length_public_key];
        let mut sk = vec![0u8; lengths.length_secret_key];
        let rc = OQS_KEM_keypair(kem, pk.as_mut_ptr(), sk.as_mut_ptr());
        OQS_KEM_free(kem);
        if rc != 0 {
            return Err(OqsError::Internal("kem keypair"));
        }
        Ok((pk, sk))
    }
}

pub fn kyber768_encapsulate(pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), OqsError> {
    unsafe {
        let kem = kem_new_with_fallback();
        if kem.is_null() {
            return Err(OqsError::Internal("kem new"));
        }
        let lengths = &*kem;

        if pk.len() != lengths.length_public_key {
            OQS_KEM_free(kem);
            return Err(OqsError::InvalidLength);
        }

        let mut ct = vec![0u8; lengths.length_ciphertext];
        let mut ss = vec![0u8; lengths.length_shared_secret];
        let rc = OQS_KEM_encaps(kem, ct.as_mut_ptr(), ss.as_mut_ptr(), pk.as_ptr());
        OQS_KEM_free(kem);
        if rc != 0 {
            return Err(OqsError::Internal("kem encaps"));
        }
        Ok((ct, ss))
    }
}

pub fn kyber768_decapsulate(ct: &[u8], sk: &[u8]) -> Result<Vec<u8>, OqsError> {
    unsafe {
        let kem = kem_new_with_fallback();
        if kem.is_null() {
            return Err(OqsError::Internal("kem new"));
        }
        let lengths = &*kem;
        if ct.len() != lengths.length_ciphertext || sk.len() != lengths.length_secret_key {
            OQS_KEM_free(kem);
            return Err(OqsError::InvalidLength);
        }
        let mut ss = vec![0u8; lengths.length_shared_secret];
        let rc = OQS_KEM_decaps(kem, ss.as_mut_ptr(), ct.as_ptr(), sk.as_ptr());
        OQS_KEM_free(kem);
        if rc != 0 {
            return Err(OqsError::Internal("kem decaps"));
        }
        Ok(ss)
    }
}

// ----------------- SIG (Dilithium2 / ML-DSA-44/2) -----------------

pub fn dilithium2_keypair() -> Result<(Vec<u8>, Vec<u8>), OqsError> {
    unsafe {
        let sig = sig_new_with_fallback();
        if sig.is_null() {
            return Err(OqsError::Internal("sig new"));
        }
        let lengths = &*sig;
        let mut pk = vec![0u8; lengths.length_public_key];
        let mut sk = vec![0u8; lengths.length_secret_key];
        let rc = OQS_SIG_keypair(sig, pk.as_mut_ptr(), sk.as_mut_ptr());
        OQS_SIG_free(sig);
        if rc != 0 {
            return Err(OqsError::Internal("sig keypair"));
        }
        Ok((pk, sk))
    }
}

pub fn dilithium2_sign(sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, OqsError> {
    unsafe {
        let sig = sig_new_with_fallback();
        if sig.is_null() {
            return Err(OqsError::Internal("sig new"));
        }
        let lengths = &*sig;

        if sk.len() != lengths.length_secret_key {
            OQS_SIG_free(sig);
            return Err(OqsError::InvalidLength);
        }

        let mut out = vec![0u8; lengths.length_signature];
        let mut out_len: usize = 0;
        let rc = OQS_SIG_sign(
            sig,
            out.as_mut_ptr(),
            &mut out_len,
            msg.as_ptr(),
            msg.len(),
            sk.as_ptr(),
        );
        OQS_SIG_free(sig);
        if rc != 0 {
            return Err(OqsError::Internal("sig sign"));
        }
        if out_len > out.len() {
            return Err(OqsError::Internal("sig out_len"));
        }
        out.truncate(out_len);
        Ok(out)
    }
}

pub fn dilithium2_verify(pk: &[u8], msg: &[u8], sig_in: &[u8]) -> Result<(), OqsError> {
    unsafe {
        let sig = sig_new_with_fallback();
        if sig.is_null() {
            return Err(OqsError::Internal("sig new"));
        }
        let lengths = &*sig;

        if pk.len() != lengths.length_public_key || sig_in.len() > lengths.length_signature {
            OQS_SIG_free(sig);
            return Err(OqsError::InvalidLength);
        }

        let rc = OQS_SIG_verify(
            sig,
            msg.as_ptr(),
            msg.len(),
            sig_in.as_ptr(),
            sig_in.len(),
            pk.as_ptr(),
        );
        OQS_SIG_free(sig);
        if rc != 0 {
            return Err(OqsError::VerifyFail);
        }
        Ok(())
    }
}
