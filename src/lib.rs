use cfg_if::cfg_if;
use std::sync::{Once};
use std::{u64, slice};
use std::os::raw::c_void;
use pocc::plot::NONCE_SIZE;
use pocc::plot::SCOOP_SIZE;
use crate::simd::SimdExtension;
use std::ffi::CString;
use once_cell::sync::Lazy;

mod pocc;
mod simd;
mod shabal;
mod curve25519;
mod scoops;

extern "C" {
    pub fn find_best_deadline_sph(
        scoops: *const u8,
        nonce_count: u64,
        gensig: *const u8,
        best_deadline: *mut u64,
        best_offset: *mut u64,
    );
}

cfg_if! {
    if #[cfg(feature = "simd")] {
        extern "C" {
            pub fn init_shabal_avx512f();
            pub fn find_best_deadline_avx512f(
                scoops: *const u8,
                nonce_count: u64,
                gensig: *const u8,
                best_deadline: *mut u64,
                best_offset: *mut u64,
            );

            pub fn init_shabal_avx2();
            pub fn find_best_deadline_avx2(
                scoops: *const u8,
                nonce_count: u64,
                gensig: *const u8,
                best_deadline: *mut u64,
                best_offset: *mut u64,
            );

            pub fn init_shabal_avx();
            pub fn find_best_deadline_avx(
                scoops: *const u8,
                nonce_count: u64,
                gensig: *const u8,
                best_deadline: *mut u64,
                best_offset: *mut u64,
            );

            pub fn init_shabal_sse2();
            pub fn find_best_deadline_sse2(
                scoops: *const u8,
                nonce_count: u64,
                gensig: *const u8,
                best_deadline: *mut u64,
                best_offset: *mut u64,
            );

            pub fn init_noncegen_sse2();
            pub fn noncegen_sse2(
                cache: *mut u8,
                numeric_ID: u64,
                local_startnonce: u64,
                local_nonces: u64,
                poc_version: u8,
            );

            pub fn init_noncegen_avx();
            pub fn noncegen_avx(
                cache: *mut u8,
                numeric_ID: u64,
                local_startnonce: u64,
                local_nonces: u64,
                poc_version: u8,
            );

            pub fn init_noncegen_avx2();
            pub fn noncegen_avx2(
                cache: *mut u8,
                numeric_ID: u64,
                local_startnonce: u64,
                local_nonces: u64,
                poc_version: u8,
            );

            pub fn init_noncegen_avx512f();
            pub fn noncegen_avx512(
                cache: *mut u8,
                numeric_ID: u64,
                local_startnonce: u64,
                local_nonces: u64,
                poc_version: u8,
            );
        }
    }
}

cfg_if! {
    if #[cfg(feature = "neon")] {
        extern "C" {
            pub fn init_shabal_neon();
            pub fn find_best_deadline_neon(
                scoops: *const u8,
                nonce_count: u64,
                gensig: *const u8,
                best_deadline: *mut u64,
                best_offset: *mut u64,
            );
        }
    }
}

static VERSION: Lazy<CString> = Lazy::new(|| {
    return CString::new("v".to_owned() + env!("CARGO_PKG_VERSION")).expect("Failed to create version string");
});

#[no_mangle]
pub extern "C" fn libshabal_version() -> *const u8 {
    return VERSION.as_ptr() as *const u8;
}

#[no_mangle]
pub extern "C" fn shabal_findBestDeadlineDirect(
    scoops: *const u8,
    nonce_count: u64,
    gensig: *const u8,
    best_deadline: *mut u64,
    best_offset: *mut u64,
) {
    let supported_extension: &SimdExtension = &simd::SUPPORTED_SIMD_EXTENSION;
    unsafe {
        match supported_extension {
            simd::SimdExtension::AVX512f => {
                #[cfg(feature = "simd")] find_best_deadline_avx512f(scoops, nonce_count, gensig, best_deadline, best_offset);
            },
            simd::SimdExtension::AVX2 => {
                #[cfg(feature = "simd")] find_best_deadline_avx2(scoops, nonce_count, gensig, best_deadline, best_offset);
            },
            simd::SimdExtension::AVX => {
                #[cfg(feature = "simd")] find_best_deadline_avx(scoops, nonce_count, gensig, best_deadline, best_offset);
            },
            simd::SimdExtension::SSE2 => {
                #[cfg(feature = "simd")] find_best_deadline_sse2(scoops, nonce_count, gensig, best_deadline, best_offset);
            },
            simd::SimdExtension::NEON => {
                #[cfg(feature = "neon")] find_best_deadline_neon(scoops, nonce_count, gensig, best_deadline, best_offset);
            },
            simd::SimdExtension::NONE => find_best_deadline_sph(scoops, nonce_count, gensig, best_deadline, best_offset),
        }
    }
}

#[no_mangle]
pub extern "C" fn shabal_init() {
    static INITIALIZE: Once = Once::new();
    INITIALIZE.call_once(|| {
        let supported_extension: &SimdExtension = &simd::SUPPORTED_SIMD_EXTENSION;
        match supported_extension {
            simd::SimdExtension::AVX512f => {
                #[cfg(feature = "simd")] unsafe {
                    init_shabal_avx512f();
                    init_noncegen_avx512f();
                }
            },
            simd::SimdExtension::AVX2 => {
                #[cfg(feature = "simd")] unsafe {
                    init_shabal_avx2();
                    init_noncegen_avx2();
                }
            },
            simd::SimdExtension::AVX => {
                #[cfg(feature = "simd")] unsafe {
                    init_shabal_avx();
                    init_noncegen_avx();
                }
            },
            simd::SimdExtension::SSE2 => {
                #[cfg(feature = "simd")] unsafe {
                    init_shabal_sse2();
                    init_noncegen_sse2();
                }
            },
            simd::SimdExtension::NEON => {
                #[cfg(feature = "neon")] unsafe {
                    init_shabal_neon();
                }
            },
            _ => {}
        }
    });
}

#[no_mangle]
pub extern "C" fn shabal_findBestDeadline(
    scoops: *const u8,
    nonce_count: u64,
    gensig: *const u8,
) -> u64 {
    let mut deadline: u64 = u64::MAX;
    let mut offset: u64 = 0;
    shabal_findBestDeadlineDirect(scoops, nonce_count, gensig, &mut deadline, &mut offset);
    return offset;
}

/// Create a new Shabal256 instance
///
/// Returns a pointer to the instance, which
/// can be used with the other functions to
/// manipulate the instance.
///
/// This implementation of Shabal256 is not particularly
/// fast but is here for completeness.
#[no_mangle]
pub extern "C" fn shabal256_new() -> *mut c_void {
    return shabal::shabal256_new()
}

/// Destroy a Shabal256 instance, clearing memory allocated for it.
///
/// `shabal` is the pointer to the instance returned from `shabal256_new()`
#[no_mangle]
pub extern "C" fn shabal256_destroy(shabal: *mut c_void) {
    shabal::shabal256_destroy(shabal)
}

/// Reset a Shabal256 instance to its initial state
///
/// `shabal` is the pointer to the instance returned from `shabal256_new()`
#[no_mangle]
pub extern "C" fn shabal256_reset(shabal: *mut c_void) {
    shabal::shabal256_reset(shabal);
}

/// Update a Shabal256 instance with new input data
///
/// `shabal` is the pointer to the instance returned from `shabal256_new()`
///
/// Inputs data into the digest from `data` starting at `offset` of length `len`
#[no_mangle]
pub extern "C" fn shabal256_update(shabal: *mut c_void, data: *const u8, offset: usize, len: usize) {
    shabal::shabal256_update(shabal, data, offset, len);
}

/// Retrieve the result of a Shabal256 digest and reset the digest.
///
/// Stores the data in `buffer` starting from `offset`. Stores 32 bytes of hash data.
///
/// `buffer` must have 32 bytes available from `offset` otherwise this will attempt to write beyond the array.
#[no_mangle]
pub extern "C" fn shabal256_digest(shabal: *mut c_void, buffer: *mut u8, offset: usize) {
    shabal::shabal256_digest(shabal, buffer, offset);
}

/// Creates PoC Nonces, with SIMD instructions for extra speed.
///
/// `plot_buffer` must be correct size - no size checks are performed.
///
/// `nonce_count` counts from 1 - 0 is no plots and will do nothing.
#[no_mangle]
pub extern "C" fn create_plots(
    account_id: u64,
    start_nonce: u64,
    nonce_count: u64,
    poc_version: u8,
    plot_buffer: *mut u8,
    plot_buffer_offset: usize,
) {
    if nonce_count == 0 { return; }
    let supported_extension: &SimdExtension = &simd::SUPPORTED_SIMD_EXTENSION;
    unsafe {
        let offset_plot_buffer = plot_buffer.add(plot_buffer_offset);
        match supported_extension {
            simd::SimdExtension::AVX512f => {
                #[cfg(feature = "simd")]
                    noncegen_avx512(offset_plot_buffer, account_id, start_nonce, nonce_count, poc_version);
            },
            simd::SimdExtension::AVX2 => {
                #[cfg(feature = "simd")]
                    noncegen_avx2(offset_plot_buffer, account_id, start_nonce, nonce_count, poc_version);
            },
            simd::SimdExtension::AVX => {
                #[cfg(feature = "simd")]
                    noncegen_avx(offset_plot_buffer, account_id, start_nonce, nonce_count, poc_version);
            },
            simd::SimdExtension::SSE2 => {
                #[cfg(feature = "simd")]
                    noncegen_sse2(offset_plot_buffer, account_id, start_nonce, nonce_count, poc_version);
            },
            _ => {
                let plot_buffer_borrowed = slice::from_raw_parts_mut(offset_plot_buffer, NONCE_SIZE * nonce_count as usize);
                pocc::plot::noncegen_rust(plot_buffer_borrowed, account_id, start_nonce, nonce_count, poc_version, );
            }
        }
    }
}

/// Creates a single PoC Nonce.
///
/// `plot_buffer` must be correct size - no size checks are performed.
#[no_mangle]
pub extern "C" fn create_plot(
    account_id: u64,
    nonce: u64,
    poc_version: u8,
    plot_buffer: *mut u8,
    plot_buffer_offset: usize,
) {
    unsafe {
        let offset_plot_buffer = plot_buffer.add(plot_buffer_offset);
        pocc::plot::noncegen_single_rust(
            slice::from_raw_parts_mut(offset_plot_buffer, NONCE_SIZE as usize),
            account_id,
            nonce,
            poc_version,
        );
    }
}

/// Creates a single PoC Scoop.
///
/// `plot_buffer` must be correct size - no size checks are performed.
#[no_mangle]
pub extern "C" fn create_scoop(
    account_id: u64,
    nonce: u64,
    scoop: u32,
    poc_version: u8,
    scoop_buffer: *mut u8,
    scoop_buffer_offset: usize,
) {
    let offset_scoop_buffer = unsafe { scoop_buffer.add(scoop_buffer_offset) };
    let mut buffer = [0u8; NONCE_SIZE];
    pocc::plot::noncegen_single_rust(
        &mut buffer,
        account_id,
        nonce,
        poc_version,
    );
    let scoop_buffer_borrowed = unsafe { slice::from_raw_parts_mut(offset_scoop_buffer, SCOOP_SIZE) };
    let offset = scoop as usize * SCOOP_SIZE;
    scoop_buffer_borrowed.copy_from_slice(&buffer[offset..offset + SCOOP_SIZE]);
}

/// Creates one PoC scoop for each (account id, nonce, scoop) triple, using SIMD instructions
/// where available. Meant for verifying a batch of blocks, which have unrelated generators and
/// nonces.
///
/// `account_ids`, `nonces` and `scoops` must hold `count` entries. Scoop `i` is written to
/// `scoop_buffer[scoop_buffer_offset + i * 64..]`, so `scoop_buffer` must hold `count * 64` bytes
/// from `scoop_buffer_offset`.
///
/// Returns 0 on success, -1 if a scoop number is not below 4096, -2 if the SIMD implementation
/// failed (memory allocation) and -3 for null pointers.
#[no_mangle]
pub extern "C" fn create_scoops(
    account_ids: *const u64,
    nonces: *const u64,
    scoops: *const u32,
    count: u32,
    poc_version: u8,
    scoop_buffer: *mut u8,
    scoop_buffer_offset: u32,
) -> i32 {
    if count == 0 {
        return 0;
    }
    if account_ids.is_null() || nonces.is_null() || scoops.is_null() || scoop_buffer.is_null() {
        return -3;
    }
    let count = count as usize;
    let result = unsafe {
        scoops::create_scoops(
            slice::from_raw_parts(account_ids, count),
            slice::from_raw_parts(nonces, count),
            slice::from_raw_parts(scoops, count),
            poc_version,
            slice::from_raw_parts_mut(scoop_buffer.add(scoop_buffer_offset as usize), count * SCOOP_SIZE),
        )
    };
    match result {
        Ok(()) => 0,
        Err(scoops::ScoopsError::InvalidScoop) => -1,
        Err(scoops::ScoopsError::SimdFailure) => -2,
        Err(scoops::ScoopsError::InvalidLength) => -3,
    }
}

#[no_mangle]
pub extern "C" fn curve25519_get_public_key(private_key: *mut u8, public_key_buffer: *mut u8) {
    unsafe {
        let private_key_borrowed = slice::from_raw_parts_mut(private_key, 32);
        let public_key_buffer_borrowed = slice::from_raw_parts_mut(public_key_buffer, 32);
        curve25519::get_public_key(private_key_borrowed, public_key_buffer_borrowed)
    }
}

#[no_mangle]
pub extern "C" fn curve25519_get_shared_secret(private_key: *mut u8, public_key: *mut u8, shared_secret_buffer: *mut u8) {
    unsafe {
        let private_key_borrowed = slice::from_raw_parts_mut(private_key, 32);
        let public_key_borrowed = slice::from_raw_parts_mut(public_key, 32);
        let shared_secret_buffer_borrowed = slice::from_raw_parts_mut(shared_secret_buffer, 32);
        curve25519::get_shared_secret(private_key_borrowed, public_key_borrowed, shared_secret_buffer_borrowed)
    }
}

#[no_mangle]
pub extern "C" fn curve25519_sign(private_key: *mut u8, message_sha256: *const u8, signature_buffer: *mut u8) {
    unsafe {
        let private_key_borrowed = slice::from_raw_parts_mut(private_key, 32);
        let message_sha256_borrowed = slice::from_raw_parts(message_sha256, 32);
        let signature_buffer_borrowed = slice::from_raw_parts_mut(signature_buffer, 64);
        curve25519::sign(private_key_borrowed, message_sha256_borrowed, signature_buffer_borrowed)
    }
}

/// `enforce_canonical` and the return value are u8 bools where 0 represents false and 1 represents true.
/// So, a return value of 1 indicates successful verification and a return value of 0 indicates unsuccessful verification.
#[no_mangle]
pub extern "C" fn curve25519_verify(public_key: *mut u8, signature: *const u8, message_sha256: *const u8, enforce_canonical: u8) -> u8 {
    unsafe {
        let public_key_borrowed = slice::from_raw_parts_mut(public_key, 32);
        let signature_borrowed = slice::from_raw_parts(signature, 64);
        let message_sha256_borrowed = slice::from_raw_parts(message_sha256, 32);
        return if curve25519::verify(public_key_borrowed, signature_borrowed, message_sha256_borrowed, enforce_canonical != 0) { 1 } else { 0 };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT_IDS: [u64; 3] = [6_502_115_112_683_865_257, 1, u64::MAX];
    const NONCES: [u64; 3] = [12_345_678, 0, u64::MAX];
    const SCOOPS: [u32; 3] = [0, 4095, 1234];

    fn single_scoop(i: usize, poc_version: u8) -> Vec<u8> {
        let mut scoop = vec![0u8; SCOOP_SIZE];
        create_scoop(ACCOUNT_IDS[i], NONCES[i], SCOOPS[i], poc_version, scoop.as_mut_ptr(), 0);
        scoop
    }

    #[test]
    fn create_scoops_export_writes_scoops_at_offset() {
        shabal_init();
        let offset = 7;
        let mut buffer = vec![0xAAu8; offset + 3 * SCOOP_SIZE + 5];
        let status = create_scoops(ACCOUNT_IDS.as_ptr(), NONCES.as_ptr(), SCOOPS.as_ptr(), 3, 2,
                                   buffer.as_mut_ptr(), offset as u32);
        assert_eq!(status, 0);
        assert!(buffer[..offset].iter().all(|&b| b == 0xAA), "bytes before the offset changed");
        assert!(buffer[offset + 3 * SCOOP_SIZE..].iter().all(|&b| b == 0xAA), "bytes after the scoops changed");
        for i in 0..3 {
            assert_eq!(buffer[offset + i * SCOOP_SIZE..offset + (i + 1) * SCOOP_SIZE].to_vec(), single_scoop(i, 2));
        }
    }

    #[test]
    fn create_scoops_export_rejects_invalid_scoop() {
        let mut buffer = vec![0u8; SCOOP_SIZE];
        let status = create_scoops(ACCOUNT_IDS.as_ptr(), NONCES.as_ptr(), [4096u32].as_ptr(), 1, 2, buffer.as_mut_ptr(), 0);
        assert_eq!(status, -1);
    }

    #[test]
    fn create_scoops_export_rejects_null_pointers() {
        let mut buffer = vec![0u8; SCOOP_SIZE];
        let status = create_scoops(std::ptr::null(), NONCES.as_ptr(), SCOOPS.as_ptr(), 1, 2, buffer.as_mut_ptr(), 0);
        assert_eq!(status, -3);
    }

    #[test]
    fn create_scoops_export_with_zero_count_does_nothing() {
        assert_eq!(create_scoops(std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, 2, std::ptr::null_mut(), 0), 0);
    }

    /// Guards the SIMD deadline search against the scalar C implementation.
    #[test]
    fn find_best_deadline_matches_scalar_reference() {
        shabal_init();
        let nonce_count = 2 * 16 + 3;
        let mut state: u32 = 0x1234_5678;
        let mut next = || { state ^= state << 13; state ^= state >> 17; state ^= state << 5; (state & 0xFF) as u8 };
        let scoops: Vec<u8> = (0..nonce_count * SCOOP_SIZE).map(|_| next()).collect();
        let gensig: Vec<u8> = (0..32).map(|_| next()).collect();

        let (mut deadline, mut offset) = (u64::MAX, 0u64);
        shabal_findBestDeadlineDirect(scoops.as_ptr(), nonce_count as u64, gensig.as_ptr(), &mut deadline, &mut offset);
        let (mut expected_deadline, mut expected_offset) = (u64::MAX, 0u64);
        unsafe {
            find_best_deadline_sph(scoops.as_ptr(), nonce_count as u64, gensig.as_ptr(), &mut expected_deadline, &mut expected_offset);
        }
        assert_eq!((deadline, offset), (expected_deadline, expected_offset));
    }

    /// Guards the SIMD plotting path (create_plots) against the single nonce path (create_plot),
    /// e.g. after making the per-file Shabal contexts static.
    #[test]
    fn create_plots_matches_create_plot() {
        shabal_init();
        let count = 2 * 16 + 3;
        let (account_id, start_nonce) = (ACCOUNT_IDS[0], 1_000u64);
        for &poc_version in &[1u8, 2u8] {
            let mut plots = vec![0u8; count * NONCE_SIZE];
            create_plots(account_id, start_nonce, count as u64, poc_version, plots.as_mut_ptr(), 0);
            let mut single = vec![0u8; NONCE_SIZE];
            for n in 0..count {
                create_plot(account_id, start_nonce + n as u64, poc_version, single.as_mut_ptr(), 0);
                assert!(plots[n * NONCE_SIZE..(n + 1) * NONCE_SIZE] == single[..], "nonce {} poc {}", n, poc_version);
            }
        }
    }
}

