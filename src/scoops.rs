//! Batched scoop creation: one scoop for each (account id, nonce, scoop) triple.
//!
//! Block verification needs one scoop per block, and the blocks of a batch have unrelated
//! generators and nonces. Generating them in SIMD lanes is several times faster than one nonce at
//! a time, because a nonce is a chain of 8192 Shabal256 hashes that cannot be shortened.

use crate::pocc::plot::{noncegen_single_rust, NONCE_SIZE, SCOOP_SIZE};
use crate::simd;

pub const NUM_SCOOPS: u32 = 4096;

/// Signature of the `noncegen_scoops_<simd>` C functions, see `noncegen_scoops_impl.h`.
type SimdScoopsFn = unsafe extern "C" fn(
    account_ids: *const u64,
    nonces: *const u64,
    scoops: *const u32,
    count: u64,
    poc_version: u8,
    out: *mut u8,
) -> i32;

#[cfg(feature = "simd")]
extern "C" {
    fn noncegen_scoops_sse2(account_ids: *const u64, nonces: *const u64, scoops: *const u32, count: u64, poc_version: u8, out: *mut u8) -> i32;
    fn noncegen_scoops_avx(account_ids: *const u64, nonces: *const u64, scoops: *const u32, count: u64, poc_version: u8, out: *mut u8) -> i32;
    fn noncegen_scoops_avx2(account_ids: *const u64, nonces: *const u64, scoops: *const u32, count: u64, poc_version: u8, out: *mut u8) -> i32;
    fn noncegen_scoops_avx512f(account_ids: *const u64, nonces: *const u64, scoops: *const u32, count: u64, poc_version: u8, out: *mut u8) -> i32;
}

/// The SIMD implementation for the detected CPU extension, with its number of lanes.
fn simd_scoops_fn(extension: &simd::SimdExtension) -> Option<(usize, SimdScoopsFn)> {
    match extension {
        #[cfg(feature = "simd")]
        simd::SimdExtension::AVX512f => Some((16, noncegen_scoops_avx512f)),
        #[cfg(feature = "simd")]
        simd::SimdExtension::AVX2 => Some((8, noncegen_scoops_avx2)),
        #[cfg(feature = "simd")]
        simd::SimdExtension::AVX => Some((4, noncegen_scoops_avx)),
        #[cfg(feature = "simd")]
        simd::SimdExtension::SSE2 => Some((4, noncegen_scoops_sse2)),
        _ => None,
    }
}

/// Error of [`create_scoops`].
#[derive(Debug, PartialEq)]
pub enum ScoopsError {
    /// The input slices or the output buffer have the wrong length.
    InvalidLength,
    /// A scoop number is not below [`NUM_SCOOPS`].
    InvalidScoop,
    /// The SIMD implementation failed (memory allocation).
    SimdFailure,
}

/// Writes scoop `scoops[i]` of nonce `nonces[i]` of account `account_ids[i]` to
/// `out[i * SCOOP_SIZE..(i + 1) * SCOOP_SIZE]`, using SIMD instructions where available.
pub fn create_scoops(
    account_ids: &[u64],
    nonces: &[u64],
    scoops: &[u32],
    poc_version: u8,
    out: &mut [u8],
) -> Result<(), ScoopsError> {
    create_scoops_with(simd_scoops_fn(&simd::SUPPORTED_SIMD_EXTENSION), account_ids, nonces, scoops, poc_version, out)
}

/// [`create_scoops`] with an explicit SIMD implementation (`None` = scalar only), so tests can
/// check every implementation the CPU supports.
pub(crate) fn create_scoops_with(
    simd_fn: Option<(usize, SimdScoopsFn)>,
    account_ids: &[u64],
    nonces: &[u64],
    scoops: &[u32],
    poc_version: u8,
    out: &mut [u8],
) -> Result<(), ScoopsError> {
    let count = account_ids.len();
    if nonces.len() != count || scoops.len() != count || out.len() != count * SCOOP_SIZE {
        return Err(ScoopsError::InvalidLength);
    }
    if scoops.iter().any(|&scoop| scoop >= NUM_SCOOPS) {
        return Err(ScoopsError::InvalidScoop);
    }

    let mut done = 0;
    if let Some((lanes, simd_fn)) = simd_fn {
        let full = count / lanes * lanes;
        if full > 0 {
            call_simd(simd_fn, &account_ids[..full], &nonces[..full], &scoops[..full], poc_version, &mut out[..full * SCOOP_SIZE])?;
            done = full;
        }
        // One padded SIMD batch costs less than two single nonces.
        let rest = count - full;
        if rest >= 2 {
            create_padded_batch(simd_fn, lanes, &account_ids[full..], &nonces[full..], &scoops[full..], poc_version, &mut out[full * SCOOP_SIZE..])?;
            done = count;
        }
    }

    if done < count {
        let mut nonce_buffer = vec![0u8; NONCE_SIZE];
        for i in done..count {
            noncegen_single_rust(&mut nonce_buffer, account_ids[i], nonces[i], poc_version);
            let offset = scoops[i] as usize * SCOOP_SIZE;
            out[i * SCOOP_SIZE..(i + 1) * SCOOP_SIZE].copy_from_slice(&nonce_buffer[offset..offset + SCOOP_SIZE]);
        }
    }
    Ok(())
}

/// Fills the unused lanes with copies of the last entry and keeps only the results of the real ones.
fn create_padded_batch(
    simd_fn: SimdScoopsFn,
    lanes: usize,
    account_ids: &[u64],
    nonces: &[u64],
    scoops: &[u32],
    poc_version: u8,
    out: &mut [u8],
) -> Result<(), ScoopsError> {
    let rest = account_ids.len();
    let pad = |values: &[u64]| -> Vec<u64> {
        let mut padded = values.to_vec();
        padded.resize(lanes, values[rest - 1]);
        padded
    };
    let mut padded_scoops = scoops.to_vec();
    padded_scoops.resize(lanes, scoops[rest - 1]);
    let mut padded_out = vec![0u8; lanes * SCOOP_SIZE];
    call_simd(simd_fn, &pad(account_ids), &pad(nonces), &padded_scoops, poc_version, &mut padded_out)?;
    out.copy_from_slice(&padded_out[..rest * SCOOP_SIZE]);
    Ok(())
}

fn call_simd(
    simd_fn: SimdScoopsFn,
    account_ids: &[u64],
    nonces: &[u64],
    scoops: &[u32],
    poc_version: u8,
    out: &mut [u8],
) -> Result<(), ScoopsError> {
    let status = unsafe {
        simd_fn(account_ids.as_ptr(), nonces.as_ptr(), scoops.as_ptr(), account_ids.len() as u64, poc_version, out.as_mut_ptr())
    };
    if status == 0 { Ok(()) } else { Err(ScoopsError::SimdFailure) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference: the existing single nonce implementation (same code path as `create_scoop`).
    fn reference_scoop(account_id: u64, nonce: u64, scoop: u32, poc_version: u8) -> Vec<u8> {
        let mut nonce_buffer = vec![0u8; NONCE_SIZE];
        noncegen_single_rust(&mut nonce_buffer, account_id, nonce, poc_version);
        let offset = scoop as usize * SCOOP_SIZE;
        nonce_buffer[offset..offset + SCOOP_SIZE].to_vec()
    }

    /// Unrelated accounts, nonces and scoops, including the edge scoops 0 and 4095.
    fn inputs(count: usize) -> (Vec<u64>, Vec<u64>, Vec<u32>) {
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let account_ids = (0..count).map(|_| next()).collect();
        let nonces = (0..count).map(|_| next()).collect();
        let scoops = (0..count)
            .map(|i| match i % 5 { 0 => 0, 1 => NUM_SCOOPS - 1, _ => (next() % NUM_SCOOPS as u64) as u32 })
            .collect();
        (account_ids, nonces, scoops)
    }

    fn assert_matches_reference(simd_fn: Option<(usize, SimdScoopsFn)>, count: usize, poc_version: u8) {
        let (account_ids, nonces, scoops) = inputs(count);
        let mut out = vec![0u8; count * SCOOP_SIZE];
        create_scoops_with(simd_fn, &account_ids, &nonces, &scoops, poc_version, &mut out).unwrap();
        for i in 0..count {
            assert_eq!(
                out[i * SCOOP_SIZE..(i + 1) * SCOOP_SIZE].to_vec(),
                reference_scoop(account_ids[i], nonces[i], scoops[i], poc_version),
                "count {} entry {} poc {} lanes {:?}", count, i, poc_version, simd_fn.map(|f| f.0)
            );
        }
    }

    /// Every SIMD implementation this CPU supports, plus the scalar path.
    fn implementations() -> Vec<Option<(usize, SimdScoopsFn)>> {
        crate::shabal_init();
        let mut implementations: Vec<Option<(usize, SimdScoopsFn)>> = vec![None];
        #[cfg(feature = "simd")]
        unsafe {
            if is_x86_feature_detected!("sse2") {
                crate::init_noncegen_sse2();
                implementations.push(Some((4, noncegen_scoops_sse2)));
            }
            if is_x86_feature_detected!("avx") {
                crate::init_noncegen_avx();
                implementations.push(Some((4, noncegen_scoops_avx)));
            }
            if is_x86_feature_detected!("avx2") {
                crate::init_noncegen_avx2();
                implementations.push(Some((8, noncegen_scoops_avx2)));
            }
            if is_x86_feature_detected!("avx512f") {
                crate::init_noncegen_avx512f();
                implementations.push(Some((16, noncegen_scoops_avx512f)));
            }
        }
        implementations
    }

    #[test]
    fn create_scoops_matches_single_nonce_reference_for_all_implementations() {
        for implementation in implementations() {
            let lanes = implementation.map_or(4, |f| f.0);
            for &count in &[1, 2, lanes - 1, lanes, lanes + 1, 2 * lanes + 3] {
                for &poc_version in &[1u8, 2u8] {
                    assert_matches_reference(implementation, count, poc_version);
                }
            }
        }
    }

    /// `cargo test --release -- --ignored --nocapture bench_create_scoops`
    #[test]
    #[ignore]
    fn bench_create_scoops() {
        let count = 64;
        let (account_ids, nonces, scoops) = inputs(count);
        let mut out = vec![0u8; count * SCOOP_SIZE];
        for implementation in implementations() {
            let start = std::time::Instant::now();
            create_scoops_with(implementation, &account_ids, &nonces, &scoops, 2, &mut out).unwrap();
            println!("lanes {:>2?}: {:.1} ms per scoop",
                     implementation.map(|f| f.0), start.elapsed().as_secs_f64() * 1000.0 / count as f64);
        }
        // for comparison: consecutive nonces of one account, all scoops (the plotting path)
        let mut plots = vec![0u8; count * NONCE_SIZE];
        let start = std::time::Instant::now();
        crate::create_plots(account_ids[0], nonces[0], count as u64, 2, plots.as_mut_ptr(), 0);
        println!("create_plots: {:.1} ms per nonce", start.elapsed().as_secs_f64() * 1000.0 / count as f64);
    }

    #[test]
    fn create_scoops_with_detected_extension_matches_reference() {
        crate::shabal_init();
        let count = 2 * 16 + 3; // more than one batch and a remainder for every lane width
        let (account_ids, nonces, scoops) = inputs(count);
        let mut out = vec![0u8; count * SCOOP_SIZE];
        create_scoops(&account_ids, &nonces, &scoops, 2, &mut out).unwrap();
        for i in 0..count {
            assert_eq!(out[i * SCOOP_SIZE..(i + 1) * SCOOP_SIZE].to_vec(),
                       reference_scoop(account_ids[i], nonces[i], scoops[i], 2), "entry {}", i);
        }
    }

    unsafe extern "C" fn failing_simd(_: *const u64, _: *const u64, _: *const u32, _: u64, _: u8, _: *mut u8) -> i32 {
        -1
    }

    #[test]
    fn create_scoops_reports_simd_failure() {
        let (account_ids, nonces, scoops) = inputs(4);
        let mut out = vec![0u8; 4 * SCOOP_SIZE];
        assert_eq!(create_scoops_with(Some((4, failing_simd)), &account_ids, &nonces, &scoops, 2, &mut out),
                   Err(ScoopsError::SimdFailure));
    }

    #[cfg(feature = "simd")]
    #[test]
    fn simd_scoops_rejects_count_not_multiple_of_lanes() {
        crate::shabal_init();
        unsafe { crate::init_noncegen_sse2(); }
        let (account_ids, nonces, scoops) = inputs(5);
        let mut out = vec![0u8; 5 * SCOOP_SIZE];
        let status = unsafe {
            noncegen_scoops_sse2(account_ids.as_ptr(), nonces.as_ptr(), scoops.as_ptr(), 5, 2, out.as_mut_ptr())
        };
        assert_eq!(status, -1);
    }

    #[test]
    fn create_scoops_with_no_entries_does_nothing() {
        assert_eq!(create_scoops(&[], &[], &[], 2, &mut []), Ok(()));
    }

    #[test]
    fn create_scoops_rejects_mismatched_lengths() {
        let mut out = vec![0u8; SCOOP_SIZE];
        assert_eq!(create_scoops(&[1, 2], &[1], &[0], 2, &mut out), Err(ScoopsError::InvalidLength));
        assert_eq!(create_scoops(&[1], &[1], &[0], 2, &mut vec![0u8; 10]), Err(ScoopsError::InvalidLength));
    }

    #[test]
    fn create_scoops_rejects_scoop_out_of_range() {
        let mut out = vec![0u8; SCOOP_SIZE];
        assert_eq!(create_scoops(&[1], &[1], &[NUM_SCOOPS], 2, &mut out), Err(ScoopsError::InvalidScoop));
    }
}
