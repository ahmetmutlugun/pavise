//! Detect EC public keys whose private scalar is a tiny integer.
//!
//! A P-256/P-384 private key is a random integer below the group order; the
//! eMudhra intermediates of October 2026 used integers below 256, so anyone
//! could recover them from the public certificate. Baby-step giant-step
//! finds any `d < 2^16` with 256 point additions and one batch inversion per
//! key, against a per-curve table of `j·G` built once.

use std::collections::HashMap;
use std::sync::OnceLock;

use p256::elliptic_curve::group::{Curve as _, Group};
use p256::elliptic_curve::sec1::{FromSec1Point, ModulusSize, ToSec1Point};
use p256::elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, ProjectivePoint};

use super::x509::Curve;

/// Baby steps per table and giant steps per key: covers `1 ≤ d < STEPS²`.
const STEPS: usize = 256;
pub const SEARCH_BOUND: u32 = (STEPS * STEPS) as u32;

type Table = HashMap<Vec<u8>, u32>;

fn compressed<C>(p: &AffinePoint<C>) -> Vec<u8>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    p.to_sec1_point(true).as_bytes().to_vec()
}

/// `j·G → j` for `0 ≤ j < STEPS` (the identity encodes as `[0]`).
fn baby_steps<C>() -> Table
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let g = ProjectivePoint::<C>::generator();
    let mut points = Vec::with_capacity(STEPS);
    let mut p = ProjectivePoint::<C>::identity();
    for _ in 0..STEPS {
        points.push(p);
        p += g;
    }
    let mut affine = vec![AffinePoint::<C>::default(); STEPS];
    ProjectivePoint::<C>::batch_normalize(&points, &mut affine);
    affine
        .iter()
        .enumerate()
        .map(|(j, a)| (compressed::<C>(a), j as u32))
        .collect()
}

fn small_scalar<C>(sec1: &[u8], table: &Table) -> Option<u32>
where
    C: CurveArithmetic,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let q = p256::elliptic_curve::PublicKey::<C>::from_sec1_bytes(sec1)
        .ok()?
        .to_projective();
    // Giant step: STEPS·G.
    let step = std::iter::repeat_n(ProjectivePoint::<C>::generator(), STEPS)
        .fold(ProjectivePoint::<C>::identity(), |acc, g| acc + g);
    let mut giants = Vec::with_capacity(STEPS);
    let mut p = q;
    for _ in 0..STEPS {
        giants.push(p);
        p -= step;
    }
    let mut affine = vec![AffinePoint::<C>::default(); STEPS];
    ProjectivePoint::<C>::batch_normalize(&giants, &mut affine);
    // Q − i·STEPS·G = j·G  ⇒  d = i·STEPS + j; ascending i gives the smallest d.
    affine.iter().enumerate().find_map(|(i, a)| {
        let j = *table.get(&compressed::<C>(a))?;
        let d = (i * STEPS) as u32 + j;
        (d > 0).then_some(d)
    })
}

/// The private key of a SEC1-encoded public point, if it is below
/// [`SEARCH_BOUND`].
pub fn recover_small_key(curve: Curve, sec1: &[u8]) -> Option<u32> {
    static P256_TABLE: OnceLock<Table> = OnceLock::new();
    static P384_TABLE: OnceLock<Table> = OnceLock::new();
    match curve {
        Curve::P256 => small_scalar::<p256::NistP256>(
            sec1,
            P256_TABLE.get_or_init(baby_steps::<p256::NistP256>),
        ),
        Curve::P384 => small_scalar::<p384::NistP384>(
            sec1,
            P384_TABLE.get_or_init(baby_steps::<p384::NistP384>),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::x509;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    fn p384_point(d: u64) -> Vec<u8> {
        let q = p384::ProjectivePoint::GENERATOR * p384::Scalar::from(d);
        q.to_affine().to_sec1_point(false).as_bytes().to_vec()
    }

    /// DER SubjectPublicKeyInfo for an uncompressed P-384 point.
    fn p384_spki(point: &[u8]) -> Vec<u8> {
        let mut alg = vec![
            0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        ];
        alg.extend([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22]);
        let mut bits = vec![0x03, (point.len() + 1) as u8, 0x00];
        bits.extend_from_slice(point);
        let mut spki = vec![0x30, (alg.len() + bits.len()) as u8];
        spki.extend(alg);
        spki.extend(bits);
        spki
    }

    /// The eight eMudhra keys are public (Mozilla bug 2083449). Each d·G must
    /// hash to the SPKI listed for that intermediate in
    /// `data/distrusted_cas.tsv`, and the weak-key search must recover d.
    #[test]
    fn emudhra_private_keys_match_listed_spki_and_are_recovered() {
        let expected = [
            (4, "EM OV TLS CA - G3C"),
            (56, "EM EV TLS CA - G3C"),
            (66, "EM OV CS CA - G3B"),
            (115, "EM EV TLS CA - G3B"),
            (155, "EM OV TLS CA - G3B"),
            (156, "EM DV TLS CA - G3B"),
            (230, "EM DV TLS CA - G3C"),
            (237, "EM OV CS CA - G3C"),
        ];
        let listed = include_str!("../../data/distrusted_cas.tsv");
        for (d, name) in expected {
            let spki = p384_spki(&p384_point(d));
            let hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&spki));
            let row = listed
                .lines()
                .find(|l| l.starts_with(&hash))
                .unwrap_or_else(|| panic!("d={} SPKI {} not listed", d, hash));
            assert!(row.contains(name), "d={} maps to {}, not {}", d, row, name);
            assert!(row.contains("\tcompromised\t"), "{}", row);

            let (curve, point) = x509::ec_point(&spki).unwrap();
            assert_eq!(curve, Curve::P384);
            assert_eq!(recover_small_key(curve, point), Some(d as u32));
        }
    }

    #[test]
    fn recovers_bounds_and_rejects_random_keys() {
        for d in [1u64, 255, 256, 257, 65_535] {
            assert_eq!(
                recover_small_key(Curve::P384, &p384_point(d)),
                Some(d as u32)
            );
            let q = p256::ProjectivePoint::GENERATOR * p256::Scalar::from(d);
            let sec1 = q.to_affine().to_sec1_point(true);
            assert_eq!(
                recover_small_key(Curve::P256, sec1.as_bytes()),
                Some(d as u32)
            );
        }
        assert_eq!(recover_small_key(Curve::P384, &p384_point(65_536)), None);
        // A real, randomly generated key.
        let keys = x509::bundled_keys("t.pem", x509::tests::TEST_CERT_PEM.as_bytes());
        let (curve, point) = x509::ec_point(&keys[0].spki).unwrap();
        assert_eq!(recover_small_key(curve, point), None);
        // Not a curve point.
        assert_eq!(recover_small_key(Curve::P256, &[0x04; 65]), None);
    }
}
