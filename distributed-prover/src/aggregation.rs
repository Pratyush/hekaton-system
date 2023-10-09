use crate::coordinator::G16Com;

use core::borrow::Borrow;

use ark_crypto_primitives::crh::sha256::{digest::Digest, Sha256};
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;

// TODO: This is clearly not an IPP com. Make it so once it's ready
pub(crate) type IppCom = [u8; 32];

/// Commits to the full set of CP-Groth16 stage 0 commitments
// TODO: Make this an IPP commitment. For now it is just SHA256
pub(crate) fn commit_to_g16_coms<E: Pairing, B: Borrow<G16Com<E>>>(
    coms: impl IntoIterator<Item = B>,
) -> IppCom {
    let mut hasher = Sha256::default();
    for com in coms.into_iter() {
        let mut buf = Vec::new();
        com.borrow().serialize_uncompressed(&mut buf).unwrap();
        hasher.update(buf);
    }

    hasher.finalize().into()
}
