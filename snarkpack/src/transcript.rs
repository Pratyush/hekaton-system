use ark_ff::PrimeField;
use ark_serialize::{CanonicalSerialize, Compress};
use merlin::Transcript as Merlin;

/// must be specific to the application.
pub fn new_merlin_transcript(label: &'static [u8]) -> impl Transcript {
    Merlin::new(label)
}

/// Transcript is the application level transcript to derive the challenges
/// needed for Fiat Shamir during aggregation. It is given to the
/// prover/verifier so that the transcript can be fed with any other data first.
pub trait Transcript {
    fn domain_sep(&mut self);

    fn append(&mut self, label: &'static [u8], point: &impl CanonicalSerialize);

    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F;
}

impl Transcript for Merlin {
    fn domain_sep(&mut self) {
        self.append_message(b"dom-sep", b"groth16-aggregation-snarkpack");
    }

    fn append(&mut self, label: &'static [u8], element: &impl CanonicalSerialize) {
        let mut buff: Vec<u8> = vec![0; element.serialized_size(Compress::Yes)];
        element
            .serialize_compressed(&mut buff)
            .expect("serialization failed");
        self.append_message(label, &buff);
    }

    fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F {
        let modulus_byte_size = ((F::MODULUS_BIT_SIZE + 7) / 8) as usize;
        let mut buf = vec![0; modulus_byte_size];
        self.challenge_bytes(label, &mut buf);
        F::from_le_bytes_mod_order(&buf)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};
    use ark_ec::Group;

    #[test]
    fn transcript() {
        let mut transcript = new_merlin_transcript(b"test");
        transcript.append(b"point", &G1Projective::generator());
        let f1 = transcript.challenge_scalar::<Fr>(b"scalar");
        let mut transcript2 = new_merlin_transcript(b"test");
        transcript2.append(b"point", &G1Projective::generator());
        let f2 = transcript2.challenge_scalar::<Fr>(b"scalar");
        assert_eq!(f1, f2);
    }
}
