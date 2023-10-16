// For benchmark, run:
//     RAYON_NUM_THREADS=N cargo bench --no-default-features --features "std parallel" -- --nocapture
// where N is the number of threads you want to use (N = 1 for single-thread).

use ark_bls12_381::{Bls12_381 as E, Fr as F};
use ark_cp_groth16::{
    committer::CommitmentBuilder,
    generator::generate_parameters,
    verifier::{prepare_verifying_key, verify_proof},
    MultiStageConstraintSynthesizer, MultiStageConstraintSystem,
};
use ark_ff::{Field, One, UniformRand};
use ark_groth16::r1cs_to_qap::LibsnarkReduction as QAP;
use ark_r1cs_std::{
    eq::EqGadget,
    fields::fp::FpVar,
    prelude::{AllocVar, FieldVar},
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSystemRef, SynthesisError},
};
use ark_std::rand::Rng;

const NUM_PROVE_REPETITIONS: usize = 1;
const NUM_CONSTRAINTS: usize = (1 << 20) / 3 - 100;

/// A multistage circuit
/// Stage 1. Witness a var and ensure it's 0
/// Stage 2. Input a monic polynomial and prove knowledge of a root
#[derive(Clone)]
struct PolyEvalCircuit {
    // A polynomial that is committed in stage 0.
    pub polynomial: Vec<F>,

    // The variable corresponding to `polynomial` that is generated after stage 0.
    pub polynomial_var: Option<Vec<FpVar<F>>>,

    // The evaluation point for the polynomial.
    pub point: Option<F>,

    // The evaluation of `self.polynomial` at `self.root`.
    pub evaluation: Option<F>,
}

impl PolyEvalCircuit {
    fn new(polynomial: Vec<F>) -> Self {
        Self {
            polynomial,
            polynomial_var: None,
            point: None,
            evaluation: None,
        }
    }

    fn rand(mut rng: impl Rng) -> Self {
        // Sample a random monic polynomial of degree NUM_CONSTRAINTS - 1
        let degree = NUM_CONSTRAINTS - 1;
        let mut polynomial = (0..degree).map(|_| F::rand(&mut rng)).collect::<Vec<_>>();
        polynomial.push(F::one());
        Self::new(polynomial)
    }

    fn add_point(&mut self, point: F) {
        use ark_std::Zero;
        self.point = Some(point);
        self.evaluation = Some(
            self.polynomial
                .iter()
                .enumerate()
                .fold(F::zero(), |acc, (i, c)| acc + c * &point.pow(&[i as u64])),
        );
    }

    fn stage_0(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let polynomial_var = self
            .polynomial
            .iter()
            .map(|c| FpVar::new_witness(ns!(cs, "coeff"), || Ok(c)))
            .collect::<Result<Vec<_>, _>>()?;
        polynomial_var
            .last()
            .unwrap()
            .enforce_equal(&FpVar::one())?;
        self.polynomial_var = Some(polynomial_var);

        Ok(())
    }

    fn stage_1(&mut self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let point = FpVar::new_input(ns!(cs, "point"), || Ok(self.point.unwrap()))?;
        let evaluation = FpVar::new_input(ns!(cs, "point"), || Ok(self.evaluation.unwrap()))?;
        let mut cur_pow = FpVar::one();
        let claimed_eval = self
            .polynomial_var
            .as_ref()
            .unwrap()
            .iter()
            .map(|coeff| {
                let result = coeff * &cur_pow;
                cur_pow *= &point;
                result
            })
            .sum::<FpVar<F>>();

        // Assert that it's a root
        claimed_eval.enforce_equal(&evaluation)?;
        Ok(())
    }
}

impl MultiStageConstraintSynthesizer<F> for PolyEvalCircuit {
    fn total_num_stages(&self) -> usize {
        2
    }

    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        let out = match stage {
            0 => cs.synthesize_with(|c| self.stage_0(c)),
            1 => cs.synthesize_with(|c| self.stage_1(c)),
            _ => panic!("unexpected stage stage {}", stage),
        };

        out
    }
}

fn main() {
    let mut rng = ark_std::test_rng();
    let circuit = PolyEvalCircuit::rand(&mut rng);

    // Run the circuit and make sure it succeeds
    {
        let mut circuit = circuit.clone();
        let mut cs = MultiStageConstraintSystem::default();
        circuit.generate_constraints(0, &mut cs).unwrap();
        let point = F::rand(&mut rng);
        circuit.add_point(point);
        circuit.generate_constraints(1, &mut cs).unwrap();
        // assert!(cs.is_satisfied().unwrap());
        println!("Hello");
    }

    // Proof check
    //

    // Generate the proving key
    let start = ark_std::time::Instant::now();
    let pk = generate_parameters::<_, E, QAP>(circuit.clone(), &mut rng).unwrap();
    println!(
        "setup time for BLS12-381: {} s",
        start.elapsed().as_secs_f64() / NUM_PROVE_REPETITIONS as f64
    );

    let mut rng = ark_std::test_rng();
    let mut cb = CommitmentBuilder::<_, E, QAP>::new(circuit, &pk);
    let start = ark_std::time::Instant::now();
    let (comm, rand) = cb.commit(&mut rng).unwrap();
    println!(
        "commitment time for BLS12-381: {} s",
        start.elapsed().as_secs_f64() / NUM_PROVE_REPETITIONS as f64
    );

    let point = F::rand(&mut rng);
    cb.circuit.add_point(point);
    let start = ark_std::time::Instant::now();
    let proof = cb.prove(&[comm], &[rand], &mut rng).unwrap();
    println!(
        "proving time for BLS12-381: {} s",
        start.elapsed().as_secs_f64() / NUM_PROVE_REPETITIONS as f64
    );
    // Verify
    let pvk = prepare_verifying_key(&pk.vk());
    let inputs = [point, cb.circuit.evaluation.unwrap()];
    assert!(verify_proof(&pvk, &proof, &inputs).unwrap());
}
