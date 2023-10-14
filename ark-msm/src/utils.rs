use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};

#[allow(clippy::type_complexity)]
pub fn generate_msm_inputs<A: AffineRepr>(
    size: usize,
) -> (
    Vec<A>,
    Vec<<A::ScalarField as PrimeField>::BigInt>,
)
where
    A: AffineRepr,
{
    let mut rng = ark_std::test_rng();
    let scalar_vec = (0..size)
        .map(|_| A::ScalarField::rand(&mut rng).into_bigint())
        .collect();
    let point_vec = (0..size)
        .map(|_| A::Group::rand(&mut rng))
        .collect::<Vec<_>>();
    (
        <A::Group as CurveGroup>::normalize_batch(&point_vec),
        scalar_vec,
    )
}
