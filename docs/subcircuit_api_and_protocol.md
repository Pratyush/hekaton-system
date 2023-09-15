# Overview

Let C represent a large circuit. A prover (our end user) wants to distribute the proof of C with inputs `(x, w)`. So they manually split up C into sequential subcircuits C₁, ..., Cₙ such that:

1. Circuit #1 takes in the public input `x`
2. Every Cᵢ can expose values, called _portal wires_, and can reference any previously exposed portal wires

The prover then acts as a _coordinator_, leveraging access to an arbitrary number of _worker nodes_ to compute its proof in as parallel a way as is possible.

# Steps for distributed proving

1. The cooridnator runs the circuit once through. That is, it runs C₁, ..., Cₙ, saving all the portal wires as pairs `(val, addr)` as it goes along (where `addr` is any unique ID for vars, e.g., a monotonic counter). It also keeps track of which wires are being accessed by which subcircuits.
2. Begin the commit-and-prove process. For each `i`, the coordinator:
    1. Computes `time_trᵢ` — the trace of `(val, addr)` pairs that the subcircuit accessed, in chronological order of access.
    2. Computes `addr_trᵢ` — a list of `(val, addr)` pairs of the same length as `time_trᵢ`, taken from the address-sorted trace
    3. Sends `(time_trᵢ, addr_trᵢ)` to a worker node. If `i = 1`, then the coordinator also sends the public input `x`.
3. Each worker node i:
    1. Uses the commit-and-prove scheme to compute the commitment `(com_trᵢ, opening_trᵢ) := Com(trᵢ)`.
    2. Sends `com_trᵢ`, and saves the commitment and opening. It will need them in step 4.
4. The coordinator gets all the worker node's commitments, and
    1. Interprets the full trace `tr` as a polynomial, i.e., the product `Π (X - eⱼ)` over all entries `eⱼ ∈ tr`. It commits to `tr`, i.e., `com_tr := PolyCom(tr)`
    2. Computes a challenge `chal = Hash(com_tr)`, which will be used for polynomial evaluation in every subcircuit proof.
    3. For each `i`, computes the partial transcript evals `time_tr_{1..i}(chal)` and `addr_tr_{1..i}(chal)`. These partial evals are called `time_pevalᵢ` and `addr_pevalᵢ` respectively.
    4. Computes a Merkle tree where leaf `i` is `(time_pevalᵢ, addr_pevalᵢ)`. Denote the root by `root_pevals`.
5. For every `i` in parallel, the coordinator:
    1. Sends `(chal, θᵢ₊₁, time_pevalᵢ, addr_pevalᵢ, fᵢ₋₁)` to a worker node, where `θᵢ` is the authentication path for leaf `i`, and `fᵢ₋₁` is the final entry in `addr_trᵢ₋₁`
    2. Waits for the worker node's CP-Groth16 proof `πᵢ` over `Cᵢ(chal, root_pevals; time_trᵢ, addr_trᵢ, time_pevalᵢ, addr_pevalᵢ, θᵢ₊₁)`. Specifically, this proof
        1. Performs the actual subcircuit, using values from `time_trᵢ` sequentially, where referenced
        2. Checks the consistency of `fᵢ₋₁ || addr_trᵢ`, i.e., that the addresses are nondecreasing and that all reads from the address have the same `val`.
        3. Computes the new partial evals `(time_pevalᵢ₊₁, addr_pevalᵢ₊₁)` using `chal`, `(time_trᵢ, addr_trᵢ)`, and `(time_pevalᵢ, addr_pevalᵢ)`
        4. Proves that `(time_pevalᵢ₊₁, addr_pevalᵢ₊₁)` occurs at leaf index `i+1`, using `θᵢ₊₁` and `root_pevals`
        5. (only for `i=1`) Takes the public input `x` and processes it into however many shared wires it needs
6. The coordinator finally combines `π₁, ..., πₙ` into an aggregate proof `π_agg` that shows that each `πᵢ` verifies wrt `(chal, root_pevals)` (and `x`, for `i=1`). Note that `i` is not a public input, rather it is a const in Cᵢ.
7. In addition, the coordinator produces an opening `θ_fin` for final Merkle leaf, which should be of the form `(s, s)`. The coordinator produces a polynomial evaluation proof `π_poly` wrt `com_tr` that `tr(chal) == s`. The final proof is thus `(com_tr, root_pevals, θ_fin, π_agg, π_poly)`.

---

# OLD OLD OLD

# Data structures for the above protocol

## Step 0

Before anything happens, the worker nodes need the CRS for the circuit(s) in question. For now, we will not split up the subcircuit CRSs. We will simply send the same large `cp_groth16::ProvingKey` to every worker node. This can bundled with the step 2's communications.

## Step 1

No communication here.

## Step 2

We need a data structure to hold the inputs and outputs. To avoid errors, let's assume that every input and output has a variable name, and has been serialized to field elements. We will define a type that represents the set of these variables:
```rust
type CircuitEnv = HashMap<String, Vec<F>>
```

The coordinator will send every worker node data in the form:
```rust
struct TraceChunk {
    subcircuit_idx: usize,
    inputs: CircuitEnv,
    outputs: CircuitEnv,
}
```

The worker will commit to the inputs and the outputs separately, using the `cp_groth16::CommitmentBuilder` functionality, and return commitments in the form
```rust
struct TraceChunkComs {
    subcircuit_idx: usize,
    inputs_com: Comm,
    outputs_com: Comm,
}
```

Each worker node will also save its `CommitmentBuilder` state, so that it can run the last stage, which is proving.

**TODO: There currently is no way to serialize a `CommitmentBuilder`!**

## Step 3

No communication here

## Step 4

The coordinator sends to every worker node `chal: F`.

Each worker loads up its `CommitmentBuilder`. It passes `chal` as a public input to the final stage, i.e., the proving stage. It then sends back the final `cp_groth16::Proof` to the coordinator.

## Step 5

No communication here

# A prover API

We define here a way of defining interoperable subcircuits using a `HashMap` to represent the wires in common.

**TODO:** I don't know how the post-commitment challenge is used in our subcircuit proof

Recall the trait definitions

```rust
pub trait ConstraintSynthesizer<F: Field> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<()>;
}

pub trait MultiStageConstraintSynthesizer<F: Field> {
    /// The number of stages required to construct the constraint system.
    fn total_num_stages(&self) -> usize;

    /// The number of stages required to construct the constraint system.
    fn last_stage(&self) -> usize {
        self.total_num_stages() - 1
    }

    /// Generates constraints for the i-th stage.
    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError>;
}
```

We need to have users define a circuit with specific points at which it can be split into subcircuits.

Here's a very basic, very not fun to use flow:
```rust
type CircuitEnv = HashMap<String, Vec<F>>;
type CircuitEnvVar = HashMap<String, Vec<FpVar<F>>>;

struct MyCircuit {
    public_bytestring: Vec<u8>,
}

impl MyCircuit {
    fn step_0(cs: &mut ConstraintSystem<F>) -> CircuitEnvVar {
        // ...
        // foo, bar, and baz all impl ToConstraintFieldGadget
        // Maybe make a macro that does this, like env!(foo, bar, baz)
        return HashMap::from([
            ("foo", foo.to_constraint_field()),
            ("bar", bar.to_constraint_field()),
            ("baz", baz.to_constraint_field()),
        ])
    }

    fn step_1(
        cs: &mut ConstraintSystem<F>,
        env: CircuitEnvVar,
    ) {
        let foo_fps = env.get("foo").unwrap();
        let bar_fps = env.get("bar").unwrap();
        let baz_fps = env.get("baz").unwrap();
        // Manual conversion back into the original representation
    }
}

trait CircuitWithPortals {
    /// Generates constraints for the i-th subcircuit.
    fn generate_constraints(
        &mut self,
        subcircuit_idx: usize,
        cs: &mut ConstraintSystem<F>,
    ) -> Result<(), SynthesisError>;
}

impl CircuitWithPortals for MyCircuit {
    /// Generates constraints for the i-th subcircuit.
    fn generate_constraints(
        &mut self,
        env: CircuitEnvVar,
        subcircuit_idx: usize,
        cs: &mut ConstraintSystem<F>,
    ) -> Result<CircuitEnvVar, SynthesisError> {
        match subcircuit_idx {
            0 => self.step_0(),
            1 => self.step_1(env),
        }
    }
}

// Define a way to commit and prove to just one subcircuit
struct CpPortalProver<P: CircuitWithPortals> {
    subcircuit_idx: usize,
    input: CircuitEnv,
    input_var: CircuitEnvVar,
    output: CircuitEnv,
    output_var: CircuitEnvVar,
    circ: P,
}


impl<P: CircuitWithPortals> MultiStageConstraintSynthesizer for CpPortalProver {
    // Three stages: input wires, output wires, and the circuit body
    fn total_num_stages(&self) -> usize {
        3
    }

    /// Generates constraints for the i-th stage.
    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        match stage {
            0 => cs.synthesize_with(|c| self.input_var = CircuitEnvVar::new_witness(c, || Ok(self.input))),
            1 => cs.synthesize_with(|c| self.output_var = CircuitEnvVar::new_witness(c, || Ok(self.output))),
            2 => cs.synthesize_with(|c| {
                let computed_output = self.circ.generate_constraints(self.input, self.subcircuit_idx)?;
                computed_output.enforce_equal(self.output_var)?;
            }),
        }
    }
}
```

