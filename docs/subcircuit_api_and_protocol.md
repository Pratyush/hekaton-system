# Overview

Let C represent a large circuit. A prover (our end user) wants to distribute the proof of C with inputs `(x, w)`. So they manually split up C into sequential subcircuits C₁, ..., Cₙ such that the output of circuit `i` is the input of circuit `i+1`. Specifically,

1. Circuit #1 takes in the public input `x` (**question: should we permit other circuits to take public input?)
2. Every Cᵢ has witnesses its inputs `hinputᵢ` and outputs `houtputᵢ`. And for every `i`, `houtputᵢ = hinputᵢ₊₁`.

They then act as a _coordinator_, leveraging access to an arbitrary number of _worker nodes_ to compute its proof in as parallel a way as is possible.

# Steps for distributed proving

1. The cooridnator runs the circuit once through. That is, it runs C₁, ..., Cₙ, saving all the inputs/outputs as it goes along.
2. Begin the commit-and-prove process. For each i, the coordinator sends `(hinputᵢ, houtputᵢ)` to a worker node. (**TODO:** this excludes the first subcircuit, which takes public input)
    * Each worker node computes the commitments,
        ```
        (com_inᵢ, opening_inᵢ) := Com(hinputᵢ)
        (com_outᵢ, opening_outᵢ) := Com(houtputᵢ)
        ```
        where the commitments are using the CRS for subcircuit `i`
    * The worker returns `(com_inᵢ, com_outᵢ)`, and saves all the coms and openings. It will need them in step 4.
3. The coordinator gets all the worker node's commitments
    * It aggregates them into `agg_in` and `agg_out` (**TODO:** not at at clear what aggregation happens here). And computes
    * And it computes a challenge `chal`, which will be used for every subcircuit proof
4. For every `i` in parallel, the coordinator:
    * Sends `chal` to a worker node
    * Waits for the worker node's CP-Groth16 proof `πᵢ` over `Cᵢ(hinputᵢ, houtputᵢ, chal)`
5. The coordinator finally combines `π₁, ..., πₙ` into an aggregate proof that shows that
    1. `π₁` verifies with some public input, as well as `(hinput₁, houtput₁)`
    2. Each `πᵢ` is verifies wrt some `(hinputᵢ, houtputᵢ)`
    3. Each `houtputᵢ = hinputᵢ₊₁`

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

