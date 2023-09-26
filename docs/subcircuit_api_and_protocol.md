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
    1. Uses the commit-and-prove scheme to compute the commitment `(com_trᵢ, opening_trᵢ) := Com((time_trᵢ, addr_trᵢ))`.
    2. Sends `com_trᵢ`, and saves the commitment and opening. It will need them in step 4.
4. The coordinator gets all the worker node's commitments, and
    1. Computes an IPP commitment to all the subtranscripts commitments, `(com_tr, opening_tr) := IPPCom(com_tr₁, ..., com_trₙ)`
    1. Computes two challenges`tr_chal, entry_chal = Hash(com_tr)`
        * `entry_chal` is used to compress `(val, addr)` to a single field element `val + entry_chal*addr`
        * `tr_chal` is used to compress the transcript (with hashed entries) to a single field element `Π (tr_chal - hashed_entryᵢ)`
    2. For each `i`, computes the partial transcript evals `time_tr_{1..i}(chal)` and `addr_tr_{1..i}(chal)`. These partial evals are called `time_pevalᵢ` and `addr_pevalᵢ` respectively.
    3. Computes a Merkle tree with leaf `i` being `(time_pevalᵢ, addr_pevalᵢ, fᵢ₋₁)`, where `fᵢ` denotes the final entry of `addr_trᵢ`. Denote the root by `root_pevals`.
5. For every `i` in parallel, the coordinator:
    1. Sends `(entry_chal, tr_chal, θᵢ₊₁, time_pevalᵢ, addr_pevalᵢ, fᵢ₋₁)` to a worker node, where `θᵢ` is the authentication path for leaf `i`, and `fᵢ₋₁` is the final entry in `addr_trᵢ₋₁`
    2. Waits for the worker node's CP-Groth16 proof `πᵢ` over `Cᵢ(entry_chal, tr_chal, root_pevals; time_trᵢ, addr_trᵢ, time_pevalᵢ, addr_pevalᵢ, θᵢ₊₁)`. Specifically, this proof
        1. Performs the actual subcircuit, using values from `time_trᵢ` sequentially, where referenced
        2. Checks the consistency of `fᵢ₋₁ || addr_trᵢ`, i.e., that the addresses are nondecreasing and that all reads from the address have the same `val`.
        3. Computes the new partial evals `(time_pevalᵢ₊₁, addr_pevalᵢ₊₁)` using `*_chal`, `(time_trᵢ, addr_trᵢ)`, and `(time_pevalᵢ, addr_pevalᵢ)`
        4. Lets `fᵢ := addr_trᵢ[-1]`
        5. Checks that `(time_pevalᵢ₊₁, addr_pevalᵢ₊₁, fᵢ)` occurs at leaf index `i+1`, using `θᵢ₊₁` and `root_pevals`
        6. Only for `i=1`:
            * Takes the public input `x` and processes it into however many shared wires it needs
            * Checks that `fᵢ₋₁ = (0, 0)` and `(time_pevalᵢ, addr_pevalᵢ) = (0, 0)`
6. The coordinator finally combines `π₁, ..., πₙ` into an aggregate proof `π_agg` using IPP that shows that each `πᵢ` verifies wrt `(com_trᵢ, entry_chal, tr_chal, root_pevals)` (and `x`, for `i=1`). Note that `i` is not a public input, rather it is a const in Cᵢ.
7. In addition, the coordinator produces an opening `θ_fin` for final Merkle leaf, which should be of the form `(s, s, fₙ₋₁)`. The final proof is thus `(com_tr, root_pevals, θ_fin, π_agg)`.

TODO: Need to hide the fₙ₋₁ in the final Merkle leaf. Maybe do this as a commitment.

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
/// The address of a portal wire is just the hash of its name (which is unique)
type PortalWireAddr = [u8; 256];
type PortalWireAddrVar<F> = F;

// An execution trace entry is an addr-value pair
type TraceEntry<F> = (PortalWireAddr, F)
type TraceEntryVar<F> = (PortalWireAddrVar<F>, FpVar<F>)

/// A trait for getting and setting portal wires in partitioned circuits
trait PortalManager {
    /// Gets the portal wire of the given name. Panics if no such wire exists.
    fn get(&mut self, name: &str) -> FpVar<F>;

    /// Sets the portal wire of the given name. Panics if the wire is already set.
    fn set(&mut self, name: &str, val: &FpVar<F>);
}

/// This portal manager is used by the coordinator to produce the trace
struct SetupPortalManager {
    pub trace: Vec<TraceEntry<F>>,

    cs: ConstraintSystemRef<F>,

    // Technically not necessary, but useful for sanity checks
    map: HashMap<String, F>,
}

impl PortalManager for SetupPortalManager {
    /// Gets the value from the map and adds the pair to the trace
    fn get(&mut self, name: &str) -> FpVar<F> {
        let val = self.map.get(name).expect(format!("cannot get portal wire '{name}'"));
        let val_var = FpVar::new_witness(ns!(self.cs, "wireval"), || Ok(val)).unwrap();
        self.trace.push(hash(name), val);

        val_var
    }

    /// Sets the value in the map and adds the pair to the trace
    fn set(&mut self, name: &str, val: &FpVar<F>) {
        assert!(
            map.get(name).is_none(),
            "cannot set portal wire more than once; wire '{name}'"
        );
        self.map.insert(name, val);
        self.trace.push((hash(name), val.value().unwrap()));
    }
}

/// This portal manager is used by a subcircuit prover. It takes the subtrace for this subcircuit as
/// well as the running evals up until this point. These values are used in the CircuitWithPortals
/// construction later.
struct ProverPortalManager {
    pub time_ordered_subtrace_var: Vec<TraceEntryVar<F>>,
    pub addr_ordered_subtrace_var: Vec<TraceEntryVar<F>>,
    pub running_evals_var: RunningEvalsVar<F>,

    cs: ConstraintSystemRef<F>,

    // Technically not necessary, but useful for sanity checks
    map: HashMap<String, F>,
}

impl PortalManager for ProverPortalManager {
    /// Pops off the subtrace, sanity checks that the names match, updates the running polyn
    /// evals to reflect the read op, and does one step of the name-ordered coherence check.
    fn get(&mut self, name: &str) -> FpVar<F> {
        // Pop the value and sanity check the name
        let (hashed_name, val) = self.time_ordered_subtrace_var.pop()?;
        assert_eq!(hashed_name.value().unwrap(), hash(expected_name));

        // Update the running polyn
        self.running_evals.update(hashed_name, val);

        // On our other subtrace, do one step of a memory-ordering check
        let (cur_addr, cur_val) = self.addr_ordered_subtrace_var.pop().unwrap();
        let (next_addr, next_val) = self.addr_ordered_subtrace_var.first().unwrap();
        // Check cur_addr <= next_addr
        cur_addr.enforce_cmp(next_addr, Ordering::Less, true);
        // Check cur_val == next_val if cur_addr == next_addr
        let is_same_addr = cur_addr.is_eq(next_addr);
        cur_val.conditional_enforce_equal(next_val, is_same_addr);

        // Return the val from the subtrace
        val
    }

    /// Set is no different from get in circuit land. This does the same thing, and also enforce
    /// that `val` equals the popped subtrace value.
    fn set(&mut self, name: &str, val: &FpVar<F>) {
        let trace_val = self.get(name);
        val.enforce_eq(trace_val)?;
    }
}

struct MyCircuit {
    public_bytestring: Vec<u8>,
}

impl MyCircuit {
    fn subcirc_0(cs: &mut ConstraintSystem<F>, pm: &mut impl PortalManager) {
        // Blah
        pm.set("foo", foo);
        pm.set("bar", bar);
        // Whatever
    }

    fn subcirc_1(cs: &mut ConstraintSystem<F>, pm: &mut impl PortalManager) {
        let foo = pm.get("foo").unwrap();
        let bar = pm.get("bar").unwrap();
        // Whatever
        pm.set("baz", baz);
    }
}

trait CircuitWithPortals {
    /// Generates constraints for the i-th subcircuit.
    fn generate_constraints(
        &mut self,
        cs: &mut ConstraintSystem<F>,
        subcircuit_idx: usize,
        pm: &mut impl PortalManager,
    ) -> Result<(), SynthesisError>;
}

impl CircuitWithPortals for MyCircuit {
    /// Generates constraints for the i-th subcircuit.
    fn generate_constraints(
        &mut self,
        cs: &mut ConstraintSystem<F>,
        subcircuit_idx: usize,
        pm: &mut impl PortalManager,
    ) -> Result<CircuitEnvVar, SynthesisError> {
        match subcircuit_idx {
            0 => self.subcirc_1(cs, pm),
            1 => self.subcirc_2(cs, pm),
        }
    }
}

/// Every Merkle leaf contains a running evaluation and the final element of the previous
/// address-ordered subtrace
struct Leaf<F> {
    evals: RunningEvals<F>,
    last_subtrace_entry: TraceEntry<F>,
}
struct LeafVar<F> {
    evals: RunningEvalsVar<F>,
    last_subtrace_entry: TraceEntryVar<F>,
}

// Define a way to commit and prove to just one subcircuit
struct CpPortalProver<P: CircuitWithPortals> {
    subcircuit_idx: usize,
    circ: P,

    // Stage 0 committed values
    pub time_ordered_subtrace: Vec<TraceEntry<F>>,
    pub addr_ordered_subtrace: Vec<TraceEntry<F>>,
    pub time_ordered_subtrace_var: Vec<TraceEntryVar<F>>,
    pub addr_ordered_subtrace_var: Vec<TraceEntryVar<F>>,

    // Stage 1 witnesses
    pub running_evals: RunningEvals<F>,
    pub running_evals_var: RunningEvalsVar<F>,
    pub cur_leaf: Leaf<F>
    pub next_leaf_membership: MerkleAuthPath<F>,
    pub cur_leaf_var: LeafVar<F>
    pub next_leaf_membership_var: MerkleAuthPathVar<F>,

    // Stage 1 public inputs
    pub entry_chal: F,
    pub tr_chal: F,
    pub root: MerkleRoot<F>,
    pub entry_chal_var: FpVar<F>,
    pub tr_chal_var: FpVar<F>,
    pub root_var: MerkleRootVar<F>,
}


impl<P: CircuitWithPortals> MultiStageConstraintSynthesizer for CpPortalProver {
    // Two stages: Subtrace commit, and the rest
    fn total_num_stages(&self) -> usize {
        2
    }

    /// Generates constraints for the i-th stage.
    fn generate_constraints(
        &mut self,
        stage: usize,
        cs: &mut MultiStageConstraintSystem<F>,
    ) -> Result<(), SynthesisError> {
        match stage {
            0 => cs.synthesize_with(|c| /* Witness the time- and memory-ordered subtraces */),
            1 => cs.synthesize_with(|c| {
                // Omitted: witnessing and inputting all the stage 1 values

                // Construct the portal manager
                // The addr-sorted subtrace starts with the last entry from the previous subtrace
                let addr_subtrace = [
                    self.next_leaf_var.0.last_subtrace_entry,
                    self.addr_ordered_subtrace_var,
                ].concat();
                let mut pm = ProverPortalManager::new(
                    self.time_ordered_subtrace_var,
                    self.addr_ordered_subtrace_var,
                    self.running_evals_var,
                    self.entry_chal_var,
                    self.tr_chal_var,
                    c,
                );
                // Run the circuit
                self.circ.generate_constraints(c, self.subcircuit_idx, &mut pm)?;

                // Do some followup checks

                // Sanity checks: make sure all the subtraces were used
                assert!(
                    pm.time_ordered_subtrace_var.empty() && pm.addr_ordered_subtrace_var.empty()
                );

                // Make sure the resulting running evals are equal to the ones in the Merkle tree
                let next_running_evals = self.next_leaf.0.evals;
                pm.running_evals_var.enforce_equal(next_running_evals);

                // Check the leaf membership in the merkle tree
                self.root_var.enforce_membership(self.next_leaf_var.0, self.next_leaf_var.1)?;
            }),
        }
    }
}
```

