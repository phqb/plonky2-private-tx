use anyhow::Result;
use log::{info, Level};
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::hash::merkle_proofs::{MerkleProof, MerkleProofTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, Hasher};
use plonky2::plonk::proof::{Proof, ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::plonk::prover::prove;
use plonky2::util::timing::TimingTree;
use plonky2_field::extension::Extendable;
use plonky2_field::goldilocks_field::GoldilocksField;

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateWitness<F: RichField> {
    pub private_key: [F; 4],
    pub index: usize,
    pub token_id: F,
    pub token_amount: F,
    pub merkle_proof: MerkleProof<F, PoseidonHash>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PublicInputs<F: RichField> {
    pub(crate) nullifier_value: HashOut<F>,
    pub(crate) new_leaf_value: HashOut<F>,
    pub merkle_root_value: HashOut<F>,
}

pub struct WiringTarget {
    pub merkle_root_target: HashOutTarget,
    pub nulifier_target: HashOutTarget,
    pub new_leaf_target: HashOutTarget,
    pub merkle_proof_target: MerkleProofTarget,
    pub private_key_target: [Target; 4],
    pub token_id_target: Target,
    pub balance_target: Target,
    pub public_key_index_target: Target,
}

/// dont touch this unless there is agreement to do so
pub fn private_tx_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    config: &CircuitConfig,
    tree_height: usize,
) -> (CircuitData<F, C, D>, WiringTarget) {
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // public data:
    // - merkle root
    let merkle_root_target = builder.add_virtual_hash();
    builder.register_public_inputs(&merkle_root_target.elements);
    // - nullify
    info!("merkle root target is {:?}", merkle_root_target);

    let nulifier_target = builder.add_virtual_hash();
    builder.register_public_inputs(&nulifier_target.elements); // - new leaf root
    let new_leaf_target = builder.add_virtual_hash();
    builder.register_public_inputs(&new_leaf_target.elements);
    // - Merkle proof
    let merkle_proof_target = MerkleProofTarget {
        siblings: builder.add_virtual_hashes(tree_height),
    };
    info!("1 merkle root target is {:?}", merkle_root_target);

    // Prepare the hash data for UTXO tree
    let private_key_target: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
    let token_id_target = builder.add_virtual_target();
    let balance_target = builder.add_virtual_target();
    let public_key_index_target = builder.add_virtual_target();
    let public_key_index_bits_target = builder.split_le(public_key_index_target, tree_height);
    let zero_target = builder.zero();

    builder.verify_merkle_proof::<PoseidonHash>(
        [
            private_key_target,
            [zero_target, zero_target, token_id_target, balance_target],
        ]
        .concat(),
        &public_key_index_bits_target,
        merkle_root_target,
        &merkle_proof_target,
    );

    info!("2 merkle root target is {:?}", merkle_root_target);

    let old_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        [
            private_key_target,
            [zero_target, zero_target, token_id_target, balance_target],
        ]
        .concat(),
    );
    // enforce nullifer == old_leaf
    for i in 0..4 {
        builder.connect(nulifier_target.elements[i], old_leaf.elements[i]);
    }

    info!("3 merkle root target is {:?}", merkle_root_target);

    //TODO:
    // - enforce nullifier at index = 0
    // - reshash nullifier tree
    // - rehash new leaf
    // - rehash private utxo tree
    (
        builder.build::<C>(),
        WiringTarget {
            merkle_root_target,
            nulifier_target,
            new_leaf_target,
            merkle_proof_target,
            private_key_target,
            token_id_target,
            balance_target,
            public_key_index_target,
        },
    )
}

pub fn gen_private_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    data: CircuitData<F, C, D>,
    public_input: PublicInputs<F>,
    witness: PrivateWitness<F>,
    wiring: WiringTarget,
) -> Result<ProofTuple<F, C, D>> {
    let mut pw = PartialWitness::new();
    //public witness
    info!("merkle root target is {:?}", wiring.merkle_root_target);

    pw.set_hash_target(wiring.merkle_root_target, public_input.merkle_root_value);
    pw.set_hash_target(wiring.nulifier_target, public_input.nullifier_value);
    pw.set_hash_target(wiring.new_leaf_target, public_input.new_leaf_value);

    for (ht, h) in wiring
        .merkle_proof_target
        .siblings
        .into_iter()
        .zip(witness.merkle_proof.siblings.clone())
    {
        pw.set_hash_target(ht, h);
    }

    //private witness
    pw.set_target_arr(wiring.private_key_target, witness.private_key);
    pw.set_target(wiring.token_id_target, witness.token_id);
    pw.set_target(wiring.balance_target, witness.token_amount);
    pw.set_target(
        wiring.public_key_index_target,
        F::from_canonical_u64(witness.index as u64),
    );
    info!("finished setting target");

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();
    info!("finish proving");
    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

pub fn verify_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    data: &CircuitData<F, C, D>,
    proof: ProofTuple<F, C, D>,
) -> Result<()> {
    data.verify(proof.0.clone())
}

pub struct RecursiveWiringTargets<const D: usize> {
    pub pt1: ProofWithPublicInputsTarget<D>,
    pub pt2: ProofWithPublicInputsTarget<D>,
    pub vc1: VerifierCircuitTarget,
    pub vc2: VerifierCircuitTarget,
}

/// recursive_circuit is a specific circuit to recursively
/// reunion 2 proofs and prove that it was generated correctly.
pub fn recursive_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner1: &ProofTuple<F, InnerC, D>,
    inner2: &ProofTuple<F, InnerC, D>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> (CircuitData<F, C, D>, RecursiveWiringTargets<D>)
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let (_, _, inner_cd1) = inner1;
    let (_, _, inner_cd2) = inner2;

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let pt1 = builder.add_virtual_proof_with_pis::<InnerC>(inner_cd1);
    let pt2 = builder.add_virtual_proof_with_pis::<InnerC>(inner_cd2);
    let vc1 = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(inner_cd1.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.register_public_inputs(vc1.circuit_digest.elements.as_slice());

    let vc2 = VerifierCircuitTarget {
        constants_sigmas_cap: builder.add_virtual_cap(inner_cd2.config.fri_config.cap_height),
        circuit_digest: builder.add_virtual_hash(),
    };
    builder.register_public_inputs(vc2.circuit_digest.elements.as_slice());

    builder.verify_proof::<InnerC>(&pt1, &vc1, inner_cd1);
    builder.verify_proof::<InnerC>(&pt2, &vc2, inner_cd2);
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    (
        builder.build::<C>(),
        RecursiveWiringTargets { pt1, pt2, vc1, vc2 },
    )
}

pub fn gen_recursive_circuit<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner1: &ProofTuple<F, InnerC, D>,
    inner2: &ProofTuple<F, InnerC, D>,
    data: CircuitData<F, C, D>,
    wiring: RecursiveWiringTargets<D>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let (inner_proof1, inner_vd1, inner_cd1) = inner1;
    let (inner_proof2, inner_vd2, inner_cd2) = inner2;

    let mut pw = PartialWitness::new();

    pw.set_proof_with_pis_target(&wiring.pt1, &inner_proof1);
    pw.set_verifier_data_target(&wiring.vc1, &inner_vd1);
    pw.set_proof_with_pis_target(&wiring.pt2, inner_proof2);
    pw.set_verifier_data_target(&wiring.vc2, inner_vd2);

    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}

pub fn recursive_proof<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    InnerC: GenericConfig<D, F = F>,
    const D: usize,
>(
    inner1: &ProofTuple<F, InnerC, D>,
    inner2: Option<ProofTuple<F, InnerC, D>>,
    config: &CircuitConfig,
    min_degree_bits: Option<usize>,
) -> Result<ProofTuple<F, C, D>>
where
    InnerC::Hasher: AlgebraicHasher<F>,
{
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let mut pw = PartialWitness::new();

    {
        let (inner_proof, inner_vd, inner_cd) = inner1;
        let pt = builder.add_virtual_proof_with_pis::<InnerC>(inner_cd);
        pw.set_proof_with_pis_target(&pt, inner_proof);
        builder.register_public_inputs(&*pt.public_inputs);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

        builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    }

    if inner2.is_some() {
        let (inner_proof, inner_vd, inner_cd) = inner2.unwrap();
        let pt = builder.add_virtual_proof_with_pis::<InnerC>(&inner_cd);
        pw.set_proof_with_pis_target(&pt, &inner_proof);
        builder.register_public_inputs(&*pt.public_inputs);

        let inner_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(inner_cd.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);
        pw.set_cap_target(
            &inner_data.constants_sigmas_cap,
            &inner_vd.constants_sigmas_cap,
        );

        builder.verify_proof::<InnerC>(&pt, &inner_data, &inner_cd);
    }
    builder.print_gate_counts(0);

    if let Some(min_degree_bits) = min_degree_bits {
        // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
        // add a few special gates afterward. So just pad to 2^(min_degree_bits
        // - 1) + 1. Then the builder will pad to the next power of two,
        // 2^min_degree_bits.
        let min_gates = (1 << (min_degree_bits - 1)) + 1;
        for _ in builder.num_gates()..min_gates {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let data = builder.build::<C>();

    let mut timing = TimingTree::new("prove", Level::Info);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    data.verify(proof.clone())?;

    Ok((proof, data.verifier_only, data.common))
}
