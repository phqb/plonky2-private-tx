#![allow(clippy::int_plus_one)] // Makes more sense for some inequalities below.

use alloc::vec;

use anyhow::{ensure, Result};

use crate::field::extension::Extendable;
use crate::fri::proof::FriProofTarget;
use crate::gadgets::polynomial::PolynomialCoeffsExtTarget;
use crate::gates::noop::NoopGate;
use crate::hash::hash_types::RichField;
use crate::iop::witness::{PartialWitness, Witness};
use crate::plonk::circuit_builder::CircuitBuilder;
use crate::plonk::circuit_data::{
    CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use crate::plonk::config::{AlgebraicHasher, GenericConfig};
use crate::plonk::proof::{ProofTarget, ProofWithPublicInputs, ProofWithPublicInputsTarget};

pub struct TreeRecursionData<
    'a,
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
> {
    proof: &'a ProofWithPublicInputs<F, C, D>,
    verifier_data: &'a VerifierOnlyCircuitData<C, D>,
    common_data: &'a CommonCircuitData<F, D>,
}

pub struct TreeRecursionNodeTarget<const D: usize> {
    pub proof0: ProofWithPublicInputsTarget<D>,
    pub proof1: ProofWithPublicInputsTarget<D>,
    pub verifier_data0: VerifierCircuitTarget,
    pub verifier_data1: VerifierCircuitTarget,
}

pub struct TreeRecursionLeafTarget<const D: usize> {
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub inner_verifier_data: VerifierCircuitTarget,
    pub verifier_data: VerifierCircuitTarget,
}

pub fn clone_proof_target<const D: usize>(
    proof_with_pis: &ProofWithPublicInputsTarget<D>,
) -> ProofWithPublicInputsTarget<D> {
    ProofWithPublicInputsTarget {
        proof: ProofTarget {
            wires_cap: proof_with_pis.proof.wires_cap.clone(),
            plonk_zs_partial_products_cap: proof_with_pis
                .proof
                .plonk_zs_partial_products_cap
                .clone(),
            quotient_polys_cap: proof_with_pis.proof.quotient_polys_cap.clone(),
            openings: proof_with_pis.proof.openings.clone(),
            opening_proof: FriProofTarget {
                commit_phase_merkle_caps: proof_with_pis
                    .proof
                    .opening_proof
                    .commit_phase_merkle_caps
                    .clone(),
                query_round_proofs: proof_with_pis
                    .proof
                    .opening_proof
                    .query_round_proofs
                    .clone(),
                final_poly: PolynomialCoeffsExtTarget(
                    proof_with_pis.proof.opening_proof.final_poly.0.clone(),
                ),
                pow_witness: proof_with_pis.proof.opening_proof.pow_witness.clone(),
            },
        },
        public_inputs: proof_with_pis.public_inputs.clone(),
    }
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilder<F, D> {
    /// WARNING: Do not register any public input before/after calling this!
    // Use requirement:
    // public inputs: [
    //   H(left_inputs, right_inputs),
    //   H(left_circuit_digest, current_circuit_digest, right_circuit_digest),
    //   current_verifier_data ]
    // Root node MUST be verified without using 'current_verifier_data' input.
    // All nodes/leaves should use the same common data.
    //
    // In this circuits:
    // 1) added two virtual inner proofs (with verifier_data as part of inputs)
    // 2) connected public inputs [0] and [1] with calculated hashes
    // 3) verified two inner proofs with their own verifier_data
    pub fn tree_recursion_node<C: GenericConfig<D, F = F>>(
        &mut self,
        common_data: &mut CommonCircuitData<F, D>,
    ) -> Result<TreeRecursionNodeTarget<D>>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let inputs_hash = self.add_virtual_hash();
        let circuit_digest_hash = self.add_virtual_hash();
        self.register_public_inputs(&inputs_hash.elements);
        self.register_public_inputs(&circuit_digest_hash.elements);

        assert!(self.verifier_data_public_input.is_none());
        self.add_verifier_data_public_input();
        let verifier_data = self.verifier_data_public_input.clone().unwrap();
        assert_eq!(common_data.num_public_inputs, self.num_public_inputs());

        let proof0 = self.add_virtual_proof_with_pis::<C>(common_data);
        let proof1 = self.add_virtual_proof_with_pis::<C>(common_data);

        let verifier_data0 = VerifierCircuitTarget::from_slice::<F, C, D>(
            &proof0.public_inputs.clone(),
            common_data,
        )?;
        let verifier_data1 = VerifierCircuitTarget::from_slice::<F, C, D>(
            &proof1.public_inputs.clone(),
            common_data,
        )?;

        let h = self.hash_n_to_hash_no_pad::<C::Hasher>(
            [
                proof0.public_inputs[0..4].to_vec(),
                proof1.public_inputs[0..4].to_vec(),
            ]
            .concat(),
        );
        self.connect_hashes(inputs_hash, h);
        let h = self.hash_n_to_hash_no_pad::<C::Hasher>(
            [
                proof0.public_inputs[4..8].to_vec(),
                verifier_data.circuit_digest.elements.to_vec(),
                proof1.public_inputs[4..8].to_vec(),
            ]
            .concat(),
        );
        self.connect_hashes(circuit_digest_hash, h);

        self.verify_proof::<C>(clone_proof_target(&proof0), &verifier_data0, common_data);
        self.verify_proof::<C>(clone_proof_target(&proof1), &verifier_data1, common_data);

        // Make sure we have enough gates to match `common_data`.
        while self.num_gates() < (common_data.degree() / 2) {
            self.add_gate(NoopGate, vec![]);
        }
        // Make sure we have every gate to match `common_data`.
        for g in &common_data.gates {
            self.add_gate_to_gate_set(g.clone());
        }

        Ok(TreeRecursionNodeTarget {
            proof0,
            proof1,
            verifier_data0,
            verifier_data1,
        })
    }

    /// WARNING: Do not register any public input before/after calling this!
    // public inputs: [
    //   H(inner_inputs),
    //   H(current_circuit_digest, inner_circuit_digest),
    //   current_verifier_data ]
    pub fn tree_recursion_leaf<C: GenericConfig<D, F = F>>(
        &mut self,
        inner_common_data: CommonCircuitData<F, D>,
        common_data: &mut CommonCircuitData<F, D>,
    ) -> Result<TreeRecursionLeafTarget<D>>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let inputs_hash = self.add_virtual_hash();
        let circuit_digest_hash = self.add_virtual_hash();
        self.register_public_inputs(&inputs_hash.elements);
        self.register_public_inputs(&circuit_digest_hash.elements);

        assert!(self.verifier_data_public_input.is_none());
        self.add_verifier_data_public_input();
        let verifier_data = self.verifier_data_public_input.clone().unwrap();
        assert_eq!(common_data.num_public_inputs, self.num_public_inputs());

        let inner_proof = self.add_virtual_proof_with_pis::<C>(&inner_common_data);
        let inner_verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: self
                .add_virtual_cap(inner_common_data.config.fri_config.cap_height),
            circuit_digest: self.add_virtual_hash(),
        };

        let h = self.hash_n_to_hash_no_pad::<C::Hasher>(inner_proof.public_inputs.clone());
        self.connect_hashes(inputs_hash, h);
        let h = self.hash_n_to_hash_no_pad::<C::Hasher>(
            [
                verifier_data.circuit_digest.elements,
                inner_verifier_data.circuit_digest.elements,
            ]
            .concat(),
        );
        self.connect_hashes(circuit_digest_hash, h);

        self.verify_proof::<C>(
            clone_proof_target(&inner_proof),
            &inner_verifier_data,
            &inner_common_data,
        );

        // Make sure we have enough gates to match `common_data`.
        while self.num_gates() < (common_data.degree() / 2) {
            self.add_gate(NoopGate, vec![]);
        }
        // Make sure we have every gate to match `common_data`.
        for g in &common_data.gates {
            self.add_gate_to_gate_set(g.clone());
        }

        Ok(TreeRecursionLeafTarget {
            inner_proof,
            inner_verifier_data,
            verifier_data,
        })
    }
}

/// Set the targets in a `TreeRecursionTarget` to their corresponding values in a `TreeRecursionData`.
pub fn set_tree_recursion_node_data_target<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    pw: &mut PartialWitness<F>,
    tree_recursion_data_target: &TreeRecursionNodeTarget<D>,
    tree_recursion_data0: &TreeRecursionData<F, C, D>,
    tree_recursion_data1: &TreeRecursionData<F, C, D>,
) -> Result<()>
where
    C::Hasher: AlgebraicHasher<F>,
{
    pw.set_proof_with_pis_target(
        &tree_recursion_data_target.proof0,
        tree_recursion_data0.proof,
    );
    pw.set_proof_with_pis_target(
        &tree_recursion_data_target.proof1,
        tree_recursion_data1.proof,
    );
    pw.set_verifier_data_target(
        &tree_recursion_data_target.verifier_data0,
        tree_recursion_data0.verifier_data,
    );
    pw.set_verifier_data_target(
        &tree_recursion_data_target.verifier_data1,
        tree_recursion_data1.verifier_data,
    );

    Ok(())
}

/// Additional checks to be performed on a tree recursive proof in addition to verifying the proof.
/// Checks that the purported verifier data in the public inputs match the real verifier data.
pub fn check_tree_proof_verifier_data<
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    const D: usize,
>(
    proof: &ProofWithPublicInputs<F, C, D>,
    verifier_data: &VerifierOnlyCircuitData<C, D>,
    common_data: &CommonCircuitData<F, D>,
) -> Result<()>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let pis = VerifierOnlyCircuitData::<C, D>::from_slice(&proof.public_inputs, common_data)?;
    ensure!(verifier_data.constants_sigmas_cap == pis.constants_sigmas_cap);
    ensure!(verifier_data.circuit_digest == pis.circuit_digest);

    Ok(())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    use crate::field::extension::Extendable;
    use crate::field::types::{Field, PrimeField64};
    use crate::gates::noop::NoopGate;
    use crate::hash::hash_types::{HashOut, RichField};
    use crate::hash::hashing::hash_n_to_hash_no_pad;
    use crate::hash::poseidon::{PoseidonHash, PoseidonPermutation};
    use crate::iop::witness::{PartialWitness, Witness};
    use crate::plonk::circuit_builder::CircuitBuilder;
    use crate::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget};
    use crate::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};

    // Generates `CommonCircuitData` usable for recursion.
    fn common_data_for_recursion<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        const D: usize,
    >() -> CommonCircuitData<F, D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let config = CircuitConfig::standard_recursion_config();
        let builder = CircuitBuilder::<F, D>::new(config);
        let data = builder.build::<C>();
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proof = builder.add_virtual_proof_with_pis::<C>(&data.common);
        let verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        builder.verify_proof::<C>(proof, &verifier_data, &data.common);
        let data = builder.build::<C>();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let proof = builder.add_virtual_proof_with_pis::<C>(&data.common);
        let verifier_data = VerifierCircuitTarget {
            constants_sigmas_cap: builder.add_virtual_cap(data.common.config.fri_config.cap_height),
            circuit_digest: builder.add_virtual_hash(),
        };
        builder.verify_proof::<C>(proof, &verifier_data, &data.common);
        while builder.num_gates() < 1 << 12 {
            builder.add_gate(NoopGate, vec![]);
        }
        builder.build::<C>().common
    }

    #[test]
    fn test_tree_recursion() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let config = CircuitConfig::standard_recursion_config();

        let hash0 = HashOut {
            elements: [F::ZERO, F::ONE, F::TWO, F::from_canonical_usize(3)],
        };
        // create dummy proof0
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        for _ in 0..1_000 {
            builder.add_gate(NoopGate, vec![]);
        }
        let input_hash = builder.add_virtual_hash();
        builder.register_public_inputs(&input_hash.elements);
        let data = builder.build::<C>();
        let mut inputs = PartialWitness::new();
        inputs.set_hash_target(input_hash, hash0);
        let proof = data.prove(inputs)?;
        data.verify(proof.clone())?;

        //
        // // Circuit that computes a repeated hash.
        // let initial_hash = builder.add_virtual_hash();
        // builder.register_public_inputs(&initial_hash.elements);
        // // Hash from the previous proof.
        // let old_hash = builder.add_virtual_hash();
        // // The input hash is either the previous hash or the initial hash depending on whether
        // // the last proof was a base case.
        // let input_hash = builder.add_virtual_hash();
        // let h = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input_hash.elements.to_vec());
        // builder.register_public_inputs(&h.elements);
        // // Previous counter.
        // let old_counter = builder.add_virtual_target();
        // let new_counter = builder.add_virtual_public_input();
        // let old_pis = [
        //     initial_hash.elements.as_slice(),
        //     old_hash.elements.as_slice(),
        //     [old_counter].as_slice(),
        // ]
        //     .concat();
        //
        // let mut common_data = common_data_for_recursion::<F, C, D>();
        //
        // let condition = builder.add_virtual_bool_target_safe();
        // // Add tree recursion gadget.
        // let tree_data_target =
        //     builder.tree_recursion::<C>(condition, &old_pis, &mut common_data)?;
        // let input_hash_bis =
        //     builder.select_hash(tree_data_target.condition, old_hash, initial_hash);
        // builder.connect_hashes(input_hash, input_hash_bis);
        // // New counter is the previous counter +1 if the previous proof wasn't a base case.
        // let new_counter_bis = builder.add(old_counter, condition.target);
        // builder.connect(new_counter, new_counter_bis);
        //
        // let tree_circuit_data = builder.build::<C>();
        //
        // let tree_recursion_data = TreeRecursionData {
        //     proof: &None, // Base case: We don't have a proof to put here yet.
        //     verifier_data: &tree_circuit_data.verifier_only,
        //     common_data: &tree_circuit_data.common,
        // };
        // let initial_hash = [F::ZERO, F::ONE, F::TWO, F::from_canonical_usize(3)];
        // set_tree_recursion_data_target(
        //     &mut pw,
        //     &tree_data_target,
        //     &tree_recursion_data,
        //     &initial_hash,
        // )?;
        // let proof = tree_circuit_data.prove(pw)?;
        // check_tree_proof_verifier_data(
        //     &proof,
        //     tree_recursion_data.verifier_data,
        //     tree_recursion_data.common_data,
        // )?;
        // tree_circuit_data.verify(proof.clone())?;
        //
        // // 1st recursive layer.
        // let mut pw = PartialWitness::new();
        // let tree_recursion_data = TreeRecursionData {
        //     proof: &Some(proof), // Input previous proof.
        //     verifier_data: &tree_circuit_data.verifier_only,
        //     common_data: &tree_circuit_data.common,
        // };
        // set_tree_recursion_data_target(
        //     &mut pw,
        //     &tree_data_target,
        //     &tree_recursion_data,
        //     &[],
        // )?;
        // let proof = tree_circuit_data.prove(pw)?;
        // check_tree_proof_verifier_data(
        //     &proof,
        //     tree_recursion_data.verifier_data,
        //     tree_recursion_data.common_data,
        // )?;
        // tree_circuit_data.verify(proof.clone())?;
        //
        // // 2nd recursive layer.
        // let mut pw = PartialWitness::new();
        // let tree_recursion_data = TreeRecursionData {
        //     proof: &Some(proof), // Input previous proof.
        //     verifier_data: &tree_circuit_data.verifier_only,
        //     common_data: &tree_circuit_data.common,
        // };
        // set_tree_recursion_data_target(
        //     &mut pw,
        //     &tree_data_target,
        //     &tree_recursion_data,
        //     &[],
        // )?;
        // let proof = tree_circuit_data.prove(pw)?;
        // check_tree_proof_verifier_data(
        //     &proof,
        //     tree_recursion_data.verifier_data,
        //     tree_recursion_data.common_data,
        // )?;
        //
        // // Verify that the proof correctly computes a repeated hash.
        // let initial_hash = &proof.public_inputs[..4];
        // let hash = &proof.public_inputs[4..8];
        // let counter = proof.public_inputs[8];
        // let mut h: [F; 4] = initial_hash.try_into().unwrap();
        // assert_eq!(
        //     hash,
        //     core::iter::repeat_with(|| {
        //         h = hash_n_to_hash_no_pad::<F, PoseidonPermutation>(&h).elements;
        //         h
        //     })
        //         .nth(counter.to_canonical_u64() as usize)
        //         .unwrap()
        // );
        //
        // tree_circuit_data.verify(proof)

        Ok(())
    }
}
