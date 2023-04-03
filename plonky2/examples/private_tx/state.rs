use log::info;
use plonky2::hash::merkle_proofs::MerkleProof;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::{GenericHashOut, Hasher};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

use crate::merkle_tree::MerkleTree;

pub struct State {
    //private_utxo_tree stores Hash (privateKey, 0,0, tokenID, token_amount) of currently available tree
    pub private_utxo_tree: MerkleTree<GoldilocksField, PoseidonHash>,
    //nullify_utxo_tree stores Hash (privateKey, 0,0, tokenID, token_amount) of the used tree
    pub nullify_utxo_tree: MerkleTree<GoldilocksField, PoseidonHash>,
    //cap height h is the h-th layer from the root of the intermedia hashes.
    pub merkle_cap_height: usize,
}

impl State {
    pub fn new(
        private_utxo_leaves: Vec<Vec<GoldilocksField>>,
        nullify_leaves: Vec<Vec<GoldilocksField>>,
    ) -> Self {
        Self {
            private_utxo_tree: MerkleTree::<GoldilocksField, PoseidonHash>::new(
                private_utxo_leaves,
                0,
            ),
            nullify_utxo_tree: MerkleTree::<GoldilocksField, PoseidonHash>::new(nullify_leaves, 0),
            merkle_cap_height: 0,
        }
    }

    pub fn add_private_utxo(
        &mut self,
        h: <PoseidonHash as Hasher<GoldilocksField>>::Hash,
        index: usize,
    ) {
        self.private_utxo_tree
            .update(h.to_vec(), index, self.merkle_cap_height);
    }

    pub fn add_nullify_utxo(
        &mut self,
        h: <PoseidonHash as Hasher<GoldilocksField>>::Hash,
        index: usize,
    ) {
        self.nullify_utxo_tree
            .update(h.to_vec(), index, self.merkle_cap_height);
    }

    //call this from client to get its proof
    pub fn private_utxo_merkle_proof(
        &self,
        index: usize,
    ) -> MerkleProof<GoldilocksField, PoseidonHash> {
        self.private_utxo_tree.prove(index)
    }

    // return a test state with a leave pointing to the user
    pub fn new_demo_state(
        prive_key: [GoldilocksField; 4],
        token_id: GoldilocksField,
        balance: u64,
        height: i32,
    ) -> (Self, usize) {
        let leave = PoseidonHash::hash_no_pad(
            &[
                prive_key,
                [
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    token_id,
                    GoldilocksField::from_canonical_u64(balance),
                ],
            ]
            .concat(),
        )
        .elements
        .to_vec();
        info!("leave private hash {:?}", leave);

        let n = 1 << height;
        let mut leaves: Vec<Vec<GoldilocksField>> = (0..n)
            .map(|_| {
                PoseidonHash::hash_no_pad(&[
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                ])
                .elements
                .to_vec()
            })
            .collect();
        leaves[0] = leave;
        let nulify_leaves: Vec<Vec<GoldilocksField>> = (0..n)
            .map(|_| {
                PoseidonHash::hash_no_pad(&[
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                    GoldilocksField::ZERO,
                ])
                .elements
                .to_vec()
            })
            .collect();
        (
            Self {
                private_utxo_tree: MerkleTree::<GoldilocksField, PoseidonHash>::new(leaves, 0),
                nullify_utxo_tree: MerkleTree::<GoldilocksField, PoseidonHash>::new(
                    nulify_leaves,
                    0,
                ),
                merkle_cap_height: 0,
            },
            0,
        )
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Sample;

    use crate::state::State;

    #[test]
    fn test_demo_state() -> Result<()> {
        let prive_key: [GoldilocksField; 4] = GoldilocksField::rand_array();
        let (demo, index) = State::new_demo_state(prive_key, GoldilocksField::rand(), 10000, 10);
        let proof = demo.private_utxo_tree.prove(index);
        Ok(())
    }
}
