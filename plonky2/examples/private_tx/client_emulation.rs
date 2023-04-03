use std::sync::Arc;
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;

use plonky2::hash::poseidon::PoseidonHash;

use anyhow::Result;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use crate::circuit;
use crate::circuit::{PrivateWitness, PublicInputs};

use crate::state::State;

pub struct Client {
    state: State,
    //mock, this should be from server
    priv_key: [GoldilocksField; 4],
    token_id: GoldilocksField,
    balance: u64,
    priv_index: usize,
    config: CircuitConfig,
    tree_height: usize,
}

impl Client {
    //state must include a leaf with priv_key
    pub fn new(state: State, priv_key: [GoldilocksField; 4], token_id: GoldilocksField, balance: u64, priv_index: usize) -> Self {
        Self {
            state,
            priv_key,
            token_id,
            balance,
            priv_index,
            config: CircuitConfig::standard_recursion_config(),
            tree_height: 10,
        }
    }


    pub fn split(&self, delta: u64) -> Result<()> {
        const D: usize = 2;

        assert!(delta <= self.balance,
                "can't split more than what you have"
        );
        let old_private_tree_hash = PoseidonHash::hash_no_pad(&[self.priv_key, [GoldilocksField::ZERO, GoldilocksField::ZERO, self.token_id, GoldilocksField::from_canonical_u64(self.balance)]].concat());
        let merkle_proof = self.state.private_utxo_merkle_proof(self.priv_index);
        let old_root = self.state.private_utxo_tree.cap.0[0];
        let new_private_tree_hash = PoseidonHash::hash_no_pad(&[self.priv_key, [GoldilocksField::ZERO, GoldilocksField::ZERO, self.token_id, GoldilocksField::from_canonical_u64(self.balance - delta)]].concat());

        //TODO: Credit an account
        let p_witness = PrivateWitness {
            private_key: self.priv_key,
            index: self.priv_index,
            token_id: self.token_id,
            token_amount: GoldilocksField::from_canonical_u64(self.balance),
            merkle_proof,
        };
        let public_inp = PublicInputs {
            nullifier_value: old_private_tree_hash,
            merkle_root_value: old_root.into(),
            new_leaf_value: new_private_tree_hash,
        };

        //Generate a proof of our privateTX
        let (circuit_data, wiring) = circuit::private_tx_circuit::<GoldilocksField, PoseidonGoldilocksConfig, D>(&self.config, self.tree_height);
        let proof = circuit::gen_private_proof::<GoldilocksField, PoseidonGoldilocksConfig, D>(circuit_data, public_inp, p_witness, wiring)?;

        Ok(())
        //We don't need to verify this. let's the server do it.
    }
}


#[cfg(test)]
mod tests {
    use anyhow::Result;
    use plonky2_field::goldilocks_field::GoldilocksField;
    use plonky2_field::types::Sample;
    use crate::state::State;

    #[test]
    fn test_client_split() -> Result<()> {
        let tree_height = 10;
        let prive_key: [GoldilocksField; 4] = GoldilocksField::rand_array();
        let (demo, index) = State::new_demo_state(prive_key, GoldilocksField::rand(), 10000, 10);
        let proof = demo.private_utxo_tree.prove(index);
        Ok(())
    }
}
