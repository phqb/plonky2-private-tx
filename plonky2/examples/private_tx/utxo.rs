use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2_field::goldilocks_field::GoldilocksField;

pub struct UTXO<F>{
    pub token_Id: F,
    pub amount: F,
}

pub type UTXOTree= MerkleTree<GoldilocksField, PoseidonHash>;

