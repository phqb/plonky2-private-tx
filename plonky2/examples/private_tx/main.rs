mod circom;
mod circom_config;
mod circuit;
mod client_emulation;
mod server_emulation;
mod state;
mod utxo;

use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use log::info;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2_field::goldilocks_field::GoldilocksField;
use plonky2_field::types::{Field, Sample};

use crate::circom::{generate_circom_verifier, generate_proof_base64, generate_verifier_config};
use crate::circom_config::PoseidonBN128GoldilocksConfig;
use crate::circuit::{
    gen_private_proof, private_tx_circuit, recursive_proof, verify_proof, PrivateWitness,
    PublicInputs,
};
use crate::state::State;

fn main() -> Result<()> {
    env_logger::init();

    info!("starting test");
    const D: usize = 2;
    const tree_height: usize = 10;
    let zk_config = CircuitConfig::standard_recursion_config();
    let (data, wr) =
        private_tx_circuit::<GoldilocksField, PoseidonGoldilocksConfig, D>(&zk_config, tree_height);
    let token_id = GoldilocksField::from_canonical_u64(1);
    let balance: u64 = 1000;
    let delta: u64 = 100;
    let priv_key: [GoldilocksField; 4] = GoldilocksField::rand_array();
    let (demo, index) = State::new_demo_state(priv_key, token_id, balance, 10);
    let merkle_proof = demo.private_utxo_tree.prove(index);

    let old_private_tree_hash = PoseidonHash::hash_no_pad(
        &[
            priv_key,
            [
                GoldilocksField::ZERO,
                GoldilocksField::ZERO,
                token_id,
                GoldilocksField::from_canonical_u64(balance),
            ],
        ]
        .concat(),
    );
    info!("old private hash {:?}", old_private_tree_hash);
    let old_root = demo.private_utxo_tree.cap.0[0];
    let new_private_tree_hash = PoseidonHash::hash_no_pad(
        &[
            priv_key,
            [
                GoldilocksField::ZERO,
                GoldilocksField::ZERO,
                token_id,
                GoldilocksField::from_canonical_u64(balance - delta),
            ],
        ]
        .concat(),
    );
    let pub_input = PublicInputs {
        nullifier_value: old_private_tree_hash,
        new_leaf_value: new_private_tree_hash,
        merkle_root_value: old_root,
    };
    let private_witness = PrivateWitness {
        private_key: priv_key,
        index,
        token_id,
        token_amount: GoldilocksField(balance),
        merkle_proof,
    };

    info!("nullifier_value: {:?}", old_private_tree_hash);
    info!("new_leaf_value: {:?}", new_private_tree_hash);
    info!("pub_input: {:?}", pub_input);

    info!("witness: {:?}", private_witness);

    let zk_proof = gen_private_proof(data, pub_input, private_witness, wr)?;

    type CBn128 = PoseidonBN128GoldilocksConfig;
    let outer = recursive_proof::<GoldilocksField, CBn128, PoseidonGoldilocksConfig, D>(
        &zk_proof, None, &zk_config, None,
    )?;

    let (proof, vd, cd) = &outer;

    /*
        Generate circom files
    */
    let conf = generate_verifier_config(&proof)?;
    let (circom_constants, circom_gates) = generate_circom_verifier(&conf, &cd, &vd)?;

    let mut circom_file = File::create("./constants.circom")?;
    circom_file.write_all(circom_constants.as_bytes())?;
    circom_file = File::create("./gates.circom")?;
    circom_file.write_all(circom_gates.as_bytes())?;

    let proof_json = generate_proof_base64(&proof, &conf)?;

    let mut proof_file = File::create("./proof.json")?;
    proof_file.write_all(proof_json.as_bytes())?;

    let mut conf_file = File::create("./conf.json")?;
    conf_file.write_all(serde_json::to_string(&conf)?.as_ref())?;

    Ok(())
}
