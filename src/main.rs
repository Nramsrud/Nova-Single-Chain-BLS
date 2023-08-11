use std::{
    collections::HashMap,
    env::current_dir,
    time::{Instant, Duration},
    io::Write,
    path::PathBuf,
    fs,
};

use nova_scotia::{
    circom::reader::{load_r1cs, generate_witness_from_bin},
    create_public_params, create_recursive_circuit, FileLocation, F1, G2, S1, S2,
};
use ff::PrimeField;
use nova_snark::{traits::Group, CompressedSNARK};
use serde_json::json;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use num_bigint::BigInt;
use num_traits::Num;

#[derive(Serialize, Deserialize)]
struct CircomInput {
    step_in: Vec<String>,
    #[serde(flatten)]
    extra: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize)]
struct Inputfile {
    step_in: Vec<Vec<[String; 7]>>,
    pubkeys: Vec<Vec<[String; 7]>>,
    pubkeybits: Vec<u8>,
    signature: Vec<Vec<[String; 7]>>,
}

fn main() {
    // Define the path to circuit and witness generator files
    let circuit_file = PathBuf::from("novatest_aggregate_bls_verify_512.r1cs");
    let witness_generator_file = PathBuf::from("novatest_aggregate_bls_verify_512_cpp/novatest_aggregate_bls_verify_512");

    // Read the input file
    let inputs: Inputfile = serde_json::from_str(include_str!("novainput_aggregate_bls_verify_512.json")).unwrap();

    // Define root directory
    let root = PathBuf::from("/");

    // Convert public input data to the correct format
    let mut pubin = Vec::new();
    for x in 0..2 {
        for k in 0..7 {
            pubin.push(F1::from_str_vartime(&inputs.step_in[x][0][k]).unwrap());
        }
        for k in 0..7 {
            pubin.push(F1::from_str_vartime(&inputs.step_in[x][1][k]).unwrap());
        }
    }
    let start_public_input = pubin.clone();

    println!("Reading in R1CS...");
    let start = Instant::now();
    // Load R1CS constraints
    let r1cs = load_r1cs(&FileLocation::PathBuf(circuit_file));
    println!("R1CS readin took: {:?}", start.elapsed());

    println!("Creating a CRS");
    // Generate public parameters
    let start = Instant::now();
    let pp = create_public_params(r1cs.clone());
    println!("CRS creation took {:?}", start.elapsed());

    // Define lengths to iterate over
    let pubkeylen = inputs.pubkeys.len();
    let pubkeybitlen = inputs.pubkeybits.len();
    let signaturelen = inputs.signature.len();

    let mut iteration_count = 0;
    let mut j = 2;//starting number of committee members

    // Main loop for recursiveSNARK creation and verification over each iteration
    for i in 1..=6 {
        let iteration_count = j; // Setting iteration count
        println!("iteration count {}", j);

        // Creating private inputs from a JSON source.
        // These are organized into hashmaps, which are then placed into a vector.
        let mut private_inputs = Vec::new();
        for _ in 0..iteration_count {
            let mut private_input = HashMap::new();
            private_input.insert("pubkeys".to_string(), json!(inputs.pubkeys[0..pubkeylen]));
            private_input.insert("pubkeybits".to_string(), json!(inputs.pubkeybits[0..pubkeybitlen]));
            private_input.insert("signature".to_string(), json!(inputs.signature[0..signaturelen]));
            private_inputs.push(private_input);
        }

        println!("this is the length of private inputs: {:?}", private_inputs.len());

        println!("Creating a RecursiveSNARK...");
        let start = Instant::now();

        // Instantiating recursion for SNARK creation
        let recursive_snark = create_recursive_circuit(
            FileLocation::PathBuf(witness_generator_file.clone()),
            r1cs.clone(),
            private_inputs,
            start_public_input.clone(),
            &pp,
        ).unwrap();
        println!("RecursiveSNARK creation took {:?}", start.elapsed());
        let prover_time = start.elapsed();

        let z0_secondary = vec![<G2 as Group>::Scalar::zero()];

        // Verifying the recursive snark
        println!("Verifying a RecursiveSNARK...");
        let start = Instant::now();
        let res = recursive_snark.verify(&pp, iteration_count, start_public_input.clone(), z0_secondary.clone());
        println!("RecursiveSNARK::verify: {:?}, took {:?}", res, start.elapsed());
        let verifier_time = start.elapsed();
        assert!(res.is_ok());

        // Generating a compressed SNARK
        println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
        let start = Instant::now();
        let (pk, vk) = CompressedSNARK::<_, _, _, _, S1, S2>::setup(&pp).unwrap();
        let res = CompressedSNARK::<_, _, _, _, S1, S2>::prove(&pp, &pk, &recursive_snark);
        println!("CompressedSNARK::prove: {:?}, took {:?}", res.is_ok(), start.elapsed());
        let compressed_snark_prover_time = start.elapsed();
        assert!(res.is_ok());
        let compressed_snark = res.unwrap();

        // Verifying the compressed SNARK
        println!("Verifying a CompressedSNARK...");
        let start = Instant::now();
        let res = compressed_snark.verify(&vk, iteration_count, start_public_input.clone(), z0_secondary);
        println!("CompressedSNARK::verify: {:?}, took {:?}", res.is_ok(), start.elapsed());
        let compressed_snark_verifier_time = start.elapsed();
        assert!(res.is_ok());

        j *= 2; // Doubling the value of j for the next iteration

    }
}
