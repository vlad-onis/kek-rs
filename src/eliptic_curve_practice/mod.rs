/// This program plays around with eliptic curve cryptographic concepts.
/// Specifically:
/// * Create a private / public key pair
/// * Obtain a valid ethereum address derived from the public key
/// * Hash a message to be signed
/// * Sign the message using the private key
/// * Derive the public key from the signature
use k256::{ecdsa::SigningKey, ecdsa::VerifyingKey, elliptic_curve::rand_core::OsRng};
use tiny_keccak::{Hasher, Keccak};

/// Leverages Keccak hash3 function to hash a message
pub fn hash_personal_message(message: &[u8]) -> [u8; 32] {
    let prefix_str = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let prefix_bytes = prefix_str.as_bytes();

    let mut full_message = Vec::with_capacity(prefix_bytes.len() + message.len());
    full_message.extend_from_slice(prefix_bytes);
    full_message.extend_from_slice(message);

    let mut hasher = Keccak::v256();
    hasher.update(&full_message);

    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Converts a public key to valid ethereum address
/// The public key is an ecdsa uncompressed key:
///     * 0x04 is the prefix
///     * The next 32 bytes are the X component on the curve
///     * The last 32 bytes are the Y component on the curve
/// Once you hash the X and Y components together into a 32 bytes array,
/// you only pick the last 20 bytes and those represent the address
pub fn to_ethereum_address(uncompressed_pub_key: &[u8]) -> Result<String, String> {
    if uncompressed_pub_key.len() == 65 && uncompressed_pub_key[0] == 0x04 {
        let mut pubkey_hasher = Keccak::v256();
        pubkey_hasher.update(&uncompressed_pub_key[1..]);
        let mut pubkey_hash = [0u8; 32];
        pubkey_hasher.finalize(&mut pubkey_hash);

        let address_bytes = &pubkey_hash[12..]; // the last 20 bytes
        Ok(format!("0x{}", hex::encode(address_bytes)))
    } else {
        Err(format!(
            "Invalid uncompressed key format: Length = {}, Prefix = {:02x}",
            uncompressed_pub_key.len(),
            if uncompressed_pub_key.len() != 0 {
                uncompressed_pub_key[0]
            } else {
                0
            },
        ))
    }
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let private_key = SigningKey::random(&mut OsRng);

    println!("Private key: 0x{}\n", hex::encode(private_key.to_bytes()));

    let public_key = private_key.verifying_key().clone();
    let binding = public_key.to_encoded_point(false);
    let uncompressed_public_key_bytes = binding.as_bytes();

    println!(
        "Public key: 0x{}\n",
        hex::encode(public_key.to_sec1_bytes())
    );

    let eth_address = to_ethereum_address(uncompressed_public_key_bytes);
    println!("ETH address: {:?}\n", eth_address.unwrap());

    let message_str = "This is the message to sign";
    let message_hash = hash_personal_message(message_str.as_bytes());

    let (signature, recovery_id) = private_key.sign_prehash_recoverable(&message_hash).unwrap();

    println!("Message: {message_str}\n");
    println!("Signature: {signature}\n");

    // Recover the public key from the signature
    let recovered_public_key =
        VerifyingKey::recover_from_prehash(&message_hash, &signature, recovery_id).unwrap();
    println!(
        "Recovered public key: 0x{}\n",
        hex::encode(recovered_public_key.to_sec1_bytes())
    );
    assert_eq!(
        recovered_public_key.to_sec1_bytes(),
        public_key.to_sec1_bytes()
    );

    Ok(())
}
