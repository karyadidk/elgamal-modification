use clap::Parser;
use clap_derive::Subcommand;
use num_bigint::{BigUint, RandBigInt};
use num_traits::One;
use num_integer::Integer; // Import Integer for is_even()
use rand::thread_rng;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::fs::File;
use std::io::Write;
use std::fs;
use std::path::PathBuf;
use std::io;

/// CLI for key generation, encryption, and decryption
#[derive(Parser)]
#[command(name = "RustCrypto", version = "1.0", about = "Encrypt & Decrypt using BigUint")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available commands
#[derive(Subcommand)]
enum Commands {
    /// Generate a key pair
    GenerateKey {
        #[arg(short, long, help = "Size of the key in bits")]
        size: u64,

        #[arg(help = "Path to save the private key")]
        private_key_path: String,

        #[arg(help = "Path to save the public key")]
        public_key_path: String,
    },

    /// Encrypt a message
    Encrypt {
        #[arg(help = "Text message to encrypt")]
        text: String,

        #[arg(help = "Path to the private key")]
        public_key_path: String,

        #[arg(help = "Path to save the encrypted message")]
        message_output_path: String,
    },

    /// Decrypt a message
    Decrypt {
        #[arg(help = "Path to the public key")]
        private_key_path: String,

        #[arg(help = "Path to the encrypted message")]
        message_path: String,
    },
}

fn generate_key_pair(size: u64, private_key_path: &PathBuf, public_key_path: &PathBuf) -> std::io::Result<()> {
    let mut rng = thread_rng();

    // 1. Generate a 2048-bit random BigUint
    let p: BigUint = rng.gen_biguint(size);

    // 2. Choose a random a such that 1 < a < p
    let a: BigUint = rng.gen_biguint_range(&BigUint::one(), &p);
    let b = &p - &a; // Ensure a + b = p

    // 3. Choose an odd x
    let mut x: BigUint = rng.gen_biguint(size);
    if x.is_even() {
        x += BigUint::one(); // Make it odd
    }

    // Compute g = a^x mod p
    let g = a.modpow(&x, &p);

    let num_usize: usize = size.try_into().expect("Value too large for usize");
    let private_key_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            writer.next().write_u8(1); // version
            // Convert the BigNum to bytes
            let mut p_bytes = p.to_bytes_be();
            // Ensure it is exactly 256 bytes (2048 bits)
            if p_bytes.len() < (num_usize/8) + 1 {
                let mut padded_bytes = vec![0u8; (num_usize/8) - p_bytes.len()]; // Padding with zeros
                padded_bytes.extend_from_slice(&p_bytes); // Append original bytes
                p_bytes = padded_bytes;
            }
            writer.next().write_bigint_bytes(&p_bytes, true);
            let b_bytes = b.to_bytes_be();
            writer.next().write_bigint_bytes(&b_bytes, true);
            let x_bytes = x.to_bytes_be();
            writer.next().write_bigint_bytes(&x_bytes, true);
        });
    });

    // Encode in Base64
    let private_key = STANDARD.encode(&private_key_der);

    // Insert line breaks every 64 characters
    let formatted_private_key = private_key
        .as_bytes()
        .chunks(64) // Break into chunks of 64 chars
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("\n");

    // Format as PEM
    let pem_private = format!(
        "-----BEGIN CUSTOM PRIVATE KEY-----\n{}\n-----END CUSTOM PRIVATE KEY-----\n",
        formatted_private_key
    );


    let public_key_der = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // Convert the BigNum to bytes
            let mut p_bytes = p.to_bytes_be();
            // Ensure it is exactly 256 bytes (2048 bits)
            if p_bytes.len() < (num_usize/8) + 1 {
                let mut padded_bytes = vec![0u8; (num_usize/8) - p_bytes.len()]; // Padding with zeros
                padded_bytes.extend_from_slice(&p_bytes); // Append original bytes
                p_bytes = padded_bytes;
            }
            writer.next().write_bigint_bytes(&p_bytes, true);
            let b_bytes = b.to_bytes_be();
            writer.next().write_bigint_bytes(&b_bytes, true);
            let g_bytes = g.to_bytes_be();
            writer.next().write_bigint_bytes(&g_bytes, true);
        });
    });

    // Encode in Base64
    let public_key = STANDARD.encode(&public_key_der);

    // Insert line breaks every 64 characters
    let formatted_public_key = public_key
        .as_bytes()
        .chunks(64) // Break into chunks of 64 chars
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<&str>>()
        .join("\n");

    // Format as PEM
    let pem_public = format!(
        "-----BEGIN CUSTOM PUBLIC KEY-----\n{}\n-----END CUSTOM PUBLIC KEY-----\n",
        formatted_public_key
    );

    // Save to a file
    let mut file_private = File::create(private_key_path)?;
    file_private.write_all(pem_private.as_bytes())?;

    // Save to a file
    let mut file_public = File::create(public_key_path)?;
    file_public.write_all(pem_public.as_bytes())?;

    println!("Key file created in PEM format");
    Ok(())
}

fn encrypt(der_bytes: &[u8], message: &str, message_output_path: &PathBuf) {
    let asn_result = yasna::parse_der(der_bytes, |reader| {
        reader.read_sequence(|reader| {
            let p = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            let b = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            let g = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);

            Ok((p, b, g))
        })
    });

    // Handle the result
    match asn_result {
        Ok((p, b, g)) => {
            let (c1, c2) = encrypt_process(&p, &b, &g, &message);

            let ciphertext_der = yasna::construct_der(|writer| {
                writer.write_sequence(|writer| {
                    let c1_bytes = c1.to_bytes_be();
                    writer.next().write_bigint_bytes(&c1_bytes, true);
                    let c2_bytes = c2.to_bytes_be();
                    writer.next().write_bigint_bytes(&c2_bytes, true);
                });
            });

            // Encode in Base64
            let chipertext = STANDARD.encode(&ciphertext_der);

            // Save to a file
            let mut file_ciphertext = File::create(message_output_path).expect("Failed to create ciphertext file");
            file_ciphertext.write_all(chipertext.as_bytes()).expect("Failed to save ciphertext");

            println!("Ciphertext generated");
        }
        Err(e) => {
            eprintln!("ASN.1 parsing error: {}", e);
        }
    }
}

fn decrypt(der_bytes: &[u8], message_bytes: &[u8]) {
    let ciphertext_result = yasna::parse_der(message_bytes, |reader| {
        reader.read_sequence(|reader| {
            let c1 = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            let c2 = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            Ok((c1, c2))
        })
    });

    let key_result = yasna::parse_der(der_bytes, |reader| {
        reader.read_sequence(|reader| {
            let version = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            let p = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            let b = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            let x = BigUint::from_bytes_be(&reader.next().read_bigint_bytes()?.0);
            Ok((version, p, b, x))
        })
    });

    // Handle the result
    match ciphertext_result {
        Ok((c1, c2)) => {
            match key_result {
                Ok((_version, p, _b, x)) => {
                    let m = decrypt_process(&c1, &c2, &p, &x);
                    let recovered_bytes = m.to_bytes_be();
                    let recovered_str = String::from_utf8(recovered_bytes).expect("Invalid UTF-8");
                
                    println!("Message: {}", recovered_str);
                }
                Err(e) => {
                    eprintln!("ASN.1 parsing error: {}", e);
                }
            }
        }
        Err(e) => {
            eprintln!("ASN.1 parsing error: {}", e);
        }
    }
}

fn decrypt_process(c1: &BigUint, c2: &BigUint, p: &BigUint, x: &BigUint) -> BigUint {
    (c2.modpow(&x, p) + c1) % p
}

fn encrypt_process(p: &BigUint, b: &BigUint, g: &BigUint, message: &str) -> (BigUint, BigUint) {
    let bytes = message.as_bytes(); // Convert &str to &[u8]
    // Step 2: Convert bytes to BigUint
    let m = BigUint::from_bytes_be(bytes); // Convert to big integer
    // println!("M: {}", m);

    let mut rng = thread_rng();

    // let m: BigUint = rng.gen_biguint(1024);
    // println!("m = {}", m);

    // 1. Choose an odd y
    let mut y: BigUint = rng.gen_biguint(1024);
    if y.is_even() {
        y += BigUint::one(); // Make it odd
    }

    // FIX: Remove extra reference on p
    let c1 = (g.modpow(&y, p) + m) % p;
    let c2 = b.modpow(&y, p);

    (c1, c2)
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::GenerateKey {
            size,
            private_key_path,
            public_key_path,
        } => {
            let private_key_path_buf = PathBuf::from(private_key_path);
            let public_key_path_buf = PathBuf::from(public_key_path);
            let _ = generate_key_pair(*size, &private_key_path_buf, &public_key_path_buf);
        }
        Commands::Encrypt {
            text,
            public_key_path,
            message_output_path,
        } => {
            // Read the file
            let public_key_path_buf = PathBuf::from(public_key_path);
            let key_data = fs::read(public_key_path_buf)?;
            // Convert Vec<u8> to String
            let key_string = String::from_utf8_lossy(&key_data);
            // Extract the Base64-encoded data (removing header/footer)
            let base64_data: String = key_string
                .lines()
                .filter(|line| !line.starts_with("-----")) // Remove PEM header/footer
                .map(|line| line.to_string()) // Convert &str to String
                .collect::<Vec<String>>() // Collect as Vec<String>
                .join(""); // Join all lines into a single Base64 string
            // Decode the Base64 data to bytes
            let decoded_bytes = STANDARD.decode(base64_data)
                .expect("Failed to decode Base64");
            let message_output_path_buf = PathBuf::from(message_output_path);
            encrypt(&decoded_bytes, &text, &message_output_path_buf);
        }
        Commands::Decrypt {
            private_key_path,
            message_path,
        } => {
            // Read the file
            let private_key_path_buf = PathBuf::from(private_key_path);
            let key_data = fs::read(private_key_path_buf)?;
            let key_string = String::from_utf8_lossy(&key_data);
            let base64_data: String = key_string
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .map(|line| line.to_string())
                .collect::<Vec<String>>()
                .join("");
            let decoded_bytes = STANDARD.decode(base64_data)
                .expect("Failed to decode Base64");
        
            let ciphertext_key_path_buf = PathBuf::from(message_path);
            let ciphertext_data = fs::read(ciphertext_key_path_buf)?;
            let ciphertext_bytes = STANDARD.decode(ciphertext_data)
                .expect("Failed to decode Base64");
        
            decrypt(&decoded_bytes, &ciphertext_bytes);

        }
    }

    Ok(())
}

// Generate Key => ./target/release/xelgamal generate-key --size 4096 private.pem public.pem
// Encrypt => ./target/release/xelgamal encrypt "hello world" public.pem encrypted.txt
// Decrypt => ./target/release/xelgamal decrypt private.pem encrypted.txt