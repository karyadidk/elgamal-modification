# x-elgamal

## Prerequisites
Ensure you have Rust and Cargo installed on your system before proceeding.

### macOS
```sh
# Install Rust and Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Reload shell configuration
source $HOME/.cargo/env
```

### Windows
```powershell
# Install Rust and Cargo using rustup
Invoke-WebRequest -Uri https://sh.rustup.rs -OutFile rustup-init.exe
./rustup-init.exe -y

# Restart your terminal after installation
```

### Linux
```sh
# Install Rust and Cargo
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Reload shell configuration
source $HOME/.cargo/env
```

## Clone the Project
```sh
git clone https://github.com/karyadidk/elgamal-modification.git
cd elgamal-modification
```

## Build the Project
```sh
cargo build --release
```

## Run the Project

### Generate Key
```sh
./target/release/xelgamal generate-key --size 4096 private.pem public.pem
```

### Encrypt
```sh
./target/release/xelgamal encrypt "hello world" public.pem encrypted.txt
```

### Decrypt
```sh
./target/release/xelgamal decrypt private.pem encrypted.txt
```

## Additional Notes
- Ensure `git` is installed before cloning the project.
- If using Windows, run the commands in PowerShell or Command Prompt.
- To update Rust, run:
  ```sh
  rustup update
  

