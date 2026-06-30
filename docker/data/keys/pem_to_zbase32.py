#!/usr/bin/env python3
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization
import z_base_32

def main():
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <path_to_private_key.pem>", file=sys.stderr)
        sys.exit(1)

    pem_path = Path(sys.argv[1])
    if not pem_path.is_file():
        print(f"Error: File '{pem_path}' not found.", file=sys.stderr)
        sys.exit(1)

    try:
        # Load the private key using Python's standard cryptography engine
        private_key = serialization.load_pem_private_key(
            pem_path.read_bytes(),
            password=None  # Change this if your PEM file is password protected
        )

        # Safely extract the public key object
        public_key = private_key.public_key()

        # Extract the pure, raw 32-byte representation (No ASN.1 / No Metadata wrappers)
        raw_public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Use the audited library to safely encode the exact bytes into z-base-32
        zbase32_string = z_base_32.encode(raw_public_bytes)
        print(zbase32_string)

    except ValueError:
        print("Error: The file provided is not a valid or unencrypted PEM key.", file=sys.stderr)
        sys.exit(1)
    except TypeError:
        print("Error: This key type is not supported or requires a passphrase.", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
