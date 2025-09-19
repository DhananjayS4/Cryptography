import oqs

# Choose algorithm: "falcon-512" or "falcon-1024"
alg = "falcon-1024"

with oqs.Signature(alg) as signer:
    print("Using algorithm:", signer.details["name"])

    # Generate keypair
    public_key = signer.generate_keypair()
    print("Public key length:", len(public_key))

    # Sign a message
    message = b"Hello from Falcon in WSL2!"
    signature = signer.sign(message)
    print("Signature length:", len(signature))

    # Verify
    with oqs.Signature(alg) as verifier:
        valid = signer.verify(message, signature, signer.export_public_key())
        print("Signature valid?", valid)
