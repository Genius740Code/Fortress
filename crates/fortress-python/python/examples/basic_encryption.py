#!/usr/bin/env python3
"""
Basic encryption example using Fortress Python SDK
"""

import asyncio
import fortress

async def main():
    print("🔐 Fortress Basic Encryption Example")
    print("=" * 40)
    
    # Get version information
    print(f"Fortress version: {fortress.get_version()}")
    build_info = fortress.get_build_info()
    print(f"Build timestamp: {build_info['timestamp']}")
    print(f"Git SHA: {build_info['git_sha']}")
    print()
    
    # List available algorithms
    algorithms = fortress.list_algorithms()
    print("Available algorithms:")
    for alg in algorithms:
        print(f"  - {alg}")
    print()
    
    # Create encryption algorithm
    algorithm = fortress.EncryptionAlgorithm.aegis256()
    print(f"Using algorithm: {algorithm.algorithm_name()}")
    print(f"Key size: {algorithm.key_size()} bytes")
    print(f"Nonce size: {algorithm.nonce_size()} bytes")
    print(f"Tag size: {algorithm.tag_size()} bytes")
    print()
    
    # Generate key
    print("Generating key...")
    key = fortress.generate_key("aegis256")
    print(f"Key generated: {len(key)} bytes")
    print()
    
    # Test encryption and decryption
    plaintext = b"Hello, Fortress! This is a test message for encryption."
    print(f"Original message: {plaintext.decode()}")
    
    # Encrypt
    print("Encrypting...")
    ciphertext = await algorithm.encrypt(plaintext, key)
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    print()
    
    # Decrypt
    print("Decrypting...")
    decrypted = await algorithm.decrypt(ciphertext, key)
    print(f"Decrypted message: {decrypted.decode()}")
    print()
    
    # Verify
    if plaintext == decrypted:
        print("✅ Encryption/Decryption successful!")
    else:
        print("❌ Encryption/Decryption failed!")
    
    print()
    print("🎉 Example completed successfully!")

if __name__ == "__main__":
    asyncio.run(main())
