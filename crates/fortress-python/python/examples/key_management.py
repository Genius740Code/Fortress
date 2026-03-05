#!/usr/bin/env python3
"""
Key management example using Fortress Python SDK
"""

import asyncio
import fortress

async def main():
    print("🔑 Fortress Key Management Example")
    print("=" * 40)
    
    # Create key manager
    key_manager = fortress.KeyManager()
    print("Key manager created")
    print()
    
    # Generate keys with different algorithms
    algorithms = ["aegis256", "chacha20poly1305", "aes256gcm"]
    key_ids = []
    
    for algorithm in algorithms:
        print(f"Generating {algorithm} key...")
        
        # Create metadata
        metadata = {
            "algorithm": algorithm,
            "created_at": "2026-01-01T00:00:00Z",
            "purpose": "data-encryption",
            "tags": [algorithm, "example"]
        }
        
        # Generate key
        key_id = await key_manager.generate_key(algorithm, metadata)
        key_ids.append(key_id)
        print(f"  Key ID: {key_id}")
    
    print()
    print(f"Generated {len(key_ids)} keys")
    print()
    
    # List all keys
    print("Listing all keys...")
    all_keys = await key_manager.list_keys()
    print(f"Total keys: {len(all_keys)}")
    for key_id in all_keys:
        print(f"  - {key_id}")
    print()
    
    # Retrieve and test a key
    test_key_id = key_ids[0]
    print(f"Retrieving key: {test_key_id}")
    key_data = await key_manager.get_key(test_key_id)
    print(f"Key data length: {len(key_data)} bytes")
    print()
    
    # Test encryption with retrieved key
    algorithm = fortress.EncryptionAlgorithm.aegis256()
    plaintext = b"Test message with retrieved key"
    ciphertext = await algorithm.encrypt(plaintext, key_data)
    decrypted = await algorithm.decrypt(ciphertext, key_data)
    
    print(f"Original: {plaintext.decode()}")
    print(f"Decrypted: {decrypted.decode()}")
    print(f"Match: {plaintext == decrypted}")
    print()
    
    # Rotate a key
    print(f"Rotating key: {test_key_id}")
    new_key_id = await key_manager.rotate_key(test_key_id)
    print(f"New key ID: {new_key_id}")
    print()
    
    # Verify old key is still accessible (for compatibility)
    old_key_data = await key_manager.get_key(test_key_id)
    print(f"Old key still accessible: {len(old_key_data)} bytes")
    
    # Clean up
    print("Cleaning up keys...")
    for key_id in key_ids:
        await key_manager.delete_key(key_id)
        print(f"  Deleted: {key_id}")
    
    print()
    print("🎉 Key management example completed!")

if __name__ == "__main__":
    asyncio.run(main())
