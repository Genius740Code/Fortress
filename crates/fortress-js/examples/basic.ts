/**
 * Basic Fortress JavaScript/TypeScript example
 * 
 * This example demonstrates basic encryption and key management
 * using the Fortress JavaScript/TypeScript SDK.
 */

import { Fortress, Utils } from '../src/index';

async function basicExample(): Promise<void> {
  console.log('Fortress Basic Example');
  console.log('='.repeat(40));

  try {
    // Initialize Fortress
    const fortress = new Fortress();
    console.log(`Fortress version: ${fortress.version}`);

    // Check compatibility
    const compatibility = fortress.checkCompatibility();
    console.log(`Browser compatible: ${compatibility.isCompatible}`);
    if (!compatibility.isCompatible) {
      console.log('Compatibility issues:', compatibility.issues);
      return;
    }

    // List available algorithms
    const algorithms = fortress.listAlgorithms();
    console.log('Available algorithms:');
    for (const alg of algorithms) {
      console.log(`  - ${alg}`);
    }

    // Create encryption algorithm
    const algorithm = fortress.createAlgorithm('aegis256');
    console.log(`Using algorithm: ${algorithm.algorithmName}`);
    console.log(`Key size: ${algorithm.keySize} bytes`);
    console.log(`Nonce size: ${algorithm.nonceSize} bytes`);
    console.log(`Tag size: ${algorithm.tagSize} bytes`);

    // Generate key
    console.log('\nGenerating key...');
    const key = fortress.generateKey('aegis256');
    console.log(`Key generated: ${key.length} bytes`);

    // Test encryption and decryption
    const plaintext = new TextEncoder().encode('Hello, Fortress! This is a test message for encryption.');
    console.log(`\nOriginal message: ${new TextDecoder().decode(plaintext)}`);

    // Encrypt
    console.log('Encrypting...');
    const ciphertext = await algorithm.encrypt(plaintext, key);
    console.log(`Ciphertext length: ${ciphertext.length} bytes`);

    // Decrypt
    console.log('Decrypting...');
    const decrypted = await algorithm.decrypt(ciphertext, key);
    console.log(`Decrypted message: ${new TextDecoder().decode(decrypted)}`);

    // Verify
    if (plaintext.length === decrypted.length && 
        plaintext.every((byte, index) => byte === decrypted[index])) {
      console.log('Encryption/Decryption successful!');
    } else {
      console.log('Encryption/Decryption failed!');
    }

    // Demonstrate utility functions
    console.log('\n--- Utility Functions ---');
    const keyHex = Utils.bytesToHex(key);
    console.log(`Key as hex: ${keyHex.substring(0, 32)}...`);
    
    const keyFromHex = Utils.hexToBytes(keyHex);
    console.log(`Key from hex: ${keyFromHex.length} bytes`);

    const keyBase64 = Utils.bytesToBase64(key);
    console.log(`Key as base64: ${keyBase64.substring(0, 32)}...`);

    // Test with different algorithms
    console.log('\n--- Testing Multiple Algorithms ---');
    const testAlgorithms = ['chacha20poly1305', 'aes256gcm', 'xchacha20poly1305'];
    
    for (const algName of testAlgorithms) {
      try {
        const testAlgorithm = fortress.createAlgorithm(algName);
        const testKey = fortress.generateKey(algName);
        
        const testPlaintext = new TextEncoder().encode(`Test message for ${algName}`);
        const testCiphertext = await testAlgorithm.encrypt(testPlaintext, testKey);
        const testDecrypted = await testAlgorithm.decrypt(testCiphertext, testKey);
        
        const success = testPlaintext.length === testDecrypted.length && 
                     testPlaintext.every((byte, index) => byte === testDecrypted[index]);
        
        console.log(`${algName}: ${success ? 'PASS' : 'FAIL'}`);
      } catch (error) {
        console.log(`${algName}: FAIL (${error})`);
      }
    }

    // Performance benchmark
    console.log('\n--- Performance Benchmark ---');
    const benchmarkResult = await fortress.benchmarkEncryption('aegis256', 1024 * 1024, 100);
    console.log(`Algorithm: ${benchmarkResult.algorithm}`);
    console.log(`Data size: ${benchmarkResult.dataSize} bytes`);
    console.log(`Iterations: ${benchmarkResult.iterations}`);
    console.log(`Total time: ${benchmarkResult.totalTimeMs.toFixed(2)} ms`);
    console.log(`Throughput: ${benchmarkResult.throughputMbps.toFixed(2)} MB/s`);
    console.log(`Avg time per op: ${benchmarkResult.avgTimePerOpMs.toFixed(2)} ms`);

    // Test error handling
    console.log('\n--- Error Handling ---');
    try {
      // Try to decrypt with wrong key
      const wrongKey = fortress.generateKey('aegis256');
      await algorithm.decrypt(ciphertext, wrongKey);
      console.log('Should have failed with wrong key');
    } catch (error) {
      console.log('Correctly failed with wrong key');
      console.log(`Error: ${(error as Error).message}`);
    }

    try {
      // Try to decrypt corrupted data
      const corruptedCiphertext = new Uint8Array(ciphertext);
      corruptedCiphertext[0] ^= 0xFF; // Flip first byte
      await algorithm.decrypt(corruptedCiphertext, key);
      console.log('Should have failed with corrupted data');
    } catch (error) {
      console.log('Correctly failed with corrupted data');
      console.log(`Error: ${(error as Error).message}`);
    }

    console.log('\nBasic example completed successfully!');

  } catch (error) {
    console.error('Example failed:', error);
  }
}

// Run the example
basicExample().catch(console.error);
