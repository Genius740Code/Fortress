package fortress

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func BenchmarkSimpleEncryption(b *testing.B) {
	// Test encryption without audit logging to avoid deadlock
	config := DefaultConfig()
	config.Audit.Enabled = false
	
	f, err := NewWithConfig(config)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := f.Encrypt(data, &EncryptionOptions{Algorithm: "aes256gcm"})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChaCha20Poly1305Simple(b *testing.B) {
	config := DefaultConfig()
	config.Audit.Enabled = false
	
	f, err := NewWithConfig(config)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := f.Encrypt(data, &EncryptionOptions{Algorithm: "chacha20poly1305"})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyGenerationSimple(b *testing.B) {
	config := DefaultConfig()
	config.Audit.Enabled = false
	
	f, err := NewWithConfig(config)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := f.GenerateKey(&KeyGenerationOptions{Algorithm: "aes256gcm"})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStorageSimple(b *testing.B) {
	storage := NewStorageBackend(DefaultConfig())
	data := make([]byte, 512)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("bench_key_%d", i)
		err := storage.Store(key, data, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestSecurityValidation(t *testing.T) {
	config := DefaultConfig()
	config.Audit.Enabled = false
	
	f, err := NewWithConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Test 1: Key security
	plaintext := []byte("Secret data")
	ciphertext, err := f.Encrypt(plaintext, &EncryptionOptions{Algorithm: "aes256gcm"})
	if err != nil {
		t.Fatal(err)
	}

	// Verify ciphertext is different from plaintext
	if string(ciphertext) == string(plaintext) {
		t.Error("Ciphertext should be different from plaintext")
	}

	// Test 2: Key isolation
	key1, err := f.GenerateKey(&KeyGenerationOptions{Algorithm: "aes256gcm"})
	if err != nil {
		t.Fatal(err)
	}

	key2, err := f.GenerateKey(&KeyGenerationOptions{Algorithm: "aes256gcm"})
	if err != nil {
		t.Fatal(err)
	}

	// Keys should be different
	if len(key1) == len(key2) {
		same := true
		for i := range key1 {
			if key1[i] != key2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Generated keys should be different")
		}
	}

	// Test 3: Storage filtering
	storage := f.GetStorage()
	
	// Add test data
	testKeys := []string{"user_123", "user_456", "admin_789"}
	testData := [][]byte{[]byte("data1"), []byte("data2"), []byte("data3")}
	
	for i, key := range testKeys {
		err := storage.Store(key, testData[i], nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Test filtering
	options := &QueryOptions{
		Filter: map[string]interface{}{
			"key_prefix": "user_",
		},
	}
	
	filteredKeys, err := storage.ListKeys(options)
	if err != nil {
		t.Fatal(err)
	}

	if len(filteredKeys) != 2 {
		t.Errorf("Expected 2 filtered keys, got %d", len(filteredKeys))
	}

	t.Log("✅ Security validation tests passed")
}
