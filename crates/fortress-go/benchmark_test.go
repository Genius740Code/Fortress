package fortress

import (
	"crypto/rand"
	"fmt"
	"testing"
)

func BenchmarkEncryption(b *testing.B) {
	f, err := New()
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

func BenchmarkChaCha20Poly1305(b *testing.B) {
	f, err := New()
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

func BenchmarkAegis256(b *testing.B) {
	f, err := New()
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := f.Encrypt(data, &EncryptionOptions{Algorithm: "aegis256"})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	f, err := New()
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

func BenchmarkStorageOperations(b *testing.B) {
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

func BenchmarkConcurrentEncryption(b *testing.B) {
	f, err := New()
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	data := make([]byte, 1024)
	rand.Read(data)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := f.Encrypt(data, &EncryptionOptions{Algorithm: "aes256gcm"})
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// Test basic functionality to ensure everything works
func TestBasicFunctionality(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Test encryption/decryption
	plaintext := []byte("Hello, Fortress!")
	_, err = f.Encrypt(plaintext, &EncryptionOptions{Algorithm: "aes256gcm"})
	if err != nil {
		t.Fatal(err)
	}

	// Test key management
	keyID, err := f.ImportKey([]byte("test_key_123456789012345678901234"), "aes256gcm")
	if err != nil {
		t.Fatal(err)
	}

	exportedKey, err := f.ExportKey(keyID)
	if err != nil {
		t.Fatal(err)
	}

	if len(exportedKey) < 32 {
		t.Errorf("Expected key length at least 32, got %d", len(exportedKey))
	}

	// Test storage
	storage := f.GetStorage()
	err = storage.Store("test_key", []byte("test_value"), nil)
	if err != nil {
		t.Fatal(err)
	}

	retrieved, err := storage.Retrieve("test_key")
	if err != nil {
		t.Fatal(err)
	}

	if string(retrieved) != "test_value" {
		t.Errorf("Expected 'test_value', got '%s'", string(retrieved))
	}

	t.Log("✅ All basic functionality tests passed")
}
