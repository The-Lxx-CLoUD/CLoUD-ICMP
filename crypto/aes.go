##github = @The-Lxx-CLoUD
##telegram = @lxxcloud

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
)

const ivSize = 16

func CalcHmac(secretKey, expectedSign, data []byte) error {
	h := hmac.New(sha256.New, secretKey)
	h.Write(data)
	newSign := h.Sum(nil)
	if !hmac.Equal(newSign, expectedSign) {
		return fmt.Errorf("Invalid signature \n")
	}
	return nil
}

func DeriveKey(userKey []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write(userKey)
	hash.Write([]byte("aes256-icrevbit-salt-key"))
	key := hash.Sum(nil)
	return key, nil
}

func EncryptData(key, iv, plaintext []byte) ([]byte, []byte, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("invalid key length: must be 32 bytes, got %d", len(key))
	}

	padded := pad(plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}
	if iv == nil {
		iv = make([]byte, ivSize)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, nil, fmt.Errorf("failed to generate IV: %v", err)
		}
	}

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	return ciphertext, iv, nil
}

func DecryptData(key, iv, ciphertext []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: must be 32 bytes, got %d", len(key))
	}
	if len(iv) != ivSize {
		return nil, fmt.Errorf("invalid IV length: must be %d bytes, got %d", ivSize, len(iv))
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of block size")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := unpad(plaintext)
	if err != nil {
		return nil, fmt.Errorf("unpadding failed: %v", err)
	}

	return unpadded, nil
}

func pad(data []byte) []byte {
	blockSize := aes.BlockSize
	paddingLen := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+paddingLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(paddingLen)
	}
	return padded
}

func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid padded data length")
	}
	paddingLen := int(data[len(data)-1])
	if paddingLen == 0 || paddingLen > aes.BlockSize {
		return nil, fmt.Errorf("invalid padding length: %d", paddingLen)
	}
	for i := len(data) - paddingLen; i < len(data); i++ {
		if data[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding bytes")
		}
	}
	return data[:len(data)-paddingLen], nil
}
