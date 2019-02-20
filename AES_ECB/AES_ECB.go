package AES_ECB

import (
	"bytes"
	"crypto/aes"
	"github.com/pkg/errors"
	"strings"
)

//加密
func EcbEncrypt(plaintext []byte, key string) ([]byte, error) {
	if len(key) != aes.BlockSize {
		return nil, errors.New("The key is not equal to 16")
	}
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	EcbPlaintext := EcbPad(plaintext)

	EcbCipherText := make([]byte, 0)
	text := make([]byte, 16)
	for len(EcbPlaintext) > 0 {
		cipher.Encrypt(text, EcbPlaintext)
		EcbPlaintext = EcbPlaintext[aes.BlockSize:]
		EcbCipherText = append(EcbCipherText, text...)
	}
	return EcbCipherText, nil
}

// 解密
func EcbDecrypt(cipherText []byte, key string) ([]byte, error) {
	if len(key) != aes.BlockSize {
		return nil, errors.New("The key is not equal to 16")
	}
	cipher, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	if len(cipherText)%aes.BlockSize != 0 {
		return nil, errors.New("Need a multiple of the block size 16")
	}
	plaintext := make([]byte, 0)
	text := make([]byte, 16)
	for len(cipherText) > 0 {
		cipher.Decrypt(text, cipherText)
		cipherText = cipherText[aes.BlockSize:]
		plaintext = append(plaintext, text...)
	}
	EcbPlaintext := EcbRemover(plaintext)
	return EcbPlaintext, nil
}

// 补全
// 补空格
func EcbPad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(0x20)}, padding)
	return append(data, padText...)
}

//去除空格
func EcbRemover(data []byte) []byte {
	s := strings.TrimSpace(string(data))
	return []byte(s)
}
