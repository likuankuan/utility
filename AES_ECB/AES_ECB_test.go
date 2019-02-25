package AES_ECB

import (
	"testing"
)

func TestEcbEncrypt(t *testing.T) {
	data := []byte("likuankuan")
	key := "1234567890123456"

	want := []byte{252, 7, 239, 110, 34, 210, 61, 46, 38, 38, 112, 245, 208, 160, 34, 59}
	cipherText, err := EcbEncrypt(data, key)
	if err != nil {
		t.Fatal(err)
	}
	for i, v := range cipherText {
		if want[i] != v {
			t.Errorf("cipherText[%q] == %q, want %q", i, v, want[i])
		}
	}
}

func TestEcbDecrypt(t *testing.T) {
	cipherText := []byte{252, 7, 239, 110, 34, 210, 61, 46, 38, 38, 112, 245, 208, 160, 34, 59}
	key := "1234567890123456"

	want := "likuankuan"

	plaintext, err := EcbDecrypt(cipherText, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != want {
		t.Errorf("plaintext == %q, want %q", string(plaintext), want)
	}

}
