package util

import (
	"encoding/hex"

	"github.com/Taoja/sm4/sm4"
)

type ecb struct {
	b         *sm4.Sm4Cipher
	blockSize int
}

func newECB(b *sm4.Sm4Cipher) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

// newECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func newECBDecrypter(b *sm4.Sm4Cipher) *ecb {
	return (*ecb)(newECB(b))
}

func (x *ecb) BlockSize() int { return x.blockSize }

func (x *ecb) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func decrypt(data []byte, key []byte) (string, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(data))
	ecb := newECBDecrypter(block)
	ecb.CryptBlocks(ciphertext, data)

	unpaddedData := pkcs5Unpadding(ciphertext)

	return string(unpaddedData), nil
}

// PKCS5 去除填充
func pkcs5Unpadding(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func Decrypt(txt, key string) (string, error) {
	decodedTxt, err := hex.DecodeString(txt)
	if err != nil {
		return "", err
	}
	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}
	return decrypt(decodedTxt, decodedKey)
}
