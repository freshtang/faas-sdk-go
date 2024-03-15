package padding

import (
	"bytes"
)

const BlockSize = 16

// PKCS7Padding
/**
 * @params cipherText 需要补位的字节码，长度需要小于等于15
 */
func PKCS7Padding(ciphertext []byte) []byte {
	len := len(ciphertext) // 获取长度
	padding := BlockSize - len%BlockSize // 计算补位值， 16 - 长度%16
	paddingText := bytes.Repeat([]byte{byte(padding)}, padding) // 补全成16位
	return append(ciphertext, paddingText...)
}

// PKCS7UnPadding 放出数据
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}