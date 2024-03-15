package sm4

import "github.com/Taoja/sm4/padding"

// SM4Context 结构体
// context sm4实例
type SM4Context struct {
	context *Sm4Cipher
}

// NewSM4 新建构造函数
func NewSM4(key []byte) *SM4Context {
	c := new(SM4Context)
	c.init(key)
	return c
}

// init 初始化sm4实例
func (this *SM4Context) init(key []byte) {
	this.context, _ = NewCipher(key)
}

// doEncrypt 加密封装
// origData []byte 明文字节组
func (this *SM4Context) DoEncrypt(origData []byte) []byte {
	origData = padding.PKCS7Padding(origData) // 使用PKCS7 对明文进行补位
	length := len(origData) // 获取补位后的长度
	enc := make([]byte, length) // 密文字节组，和明文组长度一致
	for i := 0; i < length; i += BlockSize { // 每16位循环
		sl := origData[i:i+BlockSize] // 取i - i+16 位字节
		this.context.Encrypt(enc[i:i+BlockSize], sl) // 加密，密文存入密文字节组对应位置
	}
	return enc
}

// doDecrypt 解密封装
// origData []byte 密文字节组
func (this *SM4Context)DoDecrypt(origData []byte) []byte {
	length := len(origData) // 获取长度
	dec := make([]byte, length) // 构建等长解密字节组
	for i := 0; i < length; i += BlockSize {
		sl := origData[i:i+BlockSize] //取i - i+16 位字节
		this.context.Decrypt(dec[i:i+BlockSize], sl) // 解密，明文存入解密字节组对应位置
	}
	return padding.PKCS7UnPadding(dec) // 返回解除补位后的字节组
}