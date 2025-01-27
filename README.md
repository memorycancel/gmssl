![](GMSSL.png)

`gmssl` 是GmSSL密码库 [`https://github.com/guanzhi/GmSSL`](https://github.com/guanzhi/GmSSL) 的Ruby语言封装。
依赖ruby的[`ffi`](https://github.com/ffi/ffi/wiki/Core-Concepts)实现。

## 安装

```shell
gem install gmssl
```

## 使用

```ruby
require 'gmssl'

GmSSL::Version.info #=> VERSION: 30102, GmSSL 3.1.2 Dev
```

## 示例

在调用的代码块内 include GmSSL, 调用函数时可以省略前缀,例如:

```ruby
require 'gmssl'

include GmSSL
Version.info #=> VERSION: 30102, GmSSL 3.1.2 Dev
```

等价于:
```ruby
require 'gmssl'
GmSSL::Version.info #=> VERSION: 30102, GmSSL 3.1.2 Dev
```

以下示例默认`include GmSSL`,省略前缀`GmSSL::`:

### random 随机数生成器
random实现随机数生成功能，通过rand_bytes方法生成的是具备密码安全性的随机数，可以用于密钥、IV或者其他随机数生成器的`随机种子`。

```ruby
Random.bytes(16) #=> 11260c5695a59cd50d5b4a174544166f
```

### sm3 哈希
SM3密码杂凑函数可以将`任意长度`的输入数据计算为固定32字节长度的哈希值。

```ruby
SM3.digest('abc')
#=> 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

### sm3_hmac 消息认证码

HMAC-SM3是基于SM3密码杂凑算法的消息认证码(MAC)算法，消息认证码算法可以看作带密钥的哈希函数，主要用于`保护消息不受篡改`。通信双方需要事先协商出一个密钥，比如32字节的随机字节序列，数据的发送方用这个密钥对消息计算MAC值，并且把MAC值附在消息后面。消息的接收方在收到消息后，用相同的密钥计算消息的MAC值，并且和发送消息附带的MAC值做对比，如果一致说明消息没有被篡改，如果不一致，说明消息被篡改了。

```ruby
SM3.hmac("54A38E3B599E48C4F581FEC14B62EA29", "abc")
#=>130eb2c6bc1e22cb1d7177089c59527e09aaa96a08fbaccf05c86dac034615b8
```

### sm3_pbkdf2 基于SM3的口令密钥导出函数

常用软件如Word、PDF、WinRAR等支持基于口令的文件加密，字符串形式的口令相对于随机的密钥字节序列`对用户来说更容易记忆和输入，对用户更加友好`。但是由于口令中存在的信息熵远低于随机的二进制密钥，直接将口令字符串作为密钥，甚至无法抵御来自个人计算机的暴力破解攻击。一种典型的错误用法是直接用哈希函数计算口令的哈希值，将看起来随机的哈希值作为密钥使用。但是由于口令的空间相对较小，攻击者仍然可以尝试所有可能口令的哈希值，对于暴力破解来说，破解口令的哈希值和原始口令，在攻击难度上没有太大差别。

安全和规范的做法是采用一个基于口令的密钥导出函数(Password-Based Key Derivation Function, PBKDF)从口令中导出密钥。通过PBKDF导出密钥并不会降低攻击者在暴力破解时尝试的口令数量，但是可以防止攻击者通过查预计算表的方式来加速破解，并且可以大大增加攻击者尝试每一个可能口令的计算时间。PBKDF2是安全的并且使用广泛的PBKDF算法标准之一，算法采用哈希函数作为将口令映射为密钥的主要部件，通过加入随机并且公开的盐值(Salt)来抵御预计算，通过增加多轮的循环计算来增加在线破解的难度，并且支持可变的导出密钥长度。

```ruby
psswd = "P@ssw0rd"
hex_salt = "667D1BD0262E24E8"
iterations = 10000
outlen = 16 # Desired length of the output key
SM3.pbkdf2(psswd, hex_salt, iterations, outlen)
#=> dd4fd234a828135264c7c89c13b7e1b3
```

### sm4 分组密码

SM4算法是分组密码算法，其密钥长度为128比特（16字节），分组长度为128比特（16字节）。SM4算法每次只能加密或者解密一个固定16字节长度的分组，不支持加解密任意长度的消息。分组密码通常作为更高层密码方案的一个组成部分，不适合普通上层应用调用。如果应用需要保护数据和消息，那么应该优先选择采用SM4-GCM模式，或者为了兼容已有的系统，也可以使用SM4-CBC或SM4-CTR模式。
多次调用Sm4的分组加密解密功能可以实现ECB模式，由于ECB模式在消息加密应用场景中并不安全，因此GmSSL中没有提供ECB模式。如果应用需要开发SM4的其他加密模式，也可基于SM4来开发这些模式。

### sm4_cbc 加密模式

CBC模式是应用最广泛的分组密码加密模式之一，虽然目前不建议在新的应用中继续使用CBC默认，为了`保证兼容性`，应用仍然可能需要使用CBC模式。

```ruby
key = "117B5119CDFDD46288DAF9064414D801"  # 16 bytes key
iv = "5428F71057DD4AD68C34E38BEA700309"   # 16 bytes IV
plaintext = "Hello, sm4_cbc!"

SM4.cbc_encrypt(key, iv, plaintext)
#=> 4b6f370c339fc510c19a1a3f78460725

SM4.cbc_decrypt(key, iv, "4b6f370c339fc510c19a1a3f78460725")
#=> Hello, sm4_cbc!
```

### sm4_ctr 加密模式

CTR加密模式可以加密任意长度的消息，和CBC模式不同，并不需要采用填充方案，因此SM4-CTR加密输出的密文长度和输入的明文`等长`。对于`存储或传输带宽有限的应用场景`，SM4-CTR相对SM4-CBC模式，密文`不会增加格外长度`。

```ruby
key_hex = "54A38E3B599E48C4F581FEC14B62EA29"
ctr_hex = "00000000000000000000000000000000"
SM4.ctr_encrypt("abc", key_hex, ctr_hex)
#=> 80297a
encrypted_string2 = SM4.ctr_encrypt("abcd", key_hex, ctr_hex)
#=> 80297a18
# 输出为16位字符串,转化为bytes长度除以2,因为每2个十六进制数表示1个byte
```

### sm4_gcm 认证加密模式

SM4的GCM模式是一种认证加密模式，和CBC、CTR等加密模式的主要区别在于，GCM模式的加密过程默认在密文最后添加完整性标签，也就是MAC标签，因此应用在采用SM4-GCM模式时，没有必要再计算并添加SM3-HMAC了。在有的应用场景中，比如对消息报文进行加密，对于消息头部的一段数据（报头字段）只需要做完整性保护，不需要加密，SM4-GCM支持这种场景。在Sm4Gcm类的init方法中，除了key、iv参数，还可以提供aad字节数字用于提供不需要加密的消息头部数据。

```ruby
key = "B789047EE36BD1DB9BCCD5B84D0E8C8D"  # 16 bytes key
iv = "F0F83C02897BE824AAB58361"           # 12 bytes IV
aad = "The_AAD_Data"
input = "hello_sm4_gcm"
encrypted_output, tag = SM4.gcm_encrypt(key, iv, aad, input)
SM4.gcm_decrypt(key, iv, aad, encrypted_output, tag)
#=> hello_sm4_gcm
```

### 祖冲之序列密码

祖冲之密码算法(ZU Cipher, ZUC)是一种序列密码，密钥和IV长度均为16字节。作为序列密码ZUC可以加密可变长度的输入数据，并且输出的密文数据长度和输入数据等长，因此适合不允许密文膨胀的应用场景。在国密算法体系中，ZUC算法的设计晚于SM4，在32位通用处理器上通常比SM4-CBC明显要快。

在安全性方面，不建议在一组密钥和IV的情况下用ZUC算法加密大量的数据（比如GB级或TB级），避免序列密码超长输出时安全性降低。另外ZUC算法本身并不支持数据的完整性保护，因此在采用ZUC算法加密应用数据时，应考虑配合HMAC-SM3提供完整性保护。

```ruby
key = "117B5119CDFDD46288DAF9064414D801"  # 16 bytes key
iv = "5428F71057DD4AD68C34E38BEA700309"   # 16 bytes IV
input = "zuc"
ZUC.encrypt(key, iv, input)
#=> c4fee6
ZUC.decrypt(key, iv, "c4fee6")
#=> zuc
```
## LICENSE

本项目采用`MIT`协议。

## TODO

+ 目前支持 linux MacOS(darwin)✅,~~Windows~~❌
+ 目前支持 SM2、SM3、SM4、ZUC✅ ~~SM9~~❌
+ 与Rails加密模块集成❌
