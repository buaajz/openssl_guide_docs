# README

本文档总结openssl的基本操作：

1. 基于openssl的非对称密钥及证书生成，并提供证书格式转换的参考方法。
2. 对称加密aes算法演示

## openssl AES算法

AES - 高级加密标准（英语：Advanced Encryption Standard，缩写：AES），在密码学中又称Rijndael加密法，是美国联邦政府采用的一种区块加密标准。这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用。经过五年的甄选流程，高级加密标准由美国国家标准与技术研究院（NIST）于2001年11月26日发布于FIPS PUB 197，并在2002年5月26日成为有效的标准。2006年，高级加密标准已然成为对称密钥加密中最流行的算法之一。

### AES128、AES192、AES256区别

| **AES** | 密钥长度（字节) | 分组长度(字节) | 加密轮数 |
| ------- | --------------- | -------------- | -------- |
| AES-128 | 16              | 16             | 10       |
| AES-192 | 24              | 16             | 12       |
| AES-256 | 32              | 16             | 14       |


AES加密数据块分组长度必须为128比特，密钥长度可以是128比特、192比特、256比特中的任意一个。
AES128性能最好，AES256安全性最高。

### Block Cipher(块密码加密/分组密码加密方式)

分组密码有五种工作体制：1.电码本模式（Electronic Codebook Book (ECB)）；2.密码分组链接模式（Cipher Block Chaining (CBC)）；3.计算器模式（Counter (CTR)）；4.密码反馈模式（Cipher FeedBack (CFB)）；5.输出反馈模式（Output FeedBack (OFB)）。

### 密钥生成及加密/解密

以aes-128-cbc为例做说明：

```bash
openssl rand -hex 32 # 密钥生成
openssl enc -aes-128-cbc -in software_origin.swu -out software.swu -K xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -iv xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
openssl aes-128-cbc -d -in software.swu -out software_dec.swu -K xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx -iv xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

## openssl RSA算法

RSA算法是最著名和可靠的非对称密钥加密算法。由三位开发之Ron Rivest、Adi Shamir、Leonard Adleman姓氏的首字母组成。
利用对大整数的质因数分解及其困难保证安全性。

### RSA key生成

```bash
openssl genrsa -out rsa_key.pem 2048
openssl rsa -pubout -in rsa_key.pem -out rsa_key_pub.pem
```

### 使用rsautl加密/解密

公钥加密文件

```bash
openssl rsautl -encrypt -in input.file -inkey pubkey.pem -pubin -out output.file
    -in 指定被加密的文件
    -inkey 指定加密公钥文件
    -pubin 表面是用纯公钥文件加密
    -out 指定加密后的文件
```
私钥解密文件

```bash
openssl rsautl -decrypt -in input.file -inkey key.pem -out output.file
    -in 指定需要解密的文件
    -inkey 指定私钥文件
    -out 指定解密后的文件
```

### 使用rsautl签名/验签

```bash
root_hash=$(openssl rand -hex 32)

# 使用私钥签名后，进行bash64编码
sig_base64=$(echo "$root_hash"| openssl rsautl -sign -inkey private.pem | openssl enc -base64 -A)

root_hash_with_sig="$root_hash$sig_base64"

echo "$root_hash_with_sig"

root_hash_1=${root_hash_with_sig:0:64}

sig_base64_1=${root_hash_with_sig:64}

# bash64解码后，使用公钥验签
root_hash=$(echo "$sig_base64_1"| openssl enc -base64 -d |openssl rsautl -verify -inkey public.pem -pubin)

if [ "$root_hash_1" == "$root_hash" ] ;then
        echo "succeed"
else
        echo "failed"
fi
```

**也可以使用dgst签名/验签**

```bash
openssl dgst -sign rsa_key.pem -sha256 file.txt -out sign
openssl dgst -verify rsa_key_pub.pem -sha256 -signature sign file.txt
```

### 查看rsa公私钥及CSR

查看私钥KEY的办法:

```
openssl rsa -in mykey.key -text -noout
```

如果是DER格式的话,同理应该这样了:

```
openssl rsa -in mykey.key -text -noout -inform der
```

查看RSA公钥方法

```
openssl rsa -noout -text -pubin -in ca.pub
```

RSA公钥PEM转DER

```
openssl rsa -pubin -in ca.pub -inform pem -outform der -out ca_pub.der
```

查看DER公钥

```
openssl rsa -pubin -inform der -in ca_pub.der -text -noout
```

CSR - Certificate Signing Request,即证书签名请求,这个并不是证书,而是向权威证书颁发机构获得签名证书的申请,其核心内容是一个公钥(当然还附带了一些别的信息),在生成这个申请的时候,同时也会生成一个私钥,私钥要自己保管好.做过iOS APP的朋友都应该知道是怎么向苹果申请开发者证书的吧.
查看的办法:

```
openssl req -noout -text -in my.csr
```

(如果是DER格式的话照旧加上-inform der,这里不写了)

### RSA公钥证书

#### CA根证书的生成步骤（RSA）

生成CA私钥（.key）–>生成CA证书请求（.csr）–>自签名得到根证书（.crt）（CA给自已颁发的证书）。

```bash
# Generate CA private key (制作ca.key 私钥)
openssl genrsa -out ca.key 2048

# Generate CSR
openssl req -new -key ca.key -out ca.csr

#OpenSSL创建的自签名证书在chrome端无法信任，需要添加如下
echo "subjectAltName=DNS:rojao.test.com,IP:10.10.2.137" > cert_extensions

# Generate Self Signed certificate（CA 根证书）
openssl x509 -req -days 365 -in ca.csr -signkey ca.key -extfile cert_extensions -out ca.crt
```

#### 用户证书的生成步骤（RSA）

生成私钥（.key）–>生成证书请求（.csr）–>用CA根证书签名得到证书（.crt）

```bash
# private key
openssl genrsa -des3 -out server.key 2048

# generate csr
openssl req -new -key server.key -out server.csr

#OpenSSL创建的自签名证书在chrome端无法信任，需要添加如下
echo "subjectAltName=DNS:rojao.test.com,IP:10.10.2.137" > cert_extensions

# generate certificate
openssl ca -in server.csr -out server.crt  -extfile cert_extensions -cert ca.crt -keyfile ca.key
```

#### 查看x509证书

如果ca.crt文件的内容以-----BEGIN开头，您以在文本编辑器中阅读.
该文件使用base64，它是ASCII可读的，而不是二进制格式。证书已采用PEM格式。只需将扩展名更改为.pem即可。

```
openssl x509 -in root_CA_pem_filename -text -noout
```

## openssl ECC算法

查看OpenSSL 内建的椭圆曲线

```
openssl ecparam -list_curves
```

### 生成EC私钥

```
openssl ecparam -genkey -name prime256v1 -param_enc explicit -outform pem -out ec_prikey.pem
```

### 对私钥进行口令保护

```
openssl ec -in ec_prikey.pem -des -out ec_prikey.pem
openssl ec -in ec_prikey.pem -des -passout pass:"123456" -out ec_prikey.pem
```

### 从私钥提取公钥

```
openssl ec -in ec_prikey.pem -pubout -out ec_pubkey.pem
```

### 查看私钥信息

```
openssl ec -in ec_prikey.pem -passin pass:"123456" -text
```

### 查看公钥信息

```
openssl ec -in ec_pubkey.pem -pubin -text
```

### pem为der

```
openssl ec -in ec_prikey.pem -outform der -out ec_prikey.der
```

### ECC公钥PEM转DER

```
openssl ec -pubin -in ca.pub -inform pem -outform der -out ca_pub.der
```

### 查看DER公钥

```
openssl ec -pubin -inform der -in ca_pub.der -text -noout
```
### 根证书生成

```bash
# 生成根CA私钥
openssl ecparam -out EccRootCA.key -name prime256v1 -genkey

# 生成证书CSR请求
openssl req \
-subj "/C=CN/ST=Shenzhen/L=Guangdong/O=Test Ltd/OU=Software Department/CN=root.test.com/emailAddress=root@test.com" \
-new \
-key EccRootCA.key \
-out EccRootCA.csr

# 用根私钥签名CSR请求，生成自签名公钥证书
openssl x509 \
-req \
-days 365 \
-in EccRootCA.csr \
-signkey EccRootCA.key \
-sha256 \
-extfile openssl.cnf -extensions v3_ca \
-out EccRootCA.crt
```

### 生成二级证书

生成ECC 次级CA密钥对，用根CA签发次级CA证书。注意CSR请求中的CN（Common Name）不能与给它签发证书的CA的一样。

```bash
# 生成次级CA ECC密钥对
openssl ecparam -out Ecc2ndCA.key -name prime256v1 -genkey

# 生成证书CSR请求
openssl req \
-subj "/C=CN/ST=Shenzhen/L=Guangdong/O=Test Ltd/OU=Software Department/CN=2nd.test.com/emailAddress=2nd@test.com" \
-new \
-key Ecc2ndCA.key \
-out Ecc2ndCA.csr

# 用上述根证书签发次级CA证书
openssl x509 \
-req \
-days 365 \
-in Ecc2ndCA.csr \
-CA EccRootCA.crt \
-CAkey EccRootCA.key \
-sha256 \
-CAcreateserial \
-extfile openssl.cnf -extensions v3_ca \
-out Ecc2ndCA.crt
```

### 生成三级证书

```bash
# 生成示例ECC密钥对
openssl ecparam -out EccTest.key -name prime256v1 -genkey

# 生成CSR
openssl req \
-subj "/C=CN/ST=Shenzhen/L=Guangdong/O=Test Ltd/OU=Software Department/CN=instance.test.com/emailAddress=instance@test.com" \
-new \
-key EccTest.key \
-config openssl.cnf -extensions v3_req \
-out EccTest.csr

# 用次级CA为示例公钥签发证书，注意这里的扩展使用的是v3_req而不是v3_ca
openssl x509 \
-req \
-days 365 \
-in EccTest.csr \
-CA Ecc2ndCA.crt \
-CAkey Ecc2ndCA.key \
-sha256 \
-set_serial 03 \
-extfile openssl.cnf -extensions v3_req \
-out EccTest.crt
```

## openssl证书生成

### 证书文件类型及协议

证书主要的文件类型和协议有: PEM、DER、PFX、JKS、KDB、CER、KEY、CSR、CRT、CRL 、OCSP、SCEP等。

#### X.509

X.509 - 这是一种证书标准,主要定义了证书中应该包含哪些内容.其详情可以参考[RFC5280](https://www.rfc-editor.org/rfc/rfc5280),SSL使用的就是这种证书标准。
x509证书一般会用到三类文件，key，csr，crt。

- key是私用密钥，openssl格式，通常是rsa算法。
- csr是证书请求文件，用于申请证书。在制作csr文件的时候，必须使用自己的私钥来签署申请，还可以设定一个密钥。
- crt是CA认证后的证书文件，签署人用自己的key给你签署的凭证。

### 证书编码格式

1. PEM - Openssl使用 PEM(Privacy Enhanced Mail)格式来存放各种信息,它是 openssl 默认采用的信息存放方式。Openssl 中的 PEM 文件一般包含如下信息:
内容类型:表明本文件存放的是什么信息内容,它的形式为“——-BEGIN XXXX ——”,与结尾的“——END XXXX——”对应。
头信息:表明数据是如果被处理后存放,openssl 中用的最多的是加密信息,比如加密算法以及初始化向量 iv。
信息体:为 BASE64 编码的数据。可以包括所有私钥（RSA 和 DSA）、公钥（RSA 和 DSA）和 (x509) 证书。它存储用 Base64 编码的 DER 格式数据，用 ascii 报头包围，因此适合系统之间的文本模式传输。

Apache和NGINX服务器偏向于使用这种编码格式。

```bash
openssl x509 -in certificate.pem -text -noout
```

2. DER – Distinguished Encoding Rules,辨别编码规则 (DER) 可包含所有私钥、公钥和证书。它是大多数浏览器的缺省格式，并按 ASN1 DER 格式存储。它是无报头的。打开看是二进制格式,不可读。
PEM 是用文本报头包围的 DER。

#### asn1parse

1. ASN.1:
ASN.1（Abstract Syntax Notation One) 是一套标准，是描述数据的表示、编码、传输、解码的灵活的记法。它提供了一套正式、无歧义和精确的规则以描述独立于特定计算机硬件的对象结构。
ASN.1有多种不同的编码实现，BER，CER，DER等，其中DER是最见的一种，DER是ASN.1的一种编码实现，是基于二进制的。实际上还可以使用XML来进行编码，还可以转换为C语言的数据结构。

语法简介参考：https://learn.microsoft.com/zh-cn/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding

2. PKCS#1:公钥密码学标准（PKCS）是由RSA实验室与一个非正式联盟合作共同开发的一套公钥密码学的标准。作为一个OSI标准实现。PKCS是基于二进制和ASCII编码来设计的，也兼容 ITU-T X.509 标准。已经发布的标准有PKCS #1, #3, #5, #7, #8, #9, #10 #11, #12, and #15。PKCS #13 and #14 正在开发中。
PKCS#1标准中定义了RSA公私钥的数据结构，这个标准使用ASN.1来描述数据结构。
以下是公钥加密标准（PKCS）：
- PKCS #1 定义了基于RSA公钥密码系统 加密和签名数据的机制
- PKCS #3 定义了 Diffie-Hellman 密钥协商协议
- PKCS #5 描述了一种 通过从密码衍生出密钥来加密字符串的方法
- PKCS #6 被逐步淘汰，取而代之的是X.509的第三版本
- PKCS #7 为信息定义了大体语法，包括加密增强功能产生的信息，如数字签名和加密
- PKCS #8 描述了私钥信息的格式，这个信息包括某些公钥算法的私钥，和一些可选的属性
- PKCS #9 定义了在其他的PKCS标准中可使用的选定的属性类型
- PKCS #10 描述了认证请求的语法
- PKCS #11 为加密设备定义了一个技术独立的（technology-independent ）编程接口，称之为 Cryptoki。比如智能卡、PCMCIA卡这种加密设备
- PKCS #12 为 存储或传输用户的私钥、证书、各种秘密等的过程 指定了一种可移植的格式
- PKCS #13 的目的是为了定义使用椭圆曲线加密和签名数据加密机制
- PKCS # 14正在酝酿中，涵盖了伪随机数生成
- PKCS # 15是一个PKCS # 11的补充，给出了一个存储在加密令牌上的加密证书的格式的标准

3. X.509：X.509标准是密码学里公钥证书的格式标准。它定义了数字证书的数据结构。使用了ASN.1来描述了数字证书的数据结构。

```bash
openssl asn1parse -in ca.pem
```

**参考文档**：

- [简单了解 PKCS 规范](https://razeen.me/posts/introduce-pkcs/)
- [常见的PKI标准(X.509、PKCS)及证书相关介绍](https://www.jianshu.com/p/bc32cbfe49e7)

#### PEM和DER区别

- .DER = 扩展名DER用于二进制DER编码的证书。这些证书也可以用CER或者CRT作为扩展名。比较合适的说法是“我有一个DER编码的证书”，而不是“我有一个DER证书”。
- .PEM = 扩展名PEM用于ASCII(Base64)编码的各种X.509 v3 证书。文件开始由一行"—– BEGIN …“开始。
der类型的不用再编码解码，直接就是二进制的数据可以直接使用；
pem类型的数据要根据base64编码解码后，得到的数据需要进行增加或裁剪特殊字符-、\n、\r、begin信息、end信息等。

### 文件拓展名说明

文件扩展名并不一定为"PEM"或者"DER",常见的扩展名除了PEM和DER还有以下这些,它们除了编码格式可能不同之外,内容也有差别,但大多数都能相互转换编码格式。
- CRT - CRT应该是certificate的三个字母,其实还是证书的意思,常见于*NIX系统,有可能是PEM编码,也有可能是DER编码,大多数应该是PEM编码。
- CER - 还是certificate,还是证书,常见于Windows系统,同样的,可能是PEM编码,也可能是DER编码,大多数应该是DER编码.证书中没有私钥，DER 编码二进制格式的证书文件。
- KEY - 通常用来存放一个公钥或者私钥,并非X.509证书,编码同样的,可能是PEM,也可能是DER。

### 证书查看及格式转换

更全面的命令行指导需要参考 `openssl help` 。

查看DER格式证书的信息:

```bash
openssl x509 -in certificate.der -inform der -text -noout
```

Java和Windows服务器偏向于使用这种编码格式。

PEM转为DER

```bash
openssl x509 -in cert.crt -outform der -out cert.der
```

DER转为PEM

```bash
openssl x509 -in cert.crt -inform der -outform pem -out cert.pem
```

要转换KEY文件也类似,只不过把x509换成rsa,要转CSR的话,把x509换成req。



