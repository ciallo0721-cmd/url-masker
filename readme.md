# Key-Based URL Encryptor

## 概述
`enc_v2.py` 是一个基于密钥的 URL 加密和解密工具，旨在提供安全的 URL 加密功能。它支持用户自定义密码或随机生成密钥，并通过 AES 加密算法确保数据的安全性。

## 功能
- **加密 URL**：
  - 支持用户自定义密码。
  - 自动生成随机密钥（如果未提供密码）。
  - 生成加密后的字符串，附带自定义后缀。
- **解密 URL**：
  - 验证加密数据的完整性。
  - 解密并还原原始 URL。
- **HMAC 校验**：
  - 确保数据未被篡改。

## 使用方法

### 加密
运行以下命令加密 URL：
```bash
python enc_v2.py <URL>
```
示例：
```bash
python enc_v2.py ciallo0721-cmd.github.io/blog
```

输出：
- 加密后的字符串
- 加密密钥（用于解密）

### 解密
运行以下命令解密加密字符串：
```bash
python enc_v2.py -d <加密字符串> -k <密钥>
```
示例：
```bash
python enc_v2.py -d "加密字符串.moyu0721cmd" -k "你的密钥"
```

## 依赖
- Python 3.6+
- `pycryptodome` 库

安装依赖：
```bash
pip install pycryptodome
```

## 文件结构
- `KeyBasedEncryptor` 类：
  - 核心加密和解密逻辑。
- `main` 函数：
  - 提供命令行接口。

## 注意事项
- 请妥善保存加密密钥，解密时需要它。
- 如果加密字符串被篡改，解密可能会失败。

## 示例
### 加密
```bash
python enc_v2.py ciallo0721-cmd.github.io/blog
```
输出：
```
原始URL: ciallo0721-cmd.github.io/blog
加密结果: v2|...|.moyu0721cmd
加密密钥: your-generated-key
```

### 解密
```bash
python enc_v2.py -d "v2|...|.moyu0721cmd" -k "your-generated-key"
```
输出：
```
解密成功:
原始URL: ciallo0721-cmd.github.io/blog
```