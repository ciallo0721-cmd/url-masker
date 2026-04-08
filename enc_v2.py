"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     🔐 独立密钥域名加密生成器 - URL Masker Pro                              ║
║                                                                              ║
║     安全级别:                                                                ║
║       .moyu          - 低安全性  (10,000次迭代)                              ║
║       .ciallo0721cmd - 中等安全性 (50,000次迭代)                             ║
║       .moyu0721cmd   - 较高安全性 (100,000次迭代)                            ║
║       .guange        - 最高安全性 (500,000次迭代)                            ║
║                                                                              ║
║     版本: v3 (CBC加密会话密钥 + 完整HMAC) | v2 (旧版兼容)                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import hashlib
import base64
import secrets
import argparse
from datetime import datetime
from typing import Optional, Tuple
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class KeyBasedEncryptor:
    # 定义不同后缀的安全级别配置
    SECURITY_LEVELS = {
        '.moyu': {
            'salt_size': 8,
            'iterations': 10000,
            'description': '低安全性 - 适合临时使用'
        },
        '.ciallo0721cmd': {
            'salt_size': 12,
            'iterations': 50000,
            'description': '中等安全性 - 日常使用'
        },
        '.moyu0721cmd': {
            'salt_size': 16,
            'iterations': 100000,
            'description': '较高安全性 - 推荐'
        },
        '.guange': {
            'salt_size': 32,
            'iterations': 500000,
            'description': '最高安全性 - 敏感数据'
        }
    }

    DEFAULT_SUFFIX = '.moyu0721cmd'

    def __init__(self, suffix: Optional[str] = None):
        # 自动检测或设置后缀
        if suffix is None:
            suffix = self.DEFAULT_SUFFIX

        # 确保后缀以点开头
        if not suffix.startswith('.'):
            suffix = '.' + suffix

        self.suffix = suffix.lower()

        # 获取安全级别配置
        config = self.SECURITY_LEVELS.get(self.suffix, self.SECURITY_LEVELS[self.DEFAULT_SUFFIX])
        self.salt_size = config['salt_size']
        self.key_derivation_iterations = config['iterations']
        self.security_description = config['description']

    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            self.key_derivation_iterations,
            dklen=32
        )

    def encrypt_with_key(self, url: str, user_password: Optional[str] = None) -> Tuple[str, str]:
        # 生成随机盐值
        salt = secrets.token_bytes(self.salt_size)

        # 使用用户提供的密码或生成随机密钥
        if user_password:
            base_password = user_password
        else:
            base_password = secrets.token_urlsafe(16)

        # 从密码派生加密密钥
        encryption_key = self._derive_key_from_password(base_password, salt)

        # 生成随机IV并加密数据
        iv = secrets.token_bytes(AES.block_size)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        timestamp = str(int(datetime.now().timestamp()))
        data_to_encrypt = f"{len(url):04d}|{timestamp}|{url}"
        encrypted_data = cipher.encrypt(pad(data_to_encrypt.encode('utf-8'), AES.block_size))

        # 生成和加密会话密钥 (v3: 使用CBC模式，替代不安全的ECB)
        session_key = secrets.token_bytes(32)
        iv_session = secrets.token_bytes(AES.block_size)
        cipher_for_session = AES.new(encryption_key, AES.MODE_CBC, iv_session)
        encrypted_session_key = cipher_for_session.encrypt(pad(session_key, AES.block_size))

        # 生成HMAC校验码 (v3: 保留完整32字节，不截断)
        hmac_calculator = hmac.new(session_key, encrypted_data, hashlib.sha256)
        hmac_digest = hmac_calculator.digest()

        # 组合所有部分并编码 (v3格式: salt | session_iv | session_key | data_iv | data | hmac)
        iv_b64 = base64.urlsafe_b64encode(iv).decode().rstrip('=')
        salt_b64 = base64.urlsafe_b64encode(salt).decode().rstrip('=')
        iv_session_b64 = base64.urlsafe_b64encode(iv_session).decode().rstrip('=')
        session_key_b64 = base64.urlsafe_b64encode(encrypted_session_key).decode().rstrip('=')
        data_b64 = base64.urlsafe_b64encode(encrypted_data).decode().rstrip('=')
        hmac_b64 = base64.urlsafe_b64encode(hmac_digest).decode().rstrip('=')

        combined = f"v3|{salt_b64}|{iv_session_b64}|{session_key_b64}|{iv_b64}|{data_b64}|{hmac_b64}"
        final_encoded = base64.urlsafe_b64encode(combined.encode()).decode().rstrip('=')
        final_encoded = final_encoded.replace('+', '-').replace('/', '_')

        # 确保最小长度
        min_length = 20
        if len(final_encoded) < min_length:
            final_encoded = final_encoded.ljust(min_length, 'x')

        return f"{final_encoded}{self.suffix}", base_password

    def decrypt_with_key(self, encrypted_url: str, password: str) -> Optional[str]:
        try:
            # 移除后缀
            if encrypted_url.endswith(self.suffix):
                encrypted_part = encrypted_url[:-len(self.suffix)]
            else:
                encrypted_part = encrypted_url

            # 恢复Base64字符并解码
            encoded = encrypted_part.replace('-', '+').replace('_', '/')
            missing_padding = len(encoded) % 4
            if missing_padding:
                encoded += '=' * (4 - missing_padding)

            decoded = base64.urlsafe_b64decode(encoded.encode()).decode()
            parts = decoded.split('|')

            # v3格式: 7个字段; v2格式(旧): 6个字段，尝试兼容
            version = parts[0]

            if version == "v3":
                if len(parts) != 7:
                    print("错误: 加密格式无效")
                    return None
                _, salt_b64, iv_session_b64, session_key_b64, iv_b64, data_b64, hmac_b64 = parts
            elif version == "v2":
                if len(parts) != 6:
                    print("错误: 加密格式无效")
                    return None
                _, salt_b64, session_key_b64, iv_b64, data_b64, hmac_b64 = parts
                iv_session_b64 = None  # 旧格式无session_iv
            else:
                print("错误: 不支持的版本")
                return None

            # 解码各个组件
            salt = base64.urlsafe_b64decode(salt_b64 + '=' * ((4 - len(salt_b64) % 4) % 4))
            encrypted_session_key = base64.urlsafe_b64decode(session_key_b64 + '=' * ((4 - len(session_key_b64) % 4) % 4))
            iv = base64.urlsafe_b64decode(iv_b64 + '=' * ((4 - len(iv_b64) % 4) % 4))
            encrypted_data = base64.urlsafe_b64decode(data_b64 + '=' * ((4 - len(data_b64) % 4) % 4))
            expected_hmac = base64.urlsafe_b64decode(hmac_b64 + '=' * ((4 - len(hmac_b64) % 4) % 4))

            # 从密码派生加密密钥
            encryption_key = self._derive_key_from_password(password, salt)

            # 解开会话密钥 (v3用CBC，v2旧版用ECB兼容)
            try:
                if iv_session_b64:
                    iv_session = base64.urlsafe_b64decode(iv_session_b64 + '=' * ((4 - len(iv_session_b64) % 4) % 4))
                    cipher_for_session = AES.new(encryption_key, AES.MODE_CBC, iv_session)
                else:
                    cipher_for_session = AES.new(encryption_key, AES.MODE_ECB)  # v2兼容
                session_key_padded = cipher_for_session.decrypt(encrypted_session_key)
                session_key = unpad(session_key_padded, AES.block_size)
            except (ValueError, KeyError) as e:
                print("错误: 密钥不正确或数据损坏")
                return None

            # 验证HMAC (v3完整32字节，v2旧8字节)
            hmac_calculator = hmac.new(session_key, encrypted_data, hashlib.sha256)
            calculated_hmac = hmac_calculator.digest()
            # v2旧格式的HMAC只有8字节，截断比较
            if version == "v2":
                calculated_hmac = calculated_hmac[:8]

            if not hmac.compare_digest(calculated_hmac, expected_hmac):
                print("HMAC校验失败，数据可能被篡改，拒绝解密以保护安全")
                return None

            # 解密数据
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_padded, AES.block_size).decode('utf-8')

            # 解析解密后的数据
            split_parts = decrypted_data.split('|', 2)
            if len(split_parts) != 3:
                print("错误: 解密数据格式无效")
                return None

            length_str, timestamp, original_url = split_parts
            expected_length = int(length_str)

            if len(original_url) != expected_length:
                print("警告: 数据长度不匹配，URL可能被截断或损坏")

            return original_url

        except (ValueError, KeyError, IndexError) as e:
            # 提供更友好的错误信息
            error_msg = str(e).lower()
            if 'key' in error_msg or '密钥' in error_msg:
                print("错误: 密钥不正确或格式错误")
            elif 'padding' in error_msg or '填充' in error_msg:
                print("错误: 加密数据可能已损坏")
            elif 'base64' in error_msg:
                print("错误: 加密字符串格式不正确")
            else:
                print(f"解密错误: {e}")
            return None

def validate_url(url: str) -> bool:
    """验证URL格式是否基本合法"""
    if not url or len(url) > 2048:
        return False
    # 使用urllib.parse进行严格URL验证
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        # 必须有合法scheme和netloc（域名）
        if parsed.scheme not in ('http', 'https', 'ftp', 'file'):
            return False
        if not parsed.netloc and parsed.scheme != 'file':
            return False
        # 防止路径遍历等恶意输入
        if '..' in url or url.startswith('/'):
            if not url.startswith(('http://', 'https://', 'ftp://', 'file://')):
                return False
        return True
    except (ValueError, AttributeError):
        return False

def detect_suffix(encrypted_url: str) -> str:
    """从加密字符串中检测后缀"""
    encrypted_url = encrypted_url.lower()
    # 按长度降序检查，避免短后缀误判
    suffixes = sorted(KeyBasedEncryptor.SECURITY_LEVELS.keys(), key=len, reverse=True)
    for suffix in suffixes:
        if encrypted_url.endswith(suffix):
            return suffix
    return KeyBasedEncryptor.DEFAULT_SUFFIX

def main():
    parser = argparse.ArgumentParser(
        description='独立密钥域名加密生成器 - 支持多级安全模式',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
安全级别 (后缀):
  .moyu          - 低安全性 (10,000次迭代)
  .ciallo0721cmd - 中等安全性 (50,000次迭代)
  .moyu0721cmd   - 较高安全性 (100,000次迭代, 默认)
  .guange        - 最高安全性 (500,000次迭代)

使用示例:
  加密: enc_v2.exe "https://example.com/some/path"
  加密(指定安全级别): enc_v2.exe "https://example.com" -s guange
  解密: enc_v2.exe -d "加密字符串.moyu0721cmd" -k "你的密钥"
        '''
    )

    parser.add_argument('url', nargs='?', help='要加密的URL')
    parser.add_argument('-d', '--decrypt', metavar='ENCRYPTED',
                       help='解密已加密的URL')
    parser.add_argument('-k', '--key', help='解密所需的密钥')
    parser.add_argument('-p', '--password', help='加密时使用自定义密码')
    parser.add_argument('-s', '--suffix', default='moyu0721cmd',
                       help='加密后缀/安全级别 (moyu/ciallo0721cmd/moyu0721cmd/guange)')

    args = parser.parse_args()

    # 根据参数或自动检测创建加密器
    if args.decrypt:
        # 解密时自动检测后缀
        detected_suffix = detect_suffix(args.decrypt)
        encryptor = KeyBasedEncryptor(detected_suffix)
    else:
        # 加密时使用指定后缀
        encryptor = KeyBasedEncryptor(args.suffix)

    # 解密模式
    if args.decrypt:
        if not args.key:
            print("错误: 解密需要提供密钥")
            print("请使用 -k 参数指定密钥")
            return

        print(f" 尝试解密: {args.decrypt}")
        print(f" 检测到安全级别: {encryptor.security_description}")
        print("=" * 80)

        result = encryptor.decrypt_with_key(args.decrypt, args.key)
        if result:
            print(f"解密成功!")
            print(f"原始URL: {result}")
        else:
            print("解密失败")
            print("可能的原因:")
            print("  1. 密钥不正确")
            print("  2. 加密字符串格式错误")
            print("  3. 数据已被篡改 (HMAC校验失败)")

        print("=" * 80)
        return

    # 加密模式
    if args.url:
        # 验证URL
        if not validate_url(args.url):
            print("错误: URL格式无效或过长")
            print("提示: URL应以 http:// 或 https:// 开头")
            return

        try:
            encrypted, key = encryptor.encrypt_with_key(args.url, args.password)

            print("\n" + "=" * 80)
            print(f" 原始URL: {args.url}")
            print(f" 加密结果: {encrypted}")
            print(f" 加密密钥: {key}")
            print(f" 安全级别: {encryptor.security_description}")
            print(f" 重要: 请妥善保存此密钥，解密时需要它!")
            print("=" * 80)

            # 显示解密提示
            decrypt_key = args.password if args.password else key
            print(f"\n 解密命令:")
            print(f'   enc_v2.exe -d "{encrypted}" -k "{decrypt_key}"')

        except Exception as e:
            print(f"处理过程中出现错误: {e}")
            import traceback
            traceback.print_exc()
    else:
        # 交互模式
        print(" 独立密钥域名加密生成器")
        print("=" * 50)
        print("安全级别:")
        for suffix, config in KeyBasedEncryptor.SECURITY_LEVELS.items():
            print(f"  {suffix:<15} - {config['description']}")
        print("-" * 50)
        print("命令说明:")
        print("  [URL]              - 加密URL（随机生成密钥）")
        print("  decrypt [加密URL]  - 解密（需要密钥）")
        print("  q                  - 退出")
        print("=" * 50)

        while True:
            try:
                user_input = input("\n请输入命令或URL: ").strip()

                if user_input.lower() == 'q':
                    print("再见!")
                    break
                elif user_input.lower().startswith('decrypt '):
                    encrypted_url = user_input[8:].strip()
                    # 自动检测后缀创建对应加密器
                    detected_suffix = detect_suffix(encrypted_url)
                    encryptor = KeyBasedEncryptor(detected_suffix)
                    print(f" 检测到安全级别: {encryptor.security_description}")
                    key = input("请输入解密密钥: ").strip()

                    result = encryptor.decrypt_with_key(encrypted_url, key)
                    if result:
                        print(f"解密结果: {result}")
                    else:
                        print("解密失败，请检查密钥是否正确")
                    continue

                # 默认为加密
                if user_input:
                    # 验证URL
                    if not validate_url(user_input):
                        print("URL格式无效，应以 http:// 或 https:// 开头")
                        continue

                    # 选择安全级别
                    print("\n选择安全级别:")
                    suffixes = list(KeyBasedEncryptor.SECURITY_LEVELS.keys())
                    for i, suffix in enumerate(suffixes, 1):
                        config = KeyBasedEncryptor.SECURITY_LEVELS[suffix]
                        marker = " (默认)" if suffix == KeyBasedEncryptor.DEFAULT_SUFFIX else ""
                        print(f"  {i}. {suffix:<15} - {config['description']}{marker}")

                    choice = input("\n请选择 (1-4, 直接回车使用默认): ").strip()
                    if choice.isdigit() and 1 <= int(choice) <= len(suffixes):
                        selected_suffix = suffixes[int(choice) - 1]
                    else:
                        selected_suffix = KeyBasedEncryptor.DEFAULT_SUFFIX

                    encryptor = KeyBasedEncryptor(selected_suffix)

                    # 询问是否使用自定义密码
                    use_custom = input("使用自定义密码？(y/N): ").strip().lower()
                    password = None

                    if use_custom == 'y':
                        password = input("请输入密码: ").strip()

                    encrypted, key = encryptor.encrypt_with_key(user_input, password)
                    print(f"\n{'='*60}")
                    print(f" 加密结果: {encrypted}")
                    print(f" 加密密钥: {key}")
                    print(f" 安全级别: {encryptor.security_description}")
                    print(f" 请妥善保存密钥，解密时需要它!")
                    print(f"{'='*60}")
                    print(f" 提示: 使用 'decrypt {encrypted}' 命令解密")

            except KeyboardInterrupt:
                print("\n 程序已退出")
                break
            except Exception as e:
                print(f"错误: {e}")

if __name__ == "__main__":
    try:
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad, unpad
    except ImportError:
        print("错误: 需要安装pycryptodome库")
        print("安装命令: pip install pycryptodome")
        exit(1)

    main()
