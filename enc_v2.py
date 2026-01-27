import hashlib
import base64
import secrets
import argparse
from datetime import datetime
from typing import Optional, Tuple
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
import hashlib as hashlib2

class KeyBasedEncryptor:
    def __init__(self, suffix=".moyu0721cmd"):
        self.suffix = suffix
        self.salt_size = 16
        self.key_derivation_iterations = 100000
    
    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        return hashlib2.pbkdf2_hmac(
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
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
        timestamp = str(int(datetime.now().timestamp()))
        data_to_encrypt = f"{len(url):04d}|{timestamp}|{url}"
        encrypted_data = cipher.encrypt(pad(data_to_encrypt.encode('utf-8'), AES.block_size))
        
        # 生成和加密会话密钥
        session_key = secrets.token_bytes(32)
        cipher_for_session = AES.new(encryption_key, AES.MODE_ECB)
        encrypted_session_key = cipher_for_session.encrypt(pad(session_key, AES.block_size))
        
        # 生成HMAC校验码
        hmac_calculator = hmac.new(session_key, encrypted_data, hashlib.sha256)
        hmac_digest = hmac_calculator.digest()[:8]
        
        # 组合所有部分并编码
        iv_b64 = base64.urlsafe_b64encode(iv).decode().rstrip('=')
        salt_b64 = base64.urlsafe_b64encode(salt).decode().rstrip('=')
        session_key_b64 = base64.urlsafe_b64encode(encrypted_session_key).decode().rstrip('=')
        data_b64 = base64.urlsafe_b64encode(encrypted_data).decode().rstrip('=')
        hmac_b64 = base64.urlsafe_b64encode(hmac_digest).decode().rstrip('=')
        
        combined = f"v2|{salt_b64}|{session_key_b64}|{iv_b64}|{data_b64}|{hmac_b64}"
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
            
            if len(parts) != 6:
                print("错误: 加密格式无效")
                return None
            
            version, salt_b64, session_key_b64, iv_b64, data_b64, hmac_b64 = parts
            
            if version != "v2":
                print("错误: 不支持的版本")
                return None
            
            # 解码各个组件
            salt = base64.urlsafe_b64decode(salt_b64 + '=' * (4 - len(salt_b64) % 4))
            encrypted_session_key = base64.urlsafe_b64decode(session_key_b64 + '=' * (4 - len(session_key_b64) % 4))
            iv = base64.urlsafe_b64decode(iv_b64 + '=' * (4 - len(iv_b64) % 4))
            encrypted_data = base64.urlsafe_b64decode(data_b64 + '=' * (4 - len(data_b64) % 4))
            expected_hmac = base64.urlsafe_b64decode(hmac_b64 + '=' * (4 - len(hmac_b64) % 4))
            
            # 从密码派生加密密钥
            encryption_key = self._derive_key_from_password(password, salt)
            
            # 解开会话密钥
            cipher_for_session = AES.new(encryption_key, AES.MODE_ECB)
            try:
                session_key_padded = cipher_for_session.decrypt(encrypted_session_key)
                session_key = unpad(session_key_padded, AES.block_size)
            except:
                print("错误: 密钥不正确或数据损坏")
                return None
            
            # 验证HMAC
            hmac_calculator = hmac.new(session_key, encrypted_data, hashlib.sha256)
            calculated_hmac = hmac_calculator.digest()[:8]
            
            if not hmac.compare_digest(calculated_hmac, expected_hmac):
                print("警告: HMAC校验失败，数据可能被篡改")
            
            # 解密数据
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_data)
            decrypted_data = unpad(decrypted_padded, AES.block_size).decode('utf-8')
            
            # 解析解密后的数据
            parts = decrypted_data.split('|', 2)
            if len(parts) != 3:
                print("错误: 解密数据格式无效")
                return None
            
            length_str, timestamp, original_url = parts
            expected_length = int(length_str)
            
            if len(original_url) != expected_length:
                print("警告: 数据长度不匹配")
            
            return original_url
            
        except Exception as e:
            print(f"解密错误: {e}")
            import traceback
            traceback.print_exc()
            return None

def main():
    parser = argparse.ArgumentParser(
        description='独立密钥域名加密生成器',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  加密: enc_v2.exe "https://example.com/some/path"
  解密: enc_v2.exe -d "加密字符串.moyu0721cmd" -k "你的密钥"
        '''
    )
    
    parser.add_argument('url', nargs='?', help='要加密的URL')
    parser.add_argument('-d', '--decrypt', metavar='ENCRYPTED', 
                       help='解密已加密的URL')
    parser.add_argument('-k', '--key', help='解密所需的密钥')
    parser.add_argument('-p', '--password', help='加密时使用自定义密码')
    
    args = parser.parse_args()
    
    encryptor = KeyBasedEncryptor()
    
    # 解密模式
    if args.decrypt:
        if not args.key:
            print("错误: 解密需要提供密钥")
            print("请使用 -k 参数指定密钥")
            return
        
        print(f"尝试解密: {args.decrypt}")
        print("=" * 80)
        
        result = encryptor.decrypt_with_key(args.decrypt, args.key)
        if result:
            print(f"解密成功:")
            print(f"原始URL: {result}")
        else:
            print("解密失败")
            print("可能的原因:")
            print("  1. 密钥不正确")
            print("  2. 加密字符串格式错误")
            print("  3. 数据已被篡改")
        
        print("=" * 80)
        return
    
    # 加密模式
    if args.url:
        try:
            encrypted, key = encryptor.encrypt_with_key(args.url, args.password)
            
            print("\n" + "=" * 80)
            print(f"原始URL: {args.url}")
            print(f"加密结果: {encrypted}")
            print(f"加密密钥: {key}")
            print(f"重要: 请妥善保存此密钥，解密时需要它")
            print("=" * 80)
            
            # 显示解密提示
            if args.password:
                print(f"\n解密命令:")
                print(f'  enc_v2.exe -d "{encrypted}" -k "{args.password}"')
            else:
                print(f"\n解密命令:")
                print(f'  enc_v2.exe -d "{encrypted}" -k "{key}"')
            
        except Exception as e:
            print(f"处理过程中出现错误: {e}")
            import traceback
            traceback.print_exc()
    else:
        # 交互模式
        print("独立密钥域名加密生成器")
        print("=" * 40)
        print("命令说明:")
        print("  [URL]      - 加密URL（随机生成密钥）")
        print("  d [加密URL] - 解密（需要密钥）")
        print("  q          - 退出")
        print("=" * 40)
        
        while True:
            try:
                user_input = input("\n请输入命令或URL: ").strip()
                
                if user_input.lower() == 'q':
                    break
                elif user_input.lower().startswith('d '):
                    encrypted_url = user_input[2:].strip()
                    key = input("请输入解密密钥: ").strip()
                    
                    result = encryptor.decrypt_with_key(encrypted_url, key)
                    if result:
                        print(f"解密结果: {result}")
                    else:
                        print("解密失败")
                    continue
                
                # 默认为加密
                if user_input:
                    # 询问是否使用自定义密码
                    use_custom = input("使用自定义密码？(y/N): ").strip().lower()
                    password = None
                    
                    if use_custom == 'y':
                        password = input("请输入密码: ").strip()
                    
                    encrypted, key = encryptor.encrypt_with_key(user_input, password)
                    print(f"加密结果: {encrypted}")
                    print(f"请妥善保存以下密钥以便解密:{key}")
                    print(f"加密密钥: {key}")
                    print(f"提示: 使用 'd {encrypted}' 解密")
                    
            except KeyboardInterrupt:
                print("\n程序已退出")
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
