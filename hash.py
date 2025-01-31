import os
import re
import base64
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import hashlib

MAX_FILENAME_LENGTH = 255
METADATA_HEADER_SIZE = 20  # IV(16) + filename_len(4)

def safe_b64encode(data):
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def safe_b64decode(data):
    padding_needed = 4 - (len(data) % 4)
    return base64.urlsafe_b64decode(data + '=' * padding_needed)

def get_unique_filename(directory, base_name, extension, index=0):
    """개선된 파일명 생성 함수"""
    max_base_length = MAX_FILENAME_LENGTH - len(extension) - 10
    truncated_base = base_name[:max_base_length]
    
    def generate_name(idx):
        return f"{truncated_base}_{idx}.{extension}" if idx > 0 else f"{truncated_base}.{extension}"
    
    while True:
        candidate = generate_name(index)
        full_path = os.path.join(directory, candidate)
        if not os.path.exists(full_path):
            return candidate
        index += 1

def process_directory(input_dir, output_dir, action, user_key):
    for filename in os.listdir(input_dir):
        input_path = os.path.join(input_dir, filename)
        if os.path.isfile(input_path):
            try:
                if action == 'encrypt':
                    result = encrypt_file(input_path, output_dir, user_key)
                else:
                    result = decrypt_file(input_path, output_dir, user_key)
                print(f"✓ {filename} → {os.path.basename(result)}")
            except Exception as e:
                print(f"✗ {filename} 처리 실패: {str(e)}")

def derive_keys(user_key):
    master_key = hashlib.sha256(user_key.encode()).digest()
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'filename-key',
        backend=default_backend()
    )
    filename_key = hkdf.derive(master_key)
    
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'data-key',
        backend=default_backend()
    )
    data_key = hkdf.derive(master_key)
    
    return filename_key, data_key

def encrypt_filename(filename, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    filename_bytes = filename.encode('utf-8')
    padded_name = padder.update(filename_bytes) + padder.finalize()
    return encryptor.update(padded_name) + encryptor.finalize()

def decrypt_filename(encrypted_bytes, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(decrypted_padded) + unpadder.finalize()

def encrypt_file(input_path, output_dir, user_key):
    filename_key, data_key = derive_keys(user_key)
    original_filename = os.path.basename(input_path)
    
    # 파일명 암호화
    encrypted_filename = encrypt_filename(original_filename, filename_key)
    
    # 데이터 암호화
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(data_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    # 메타데이터 구성
    filename_len = len(encrypted_filename).to_bytes(4, 'big')
    file_content = iv + filename_len + encrypted_filename + ciphertext
    
    # 출력 파일명 생성
    file_hash = hashlib.sha256(file_content).hexdigest()[:16]
    output_filename = get_unique_filename(output_dir, file_hash, 'enc')
    output_path = os.path.join(output_dir, output_filename)
    
    with open(output_path, 'wb') as f:
        f.write(file_content)
    
    return output_path

def decrypt_file(input_path, output_dir, user_key):
    filename_key, data_key = derive_keys(user_key)
    
    with open(input_path, 'rb') as f:
        file_content = f.read()
    
    # 메타데이터 추출
    iv = file_content[:16]
    filename_len = int.from_bytes(file_content[16:20], 'big')
    encrypted_filename = file_content[20:20+filename_len]
    ciphertext = file_content[20+filename_len:]
    
    # 파일명 복호화
    try:
        decrypted_bytes = decrypt_filename(encrypted_filename, filename_key)
        original_filename = decrypted_bytes.decode('utf-8')
    except Exception as e:
        raise ValueError(f"파일명 복호화 실패: {str(e)}")
    
    # 데이터 복호화
    cipher = Cipher(algorithms.AES(data_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    try:
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()
    except ValueError:
        raise ValueError("데이터 복호화 실패: 패딩 오류")
    
    # 출력 파일 생성
    base_name, ext = os.path.splitext(original_filename)
    final_name = get_unique_filename(output_dir, base_name, ext.lstrip('.'))
    output_path = os.path.join(output_dir, final_name)
    
    with open(output_path, 'wb') as f:
        f.write(decrypted_data)
    
    return output_path

def main():
    parser = argparse.ArgumentParser(description="고급 영상 암호화/복호화 도구")
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help='처리 동작 선택')
    parser.add_argument('--input', default='./input', help='입력 디렉토리 (기본: ./input)')
    parser.add_argument('--output', default='./output', help='출력 디렉토리 (기본: ./output)')
    parser.add_argument('--key', required=True, help='암호화 키 (필수)')
    args = parser.parse_args()
    
    os.makedirs(args.input, exist_ok=True)
    os.makedirs(args.output, exist_ok=True)
    
    try:
        if args.action == 'encrypt':
            process_directory(args.input, args.output, 'encrypt', args.key)
            print(f"✅ 암호화 완료: {args.output}/ 경로 확인")
        else:
            process_directory(args.output, args.input, 'decrypt', args.key)
            print(f"✅ 복호화 완료: {args.input}/ 경로 확인")
    except Exception as e:
        print(f"⛔ 치명적 오류: {str(e)}")

if __name__ == '__main__':
    main()