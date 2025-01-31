# # 옵션 A 실행 (파일 내용 초기화)
# python3 delete.py -a

# # 옵션 B 실행 (파일명 난독화)
# python3 delete.py -b

import os
import uuid
import argparse

def secure_delete():
    parser = argparse.ArgumentParser(description='파일 안전 삭제 도구')
    parser.add_argument('-a', '--option-a', action='store_true', help='파일 내용 초기화')
    parser.add_argument('-b', '--option-b', action='store_true', help='파일명 난독화')
    args = parser.parse_args()

    if not (args.option_a ^ args.option_b):
        parser.error("반드시 하나의 옵션을 선택해야 합니다 (-a 또는 -b)")

    delete_dir = './delete'
    if not os.path.exists(delete_dir):
        print(f"경고: {delete_dir} 디렉토리가 존재하지 않습니다")
        return

    for filename in os.listdir(delete_dir):
        file_path = os.path.join(delete_dir, filename)
        
        if os.path.isfile(file_path):
            try:
                if args.option_a:
                    # 파일 내용 초기화
                    with open(file_path, 'w') as f:
                        f.write('')
                    print(f"[성공] 내용 삭제: {filename}")

                elif args.option_b:
                    # 파일명 난독화 (확장자 제거)
                    new_name = uuid.uuid4().hex
                    new_path = os.path.join(delete_dir, new_name)
                    os.rename(file_path, new_path)
                    print(f"[성공] 이름 변경: {filename} -> {new_name}")

            except Exception as e:
                print(f"[실패] 처리 실패: {filename} - {str(e)}")

if __name__ == '__main__':
    secure_delete()