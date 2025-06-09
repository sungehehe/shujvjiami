import os

key_storage_path = "./keys"  # 根据你的配置修改路径
master_key_path = os.path.join(key_storage_path, "master.key")

try:
    with open(master_key_path, 'rb') as f:
        master_key = f.read()
        print(f"主密钥的二进制内容: {master_key}")
        print(f"主密钥的十六进制表示: {master_key.hex()}")
except FileNotFoundError:
    print(f"未找到 {master_key_path} 文件，请检查路径是否正确。")