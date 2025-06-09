import os
import json
import logging
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from typing import Dict, Any, Optional, Union

# 配置日志记录
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("encryption_audit.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DataEncryptionSystem")

class DataClassifier:
    """数据分类分级模块"""
    
    def __init__(self, classification_rules_path: str):
        self.rules = self._load_rules(classification_rules_path)
    
    def _load_rules(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"加载分类规则失败: {e}")
            return {}
    
    def classify_data(self, data: Any, context: Dict[str, Any]) -> str:
        """根据预定义规则对数据进行分类分级"""
        # 实际实现需要基于具体业务规则
        for category, rules in self.rules.items():
            if self._check_rules(data, context, rules):
                return category
        return "公开"
    
    def _check_rules(self, data: Any, context: Dict[str, Any], rules: Dict[str, Any]) -> bool:
        """检查数据是否符合特定分类规则"""
        # 简化实现，实际应用中需要更复杂的规则评估
        return False


class KeyManager:
    """密钥管理模块"""
    
    def __init__(self, key_storage_path: str):
        self.key_storage_path = key_storage_path
        self.master_key = self._load_or_generate_master_key()
        self.key_rotation_interval = timedelta(days=30)
        self.current_data_key = self._get_current_data_key()
    
    def _load_or_generate_master_key(self) -> bytes:
        """加载或生成主密钥"""
        master_key_path = os.path.join(self.key_storage_path, "master.key")
        if os.path.exists(master_key_path):
            with open(master_key_path, 'rb') as f:
                return f.read()
        else:
            os.makedirs(self.key_storage_path, exist_ok=True)
            master_key = os.urandom(32)  # 256-bit AES key
            with open(master_key_path, 'wb') as f:
                f.write(master_key)
            logger.info("生成新的主密钥")
            return master_key
    
    def _get_current_data_key(self) -> Dict[str, Any]:
        """获取当前数据密钥，必要时生成新密钥"""
        data_keys_path = os.path.join(self.key_storage_path, "data_keys.json")
        if os.path.exists(data_keys_path):
            with open(data_keys_path, 'r') as f:
                data_keys = json.load(f)
                latest_key = data_keys[-1]
                creation_time = datetime.fromisoformat(latest_key['creation_time'])
                if datetime.now() - creation_time > self.key_rotation_interval:
                    return self._generate_new_data_key()
                return latest_key
        return self._generate_new_data_key()
    
    def _generate_new_data_key(self) -> Dict[str, Any]:
        """生成新的数据密钥"""
        data_key = os.urandom(32)  # 256-bit AES key
        encrypted_key = self._encrypt_key(data_key)
        
        new_key = {
            "key_id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "encrypted_key": encrypted_key.hex(),
            "creation_time": datetime.now().isoformat()
        }
        
        data_keys_path = os.path.join(self.key_storage_path, "data_keys.json")
        data_keys = []
        if os.path.exists(data_keys_path):
            with open(data_keys_path, 'r') as f:
                data_keys = json.load(f)
        
        data_keys.append(new_key)
        with open(data_keys_path, 'w') as f:
            json.dump(data_keys, f, indent=2)
        
        logger.info(f"生成新的数据密钥: {new_key['key_id']}")
        return new_key
    
    def _encrypt_key(self, key: bytes) -> bytes:
        """使用主密钥加密数据密钥"""
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(os.urandom(12)))
        encryptor = cipher.encryptor()
        encrypted_key = encryptor.update(key) + encryptor.finalize()
        return encrypted_key + encryptor.tag
    
    def get_decrypted_data_key(self, key_id: Optional[str] = None) -> bytes:
        """获取解密后的数据密钥"""
        if key_id is None:
            key_id = self.current_data_key['key_id']
        
        data_keys_path = os.path.join(self.key_storage_path, "data_keys.json")
        if not os.path.exists(data_keys_path):
            raise ValueError("数据密钥不存在")
        
        with open(data_keys_path, 'r') as f:
            data_keys = json.load(f)
        
        for key_data in data_keys:
            if key_data['key_id'] == key_id:
                encrypted_key_with_tag = bytes.fromhex(key_data['encrypted_key'])
                tag = encrypted_key_with_tag[-16:]
                encrypted_key = encrypted_key_with_tag[:-16]
                
                cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(os.urandom(12), tag))
                decryptor = cipher.decryptor()
                return decryptor.update(encrypted_key) + decryptor.finalize()
        
        raise ValueError(f"找不到密钥 ID: {key_id}")


class EncryptionEngine:
    """加密引擎，实现混合加密"""
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.rsa_key_size = 2048
        self.aes_key_size = 256
    
    def generate_rsa_key_pair(self) -> Dict[str, bytes]:
        """生成RSA密钥对"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=default_backend()
        )
        
        public_key = private_key.public_key()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            "private_key": private_pem,
            "public_key": public_pem
        }
    
    def encrypt_with_rsa(self, data: bytes, public_key_pem: bytes) -> bytes:
        """使用RSA公钥加密数据"""
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted
    
    def decrypt_with_rsa(self, encrypted_data: bytes, private_key_pem: bytes) -> bytes:
        """使用RSA私钥解密数据"""
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted
    
    def encrypt_with_aes(self, data: Union[str, bytes], key_id: Optional[str] = None) -> Dict[str, bytes]:
        """使用AES加密数据"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        data_key = self.key_manager.get_decrypted_data_key(key_id)
        iv = os.urandom(12)  # AES-GCM推荐使用12字节IV
        
        cipher = Cipher(algorithms.AES(data_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        return {
            "ciphertext": encrypted_data,
            "iv": iv,
            "tag": encryptor.tag,
            "key_id": key_id or self.key_manager.current_data_key['key_id']
        }
    
    def decrypt_with_aes(self, encrypted_data: Dict[str, bytes]) -> bytes:
        """使用AES解密数据"""
        ciphertext = encrypted_data["ciphertext"]
        iv = encrypted_data["iv"]
        tag = encrypted_data["tag"]
        key_id = encrypted_data.get("key_id")
        
        data_key = self.key_manager.get_decrypted_data_key(key_id)
        
        cipher = Cipher(algorithms.AES(data_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def hybrid_encrypt(self, data: Union[str, bytes], recipient_public_key: bytes) -> Dict[str, bytes]:
        """混合加密：使用AES加密数据，使用RSA加密AES密钥"""
        aes_encrypted = self.encrypt_with_aes(data)
        encrypted_key = self.encrypt_with_rsa(
            aes_encrypted["key_id"].encode('utf-8'), 
            recipient_public_key
        )
        
        return {
            "encrypted_data": aes_encrypted["ciphertext"],
            "iv": aes_encrypted["iv"],
            "tag": aes_encrypted["tag"],
            "encrypted_key": encrypted_key
        }
    
    def hybrid_decrypt(self, encrypted_data: Dict[str, bytes], private_key: bytes) -> bytes:
        """混合解密：使用RSA解密AES密钥，使用AES解密数据"""
        decrypted_key_id = self.decrypt_with_rsa(
            encrypted_data["encrypted_key"], 
            private_key
        ).decode('utf-8')
        
        aes_data = {
            "ciphertext": encrypted_data["encrypted_data"],
            "iv": encrypted_data["iv"],
            "tag": encrypted_data["tag"],
            "key_id": decrypted_key_id
        }
        
        return self.decrypt_with_aes(aes_data)


class AuditLogger:
    """审计日志与异常检测模块"""
    
    def __init__(self, audit_log_path: str):
        self.audit_log_path = audit_log_path
        self.anomaly_rules = self._load_anomaly_rules()
        self.suspicious_activities = []
    
    def _load_anomaly_rules(self) -> Dict[str, Any]:
        """加载异常检测规则"""
        try:
            with open("anomaly_rules.json", 'r') as f:
                return json.load(f)
        except Exception:
            return {
                "frequent_access_threshold": 100,  # 单位时间内的频繁访问阈值
                "unusual_time_threshold": 2,       # 异常时间访问阈值
                "failed_attempts_threshold": 5     # 失败尝试阈值
            }
    
    def log_operation(self, operation: str, user: str, data_category: str, success: bool, details: Dict[str, Any] = None):
        """记录操作审计日志"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "operation": operation,
            "user": user,
            "data_category": data_category,
            "success": success,
            "details": details or {}
        }
        
        self._write_log_entry(log_entry)
        self._check_anomaly(log_entry)
    
    def _write_log_entry(self, entry: Dict[str, Any]):
        """写入日志条目"""
        with open(self.audit_log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def _check_anomaly(self, entry: Dict[str, Any]):
        """检查是否存在异常行为"""
        # 简化的异常检测逻辑
        if not entry["success"]:
            self._check_failed_attempts(entry["user"])
        
        # 可以添加更多异常检测逻辑
        # ...
    
    def _check_failed_attempts(self, user: str):
        """检查用户失败尝试次数"""
        recent_fails = [
            e for e in self.suspicious_activities 
            if e["user"] == user and not e["success"]
        ]
        
        if len(recent_fails) >= self.anomaly_rules["failed_attempts_threshold"]:
            logger.warning(f"用户 {user} 多次尝试失败，可能存在暴力破解风险")
            # 可以触发警报或采取其他措施


class DataEncryptionSystem:
    """敏感数据加密系统主类"""
    
    def __init__(self, config_path: str = "encryption_config.json"):
        self.config = self._load_config(config_path)
        self.classifier = DataClassifier(self.config["classification_rules_path"])
        self.key_manager = KeyManager(self.config["key_storage_path"])
        self.encryption_engine = EncryptionEngine(self.key_manager)
        self.audit_logger = AuditLogger(self.config["audit_log_path"])
    
    def _load_config(self, path: str) -> Dict[str, Any]:
        """加载系统配置"""
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except Exception:
            return {
                "classification_rules_path": "classification_rules.json",
                "key_storage_path": "./keys",
                "audit_log_path": "encryption_audit.log",
                "anomaly_rules_path": "anomaly_rules.json"
            }
    
    def process_data(self, data: Any, context: Dict[str, Any], user: str) -> Dict[str, Any]:
        """处理数据：分类、加密并记录审计日志"""
        category = self.classifier.classify_data(data, context)
        logger.info(f"数据分类为: {category}")
        
        if category == "公开":
            self.audit_logger.log_operation(
                "数据处理", user, category, True, 
                {"reason": "数据为公开类型，无需加密"}
            )
            return {"data": data, "category": category, "encrypted": False}
        
        try:
            # 生成RSA密钥对（实际应用中应该预先生成并安全存储）
            key_pair = self.encryption_engine.generate_rsa_key_pair()
            
            # 使用混合加密
            encrypted_result = self.encryption_engine.hybrid_encrypt(
                json.dumps(data), key_pair["public_key"]
            )
            
            self.audit_logger.log_operation(
                "数据加密", user, category, True,
                {"data_size": len(json.dumps(data)), "encryption_type": "hybrid"}
            )
            
            return {
                "encrypted_data": encrypted_result,
                "category": category,
                "encrypted": True,
                "private_key": key_pair["private_key"]  # 实际应用中私钥不应返回，这里仅作演示
            }
        except Exception as e:
            self.audit_logger.log_operation(
                "数据加密", user, category, False,
                {"error": str(e)}
            )
            raise
    
    def decrypt_data(self, encrypted_data: Dict[str, Any], private_key: bytes, user: str) -> Any:
        """解密数据并记录审计日志"""
        category = encrypted_data["category"]
        
        try:
            decrypted_data = self.encryption_engine.hybrid_decrypt(
                encrypted_data["encrypted_data"], private_key
            )
            
            self.audit_logger.log_operation(
                "数据解密", user, category, True,
                {"data_size": len(decrypted_data)}
            )
            
            return json.loads(decrypted_data)
        except Exception as e:
            self.audit_logger.log_operation(
                "数据解密", user, category, False,
                {"error": str(e)}
            )
            raise


# 示例使用
if __name__ == "__main__":
    # 初始化系统
    encryption_system = DataEncryptionSystem()
    
    # 示例敏感数据
    sensitive_data = {
        "name": "张三",
        "id_number": "123456199001011234",
        "phone": "13800138000",
        "address": "北京市朝阳区..."
    }
    
    # 处理上下文
    context = {
        "source": "用户注册表单",
        "location": "北京",
        "application": "用户管理系统"
    }
    
    # 处理数据（加密）
    try:
        result = encryption_system.process_data(sensitive_data, context, "system")
        print("数据已加密并存储")
        
        # 模拟数据解密
        decrypted = encryption_system.decrypt_data(
            result, result["private_key"], "admin"
        )
        print("数据已成功解密")
        print(decrypted)
    except Exception as e:
        print(f"处理数据时出错: {e}")