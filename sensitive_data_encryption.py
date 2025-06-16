import os #导入os模块，用于处理文件和目录路径
import json#导入json模块
import logging#导入logging模块，用于记录日志
from datetime import datetime, timedelta#导入datetime模块，用于处理日期和时间
from cryptography.hazmat.primitives.asymmetric import rsa, padding#导入rsa和padding模块，用于生成和验证RSA密钥
from cryptography.hazmat.primitives import serialization, hashes#导入serialization和hashes模块，用于序列化和哈希
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes#导入Cipher、algorithms和modes模块，用于加密和解密
from cryptography.hazmat.backends import default_backend#导入default_backend模块，用于指定默认的后端
from typing import Dict, Any, Optional, Union#导入Dict、Any、Optional和Union模块，用于类型提示

# 配置日志记录
# 配置日志系统，设置日志的基本属性
logging.basicConfig(
    # 设置日志级别为 INFO，意味着只记录 INFO 及以上级别的日志
    level=logging.INFO,
    # 定义日志的输出格式，包含时间、日志名称、日志级别和日志消息
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    # 定义日志处理器列表，将日志同时输出到文件和控制台
    handlers=[
        # 将日志写入名为 encryption_audit.log 的文件
        logging.FileHandler("encryption_audit.log"),
        # 将日志输出到控制台
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("DataEncryptionSystem")

# 定义数据分类分级模块的类
class DataClassifier:
    """数据分类分级模块"""
    
    # 类的构造函数，初始化时加载分类规则
    def __init__(self, classification_rules_path: str):
        # 调用 _load_rules 方法加载分类规则，并将结果存储在 self.rules 中
        self.rules = self._load_rules(classification_rules_path)
    
    # 私有方法，用于从指定路径加载分类规则文件
    def _load_rules(self, path: str) -> Dict[str, Any]:
        try:
            # 以只读模式打开文件，并指定编码为 utf-8
            with open(path, 'r', encoding='utf-8') as f:
                # 将文件内容解析为 JSON 格式并返回
                return json.load(f)
        except Exception as e:
            # 若加载失败，记录错误日志
            logger.error(f"加载分类规则失败: {e}")
            # 返回空字典
            return {}
    
    # 根据预定义规则对数据进行分类分级的方法
    def classify_data(self, data: Any, context: Dict[str, Any]) -> str:
        """根据预定义规则对数据进行分类分级"""
        # 实际实现需要基于具体业务规则
        # 遍历所有分类和对应的规则
        for category, rules in self.rules.items():
            # 调用 _check_rules 方法检查数据是否符合当前规则
            if self._check_rules(data, context, rules):
                # 若符合规则，返回对应的分类
                return category
        # 若所有规则都不满足，默认返回 '公开'
        return "公开"
    
    # 私有方法，用于检查数据是否符合特定分类规则
    def _check_rules(self, data: Any, context: Dict[str, Any], rules: Dict[str, Any]) -> bool:
        """检查数据是否符合特定分类规则"""
        # 从规则字典中获取规则描述
        rule = rules.get("rule")
        if rule == "包含身份证号或手机号":
            # 若规则是检查是否包含身份证号或手机号
            if isinstance(data, dict):
                # 将字典类型的数据转换为字符串
                data_str = str(data)
                # 导入正则表达式模块
                import re
                # 定义身份证号的正则表达式模式
                id_card_pattern = re.compile(r'\d{17}[\dXx]')#等价于字符类 [0-9]{17}[0-9Xx] {17个连续的数字最后是数字或X或x}
                # 检查数据中是否包含身份证号
                if id_card_pattern.search(data_str):
                    return True
                # 定义手机号的正则表达式模式
                phone_pattern = re.compile(r'1[3-9]\d{9}')#等价于字符类 [1][3-9][0-9]{9} {1开头，第二位是3-9，后面9位是0-9}
                # 检查数据中是否包含手机号
                if phone_pattern.search(data_str):
                    return True
        return False


class KeyManager:
    """密钥管理模块，负责主密钥和数据密钥的加载、生成、加密、解密以及轮换等操作。"""
    
    def __init__(self, key_storage_path: str):
        # 存储密钥的路径
        self.key_storage_path = key_storage_path
        # 加载或生成主密钥
        self.master_key = self._load_or_generate_master_key()
        # 密钥轮换间隔，默认为 30 天
        self.key_rotation_interval = timedelta(days=30)
        # 获取当前的数据密钥
        self.current_data_key = self._get_current_data_key()
    
    def _load_or_generate_master_key(self) -> bytes:
        """加载或生成主密钥。如果主密钥文件存在，则加载该文件；否则生成一个新的主密钥并保存到文件中。"""
        # 构建主密钥文件的路径
        master_key_path = os.path.join(self.key_storage_path, "master.key")
        if os.path.exists(master_key_path):
            # 如果主密钥文件存在，以二进制只读模式打开并读取内容
            with open(master_key_path, 'rb') as f:
                return f.read()
        else:
            # 如果主密钥文件不存在，创建存储密钥的目录
            os.makedirs(self.key_storage_path, exist_ok=True)
            # 生成一个 256 位的 AES 主密钥
            master_key = os.urandom(32)  # 256-bit AES key
            # 以二进制写入模式打开文件并保存主密钥
            with open(master_key_path, 'wb') as f:
                f.write(master_key)
            # 记录生成新主密钥的日志
            logger.info("生成新的主密钥")
            return master_key
    
    def _get_current_data_key(self) -> Dict[str, Any]:
        """获取当前数据密钥，必要时生成新密钥。如果数据密钥文件存在且未过期，则返回最新的密钥；否则生成一个新的密钥。"""
        # 构建数据密钥文件的路径
        data_keys_path = os.path.join(self.key_storage_path, "data_keys.json")
        if os.path.exists(data_keys_path):
            # 如果数据密钥文件存在，以只读模式打开并加载 JSON 数据
            with open(data_keys_path, 'r') as f:
                data_keys = json.load(f)
                # 获取最新的数据密钥
                latest_key = data_keys[-1]
                # 将创建时间字符串转换为 datetime 对象
                creation_time = datetime.fromisoformat(latest_key['creation_time'])
                # 检查密钥是否过期
                if datetime.now() - creation_time > self.key_rotation_interval:
                    return self._generate_new_data_key()
                return latest_key
        # 如果数据密钥文件不存在，生成一个新的数据密钥
        return self._generate_new_data_key()
    
    def _encrypt_key(self, key: bytes) -> Dict[str, bytes]:
        """使用主密钥加密数据密钥。使用 AES-GCM 算法进行加密。"""
        # 生成一个 12 字节的初始化向量 (IV)
        iv = os.urandom(12)  # 生成 IV
        # 创建一个 AES-GCM 加密器
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        # 执行加密操作
        encrypted_key = encryptor.update(key) + encryptor.finalize()
        return {
            # 加密后的密钥和认证标签
            "encrypted_key": encrypted_key + encryptor.tag,
            "iv": iv
        }
    
    def _generate_new_data_key(self) -> Dict[str, Any]:
        """生成新的数据密钥。生成一个新的 256 位 AES 数据密钥，使用主密钥加密后保存到数据密钥文件中。"""
        # 生成一个 256 位的 AES 数据密钥
        data_key = os.urandom(32)  # 256-bit AES key
        # 使用主密钥加密数据密钥
        encrypted_result = self._encrypt_key(data_key)
        
        # 构建新密钥的信息
        new_key = {
            # 以当前时间生成唯一的密钥 ID
            "key_id": datetime.now().strftime("%Y%m%d%H%M%S"),
            # 加密后的密钥转换为十六进制字符串
            "encrypted_key": encrypted_result["encrypted_key"].hex(),
            # 初始化向量转换为十六进制字符串
            "iv": encrypted_result["iv"].hex(),
            # 记录密钥的创建时间
            "creation_time": datetime.now().isoformat()
        }
        
        # 构建数据密钥文件的路径
        data_keys_path = os.path.join(self.key_storage_path, "data_keys.json")
        data_keys = []
        if os.path.exists(data_keys_path):
            # 如果数据密钥文件存在，以只读模式打开并加载 JSON 数据
            with open(data_keys_path, 'r') as f:
                data_keys = json.load(f)
        
        # 将新密钥添加到密钥列表中
        data_keys.append(new_key)
        # 以写入模式打开文件并保存更新后的密钥列表
        with open(data_keys_path, 'w') as f:
            json.dump(data_keys, f, indent=2)
        
        # 记录生成新数据密钥的日志
        logger.info(f"生成新的数据密钥: {new_key['key_id']}")
        return new_key
    
    def get_decrypted_data_key(self, key_id: Optional[str] = None) -> bytes:
        """获取解密后的数据密钥。根据指定的密钥 ID 解密数据密钥，如果未指定则使用当前密钥。"""
        if key_id is None:
            # 如果未指定密钥 ID，使用当前的数据密钥 ID
            key_id = self.current_data_key['key_id']
        
        # 构建数据密钥文件的路径
        data_keys_path = os.path.join(self.key_storage_path, "data_keys.json")
        if not os.path.exists(data_keys_path):
            # 如果数据密钥文件不存在，抛出异常
            raise ValueError("数据密钥不存在")
        
        # 以只读模式打开文件并加载 JSON 数据
        with open(data_keys_path, 'r') as f:
            data_keys = json.load(f)
        
        for key_data in data_keys:
            if key_data['key_id'] == key_id:
                # 将十六进制字符串转换为字节对象
                encrypted_key_with_tag = bytes.fromhex(key_data['encrypted_key'])
                # 提取认证标签
                tag = encrypted_key_with_tag[-16:]
                # 提取加密后的密钥
                encrypted_key = encrypted_key_with_tag[:-16]
                # 将十六进制字符串转换为字节对象作为初始化向量
                iv = bytes.fromhex(key_data["iv"])  # 获取存储的 IV
                
                # 创建一个 AES-GCM 解密器
                cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv, tag))
                decryptor = cipher.decryptor()
                # 执行解密操作并返回解密后的密钥
                return decryptor.update(encrypted_key) + decryptor.finalize()
        
        # 如果找不到指定的密钥 ID，抛出异常
        raise ValueError(f"找不到密钥 ID: {key_id}")


# 定义一个名为 EncryptionEngine 的类，该类作为加密引擎，用于实现混合加密功能
class EncryptionEngine:
    """加密引擎，实现混合加密"""
    
    # 类的构造函数，在创建 EncryptionEngine 类的实例时会被调用
    def __init__(self, key_manager: KeyManager):
        # 将传入的密钥管理器实例赋值给类的属性，方便后续方法使用
        self.key_manager = key_manager
        # 设置 RSA 密钥对的长度为 2048 位，这是一个常用的安全长度
        self.rsa_key_size = 2048
        # 设置 AES 加密算法使用的密钥长度为 256 位，提供较高的安全性
        self.aes_key_size = 256
    
    # 定义一个方法，用于生成 RSA 密钥对，返回一个包含私钥和公钥的字典
    def generate_rsa_key_pair(self) -> Dict[str, bytes]:
        """生成RSA密钥对"""
        # 使用 rsa 模块的 generate_private_key 函数生成一个 RSA 私钥
        # public_exponent 通常设置为 65537，是一个常用的公钥指数
        # key_size 由类属性 self.rsa_key_size 决定
        # backend 使用默认的加密后端
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=default_backend()
        )
        
        # 从生成的私钥中提取对应的公钥
        public_key = private_key.public_key()
        
        # 将私钥序列化为 PEM 格式的字节串，采用 PKCS8 格式，不进行加密
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # 将公钥序列化为 PEM 格式的字节串，采用 SubjectPublicKeyInfo 格式
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # 返回一个字典，包含私钥和公钥的 PEM 格式字节串
        return {
            "private_key": private_pem,
            "public_key": public_pem
        }
    
    # 定义一个方法，使用 RSA 公钥对数据进行加密
    def encrypt_with_rsa(self, data: bytes, public_key_pem: bytes) -> bytes:
        """使用RSA公钥加密数据"""
        # 从 PEM 格式的字节串中加载公钥
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=default_backend()
        )
        
        # 使用加载的公钥对数据进行加密，采用 OAEP 填充方式提高安全性
        # OAEP 填充结合了 MGF1 掩码生成函数和 SHA256 哈希算法
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted
    
    # 定义一个方法，使用 RSA 私钥对加密的数据进行解密
    def decrypt_with_rsa(self, encrypted_data: bytes, private_key_pem: bytes) -> bytes:
        """使用RSA私钥解密数据"""
        # 从 PEM 格式的字节串中加载私钥，由于私钥未加密，密码参数为 None
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        
        # 使用加载的私钥对加密数据进行解密，采用与加密相同的 OAEP 填充方式
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
        # 如果输入数据是字符串类型，将其编码为UTF-8字节流
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 从密钥管理器获取解密后的数据密钥
        data_key = self.key_manager.get_decrypted_data_key(key_id)
        # 生成一个12字节的随机初始化向量（IV），AES-GCM推荐使用12字节的IV
        iv = os.urandom(12)
        
        # 创建一个AES-GCM模式的加密器
        cipher = Cipher(algorithms.AES(data_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        # 执行加密操作
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        
        return {
            "ciphertext": encrypted_data,  # 加密后的数据
            "iv": iv,  # 初始化向量
            "tag": encryptor.tag,  # 认证标签，用于验证数据完整性
            "key_id": key_id or self.key_manager.current_data_key['key_id']  # 密钥ID
        }
    
    def decrypt_with_aes(self, encrypted_data: Dict[str, bytes]) -> bytes:
        """使用AES解密数据"""
        # 从输入字典中提取加密数据、初始化向量、认证标签和密钥ID
        ciphertext = encrypted_data["ciphertext"]
        iv = encrypted_data["iv"]
        tag = encrypted_data["tag"]
        key_id = encrypted_data.get("key_id")
        
        # 从密钥管理器获取解密后的数据密钥
        data_key = self.key_manager.get_decrypted_data_key(key_id)
        
        # 创建一个AES-GCM模式的解密器
        cipher = Cipher(algorithms.AES(data_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        # 执行解密操作
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def hybrid_encrypt(self, data: Union[str, bytes], recipient_public_key: bytes) -> Dict[str, bytes]:
        """混合加密：使用AES加密数据，使用RSA加密AES密钥"""
        # 首先使用AES对数据进行加密
        aes_encrypted = self.encrypt_with_aes(data)
        # 然后使用RSA公钥对AES密钥ID进行加密
        encrypted_key = self.encrypt_with_rsa(
            aes_encrypted["key_id"].encode('utf-8'), 
            recipient_public_key
        )
        
        return {
            "encrypted_data": aes_encrypted["ciphertext"],  # AES加密后的数据
            "iv": aes_encrypted["iv"],  # AES的初始化向量
            "tag": aes_encrypted["tag"],  # AES的认证标签
            "encrypted_key": encrypted_key  # RSA加密后的AES密钥ID
        }
    
    def hybrid_decrypt(self, encrypted_data: Dict[str, bytes], private_key: bytes) -> bytes:
        """混合解密：使用RSA解密AES密钥，使用AES解密数据"""
        # 首先使用RSA私钥解密AES密钥ID
        decrypted_key_id = self.decrypt_with_rsa(
            encrypted_data["encrypted_key"], 
            private_key
        ).decode('utf-8')
        
        # 构建AES解密所需的数据字典
        aes_data = {
            "ciphertext": encrypted_data["encrypted_data"],
            "iv": encrypted_data["iv"],
            "tag": encrypted_data["tag"],
            "key_id": decrypted_key_id
        }
        
        # 使用AES解密数据
        return self.decrypt_with_aes(aes_data)


class AuditLogger:
    """审计日志与异常检测模块
    该类负责记录操作审计日志，并根据预定义的规则检测异常行为。
    """
    
    def __init__(self, audit_log_path: str):
        """初始化审计日志记录器

        Args:
            audit_log_path (str): 审计日志文件的路径。
        """
        # 保存审计日志文件的路径
        self.audit_log_path = audit_log_path
        # 加载异常检测规则
        self.anomaly_rules = self._load_anomaly_rules()
        # 存储可疑活动的列表
        self.suspicious_activities = []
    
    def _load_anomaly_rules(self) -> Dict[str, Any]:
        """加载异常检测规则

        尝试从 `anomaly_rules.json` 文件中加载异常检测规则，如果文件不存在或读取失败，则使用默认规则。

        Returns:
            Dict[str, Any]: 包含异常检测规则的字典。
        """
        try:
            # 尝试打开并读取异常检测规则文件
            with open("anomaly_rules.json", 'r') as f:
                return json.load(f)
        except Exception:
            # 如果读取失败，返回默认的异常检测规则
            return {
                "frequent_access_threshold": 100,  # 单位时间内的频繁访问阈值
                "unusual_time_threshold": 2,       # 异常时间访问阈值
                "failed_attempts_threshold": 5     # 失败尝试阈值
            }
    
    def log_operation(self, operation: str, user: str, data_category: str, success: bool, details: Dict[str, Any] = None):
        """记录操作审计日志

        将操作信息记录到审计日志文件中，并检查该操作是否存在异常行为。

        Args:
            operation (str): 执行的操作名称。
            user (str): 执行操作的用户。
            data_category (str): 操作涉及的数据类别。
            success (bool): 操作是否成功。
            details (Dict[str, Any], optional): 操作的详细信息。默认为 None。
        """
        # 构建日志条目
        log_entry = {
            "timestamp": datetime.now().isoformat(),  # 操作时间戳
            "operation": operation,  # 操作名称
            "user": user,  # 执行操作的用户
            "data_category": data_category,  # 数据类别
            "success": success,  # 操作是否成功
            "details": details or {}  # 操作详细信息
        }
        
        # 将日志条目写入文件
        self._write_log_entry(log_entry)
        # 检查该操作是否存在异常行为
        self._check_anomaly(log_entry)
    
    def _write_log_entry(self, entry: Dict[str, Any]):
        """写入日志条目

        将日志条目以 JSON 格式追加到审计日志文件中。

        Args:
            entry (Dict[str, Any]): 要写入的日志条目。
        """
        with open(self.audit_log_path, 'a') as f:
            # 将日志条目转换为 JSON 字符串并追加到文件中，每行一个条目
            f.write(json.dumps(entry) + '\n')
    
    def _check_anomaly(self, entry: Dict[str, Any]):
        """检查是否存在异常行为

        根据日志条目检查是否存在异常行为，目前仅检查操作失败的情况。

        Args:
            entry (Dict[str, Any]): 要检查的日志条目。
        """
        # 如果操作失败，检查用户的失败尝试次数
        if not entry["success"]:
            self._check_failed_attempts(entry["user"])
        
        # 可以添加更多异常检测逻辑
    
    def _check_failed_attempts(self, user: str):
        """检查用户失败尝试次数

        统计用户最近的失败尝试次数，如果超过阈值，则记录警告日志。

        Args:
            user (str): 要检查的用户。
        """
        # 筛选出指定用户的最近失败尝试记录
        recent_fails = [
            e for e in self.suspicious_activities 
            if e["user"] == user and not e["success"]
        ]
        
        # 如果失败尝试次数超过阈值
        if len(recent_fails) >= self.anomaly_rules["failed_attempts_threshold"]:
            # 记录警告日志，提示可能存在暴力破解风险
            logger.warning(f"用户 {user} 多次尝试失败，可能存在暴力破解风险")
            # 可以触发警报或采取其他措施


class DataEncryptionSystem:
    """敏感数据加密系统主类
    该类作为敏感数据加密系统的核心，负责加载配置、分类数据、加密和解密数据，并记录审计日志。
    """
    
    def __init__(self, config_path: str = "encryption_config.json"):
        """初始化敏感数据加密系统

        Args:
            config_path (str, optional): 配置文件的路径。默认为 "encryption_config.json"。
        """
        # 加载系统配置
        self.config = self._load_config(config_path)
        # 初始化数据分类器
        self.classifier = DataClassifier(self.config["classification_rules_path"])
        # 初始化密钥管理器
        self.key_manager = KeyManager(self.config["key_storage_path"])
        # 初始化加密引擎
        self.encryption_engine = EncryptionEngine(self.key_manager)
        # 初始化审计日志记录器
        self.audit_logger = AuditLogger(self.config["audit_log_path"])
    
    def _load_config(self, path: str) -> Dict[str, Any]:
        """加载系统配置

        尝试从指定路径加载配置文件，如果文件不存在或读取失败，则使用默认配置。

        Args:
            path (str): 配置文件的路径。

        Returns:
            Dict[str, Any]: 包含系统配置的字典。
        """
        try:
            # 打开配置文件并加载 JSON 数据
            with open(path, 'r') as f:
                return json.load(f)
        except Exception:
            # 如果读取失败，返回默认配置
            return {
                "classification_rules_path": "classification_rules.json",
                "key_storage_path": "./keys",
                "audit_log_path": "encryption_audit.log",
                "anomaly_rules_path": "anomaly_rules.json"
            }
    
    def process_data(self, data: Any, context: Dict[str, Any], user: str) -> Dict[str, Any]:
        """处理数据：分类、加密并记录审计日志

        对输入的数据进行分类，根据分类结果决定是否加密，并记录审计日志。

        Args:
            data (Any): 要处理的数据。
            context (Dict[str, Any]): 数据的上下文信息。
            user (str): 执行操作的用户。

        Returns:
            Dict[str, Any]: 包含处理结果的字典。
        """
        # 对数据进行分类
        category = self.classifier.classify_data(data, context)
        # 记录数据分类信息
        logger.info(f"数据分类为: {category}")
        
        # 如果数据类别为公开，则无需加密
        if category == "公开":
            # 记录审计日志
            self.audit_logger.log_operation(
                "数据处理", user, category, True, 
                {"reason": "数据为公开类型，无需加密"}
            )
            return {"data": data, "category": category, "encrypted": False}
        
        try:
            # 对于敏感数据，增强加密逻辑
            if category == "敏感":
                # 记录使用增强加密策略的信息
                logger.info("检测到敏感数据，使用增强加密策略")
                # 可以在这里添加更复杂的加密逻辑，例如增加加密算法的迭代次数
            
            # 生成RSA密钥对（实际应用中应该预先生成并安全存储）
            key_pair = self.encryption_engine.generate_rsa_key_pair()
            
            # 使用混合加密
            encrypted_result = self.encryption_engine.hybrid_encrypt(
                json.dumps(data), key_pair["public_key"]
            )
            
            # 增强审计日志，记录更详细的信息
            detailed_info = {
                "data_size": len(json.dumps(data)),
                "encryption_type": "hybrid",
                "source": context.get("source"),
                "location": context.get("location"),
                "application": context.get("application")
            }
            
            # 记录加密操作的审计日志
            self.audit_logger.log_operation(
                "数据加密", user, category, True,
                detailed_info
            )
            
            return {
                "encrypted_data": encrypted_result, # 加密后的数据
                "category": category, # 数据类别
                "encrypted": True, # 数据是否已加密
                "private_key": key_pair["private_key"]  # 实际应用中私钥不应返回，这里仅作演示
            }
        except Exception as e:
            # 记录加密失败的审计日志
            self.audit_logger.log_operation(
                "数据加密", user, category, False,
                {"error": str(e)}
            )
            # 重新抛出异常，让调用者处理
            raise
    
    def decrypt_data(self, encrypted_data: Dict[str, Any], private_key: bytes, user: str) -> Any:
        """解密数据并记录审计日志

        对加密的数据进行解密，并记录审计日志。

        Args:
            encrypted_data (Dict[str, Any]): 包含加密数据的字典。
            private_key (bytes): 用于解密的私钥。
            user (str): 执行操作的用户。

        Returns:
            Any: 解密后的数据。
        """
        # 获取数据类别
        category = encrypted_data["category"]
        
        try:
            # 使用混合解密方法解密数据
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
        
        # 确保正确传递参数
        decrypted = encryption_system.decrypt_data(
            {
                "encrypted_data": result["encrypted_data"], #加密数据
                "category": result["category"]#是否为敏感数据
            }, 
            result["private_key"], 
            "admin"
        )
        print("数据已成功解密")
        print(decrypted)
    except Exception as e:
        import traceback
        print(f"处理数据时出错: {e}")
        traceback.print_exc()


# 假设已经有 DataEncryptionSystem 实例 encryption_system
# 包含姓名、身份证号、手机号和地址的多组敏感数据列表
sensitive_data_list = [
    {
        'data': {
            '姓名': '张三',
            '身份证号': '11010519491231002X',
            '手机号': '13800138000',
            '地址': '北京市朝阳区建国路 1 号'
        },
        'context': {'source': '用户注册表单'}
    },
    {
        'data': {
            '姓名': '李四',
            '身份证号': '0',
            '手机号': '0',
            '地址': '深圳市南山区科技园科苑路 2 号'
        },
        'context': {'source': '用户注册表单'}
    }
]

# 用于存储加密结果的列表
encrypted_results = []

# 遍历多组数据并加密
for data_info in sensitive_data_list:
    sensitive_data = data_info['data']
    context = data_info['context']
    try:
        result = encryption_system.process_data(sensitive_data, context, "system")
        encrypted_results.append(result)#添加到列表中
        logger.info(f"成功加密数据: {sensitive_data}")
    except Exception as e:
        logger.error(f"加密数据 {sensitive_data} 时出错: {e}")

# 打印加密结果
#for result in encrypted_results:
#    print("加密后的数据:", result)  