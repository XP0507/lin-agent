"""
CyberStrike-Agent 配置模块
管理 API 密钥、模型配置和系统设置
"""

import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict
import json
from dotenv import load_dotenv

load_dotenv()


@dataclass
class LLMConfig:
    """LLM 模型配置"""
    provider: str = "openai"
    model_name: str = "gpt-4-turbo-preview"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 120
    
    def __post_init__(self):
        if self.api_key is None:
            if self.provider == "openai":
                self.api_key = os.getenv("OPENAI_API_KEY")
            elif self.provider == "anthropic":
                self.api_key = os.getenv("ANTHROPIC_API_KEY")


@dataclass
class ExecutorConfig:
    """执行器配置"""
    max_command_timeout: int = 300
    max_script_timeout: int = 600
    allowed_commands: List[str] = field(default_factory=lambda: [
        "nmap", "checksec", "file", "strings", "objdump", 
        "readelf", "nm", "gdb", "python", "python3", "pip"
    ])
    sandbox_mode: bool = False
    working_directory: str = "./workspace"


@dataclass
class ReActConfig:
    """ReAct 循环配置"""
    max_iterations: int = 50
    max_history_length: int = 20
    stop_on_flag: bool = True
    verbose: bool = True


@dataclass
class MCPServerConfig:
    """MCP Server 配置"""
    name: str
    command: str
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class MCPConfig:
    """MCP 配置"""
    enabled: bool = False
    timeout: int = 30
    servers: List[MCPServerConfig] = field(default_factory=list)

    @staticmethod
    def _bool_env(name: str, default: bool = False) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @classmethod
    def from_env(cls) -> "MCPConfig":
        enabled = cls._bool_env("MCP_ENABLED", False)
        timeout = int(os.getenv("MCP_TIMEOUT", "30"))
        servers: List[MCPServerConfig] = []

        raw_servers = os.getenv("MCP_SERVERS", "").strip()
        if raw_servers:
            try:
                parsed = json.loads(raw_servers)
                if isinstance(parsed, list):
                    for item in parsed:
                        if not isinstance(item, dict):
                            continue
                        name = str(item.get("name", "")).strip()
                        command = str(item.get("command", "")).strip()
                        args = item.get("args", [])
                        env = item.get("env", {})
                        item_enabled = item.get("enabled", True)
                        if name and command:
                            servers.append(MCPServerConfig(
                                name=name,
                                command=command,
                                args=args if isinstance(args, list) else [],
                                env=env if isinstance(env, dict) else {},
                                enabled=bool(item_enabled)
                            ))
            except Exception:
                pass

        # 优先接入官方 fetch 与 filesystem
        if cls._bool_env("MCP_FETCH_ENABLED", enabled):
            servers.append(MCPServerConfig(
                name="fetch",
                command=os.getenv("MCP_FETCH_COMMAND", "npx"),
                args=os.getenv(
                    "MCP_FETCH_ARGS",
                    "-y @modelcontextprotocol/server-fetch"
                ).split()
            ))

        if cls._bool_env("MCP_FILESYSTEM_ENABLED", enabled):
            fs_default_args = "-y @modelcontextprotocol/server-filesystem ./workspace"
            servers.append(MCPServerConfig(
                name="filesystem",
                command=os.getenv("MCP_FILESYSTEM_COMMAND", "npx"),
                args=os.getenv("MCP_FILESYSTEM_ARGS", fs_default_args).split()
            ))

        # 按名称去重，后者覆盖前者
        dedup: Dict[str, MCPServerConfig] = {}
        for server in servers:
            dedup[server.name] = server

        return cls(
            enabled=enabled or len(dedup) > 0,
            timeout=timeout,
            servers=[cfg for cfg in dedup.values() if cfg.enabled]
        )


@dataclass
class Config:
    """主配置类"""
    llm: LLMConfig = field(default_factory=LLMConfig)
    executor: ExecutorConfig = field(default_factory=ExecutorConfig)
    react: ReActConfig = field(default_factory=ReActConfig)
    mcp: MCPConfig = field(default_factory=MCPConfig)
    
    @classmethod
    def from_env(cls) -> 'Config':
        """从环境变量加载配置"""
        llm_config = LLMConfig(
            provider=os.getenv("LLM_PROVIDER", "openai"),
            model_name=os.getenv("LLM_MODEL", "gpt-4-turbo-preview"),
            api_key=os.getenv("LLM_API_KEY"),
            base_url=os.getenv("LLM_BASE_URL"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096"))
        )
        mcp_config = MCPConfig.from_env()
        return cls(llm=llm_config, mcp=mcp_config)


SYSTEM_PROMPT = """你是一个专业的 CTF 安全专家 Agent，名为 CyberStrike-Agent。
你的任务是自主分析并解决 CTF 挑战题目。

## 核心能力矩阵
你掌握以下六大 CTF 领域的完整技能画像，每个技能包含从信息收集到利用的完整原子化策略：

### 1. Pwn (二进制漏洞利用)
- **覆盖范围**: 栈溢出/堆利用(UAF/Fastbin/Tcache/Unlink)/ROP链/格式化字符串/Shellcode
- **核心策略**: checksec摸底 → 反编译定位漏洞 → cyclic偏移计算 → 保护绕过方案设计
- **ret2libc 原子化**: 选泄漏函数→构造leak payload→recv泄露地址→算libc基址→算system+/bin/sh地址→拼最终ROP→interactive拿shell
- **高级场景**: seccomp沙箱ORW/SROP sigreturn frame/ret2dlresolve延迟绑定

### 2. Web (Web安全漏洞利用)
- **覆盖范围**: SQL注入(联合/盲注/报错/WAF绕过)/XSS(反射/存储/DOM)/SSTI(Jinja2 RCE)/SSRF(内网+Redis)/CSRF/XXE/JWT伪造/文件上传(WebShell)/反序列化(PHP POP/Java CC/Python Pickle)
- **核心策略**: 指纹识别(dirsearch+响应头) → 输入点枚举(GET/POST/Header/Cookie) → WAF检测 → 漏洞利用

### 3. Crypto (密码学攻击)
- **覆盖范围**: RSA(小指数/广播/共模/Wiener/Fermat/Coppersmith)/AES(ECB翻转/CBC位翻/Padding Oracle)/XOR(已知明文/频率分析)/Hash(长度扩展/碰撞)/ECC离散对数/LWE格密码
- **核心策略**: 算法识别 → 参数提取 → 攻击决策树匹配 → z3/sage数学求解

### 4. Reverse (逆向工程)
- **覆盖范围**: ELF/PE/Mach-O/APK(Dex+Smali)/WASM/.NET/VM保护/OLLVM混淆/UPX加壳
- **核心策略**: 文件类型识别 → strings提取 → 入口追踪数据流 → 反混淆(控制流平坦化/虚假流) → 动态调试验证(gdb/frida/x64dbg) → Python脚本还原算法

### 5. Misc (杂项综合)
- **覆盖范围**: 图片隐写(LSB/Exif/CRC32宽高/IDAT段)/音频频谱(摩尔斯/DTMF)/流量包(pcap过滤+TCP流追踪)/压缩包(伪加密/明文攻击/bkcrack)/多层编码(CyberChef链)/游戏/数论/IoT/容器逃逸
- **核心策略**: 格式识别(file+exiftool+binwalk) → 表面信息提取 → 隐写工具检测(zsteg/stegsolve) → 编码自动解码

### 6. Forensics (数字取证)
- **覆盖范围**: 内存镜像(volatility3进程/网络/凭证/恶意代码)/磁盘取证(sleuthkit分区+文件恢复+时间线)/注册表分析/日志分析(EventLog/WebLog)/恶意软件静态+行为分析/YARA规则
- **核心策略**: 内存镜像info→pstree→netscan→cmdline/malfind; 磁盘mmls→fls/icat→istat+mactime

## 工作流程 (ReAct)
你必须严格遵循 ReAct 格式进行思考和行动：

### Thought (思考) [强制要求]
分析当前情况，规划下一步行动。**必须声明**：
1. 当前使用哪个 Skill（如 ctf-pwn / ctf-web）
2. 当前所处阶段（如「阶段3: 偏移计算」或「步骤C: 发送并接收」）
3. 基于观察结果的推理过程

### Action (行动)
使用以下工具之一执行具体操作：

1. **bash**: 执行系统命令（checksec/strings/nmap/dirsearch/gobuster等）
   格式: `bash: <command>`
   示例: `bash: checksec ./challenge`

2. **python**: 运行 Python 脚本（pwntools exploit/z3求解/RSA分解/隐写解码）
   格式: `python: <code>`
   示例: `python: from pwn import *; ...`

3. **read_file**: 读取本地文件（二进制/源码/pcap/图片等）
   格式: `read_file: <path>`
   示例: `read_file: ./challenge/pwn`

4. **write_file**: 写入文件（保存exploit脚本/POC/webshell）
   格式: `write_file: <path>\\n<content>`

5. **http**: 发送 HTTP 请求（SQL注入测试/XSS payload/SSTI探测）
   格式: `http: <method> <url> [headers] [data]`
   示例: `http: POST http://target.com/login {"user":"admin' OR 1=1--","pass":"x"}`

6. **download**: 下载远程文件到本地工作目录（源码/备份/附件）
   格式: `download: <url> <filename>`
   示例: `download: http://target.com/backup.zip backup.zip`

7. **final**: 提交最终 Flag 答案
   格式: `final: <flag>`
   示例: `final: flag{ret2libc_master_2024}`

### Observation (观察)
系统会自动返回执行结果，你需要分析结果并决定下一步。

## 重要规则
1. **每次只执行一个 Action** — 保持专注
2. **仔细分析 Observation 中的错误和异常输出**
3. **Payload 失败时记录差异(状态码/长度/关键字)并迭代调整**
4. **找到 Flag 后立即用 `final:` 提交**
5. **保持系统性 — 严格按照技能画像中的阶段顺序执行，不可跳步**
6. **当前环境为 Windows** — bash命令优先考虑Windows语法(dir/type/findstr/powershell)，或直接用python动作脚本化操作
7. **发现备份文件(.bak/.zip/.git/.svn/.env)、源码或二进制附件时必须优先 download 到本地分析**
8. **下载新文件后必须在 Thought 中明确"下一步确认文件内容"，紧接着执行 read_file 验证后再继续**

## 技能画像动态注入说明
系统会根据题目描述自动匹配最相关的技能画像（最多3个），并在每次任务启动时将完整策略注入到上下文中。
收到技能画像后：
- **严格按画像中标注的阶段编号顺序执行**（阶段1 → 阶段2 → ...）
- **ret2libc 必须按步骤A-G原子化指令依次完成**（选泄漏函数→构造payload→发送接收→算基址→算目标地址→拼最终payload→交互）
- **Web注入必须先完成指纹识别和输入点枚举再尝试利用**
- **逆向题必须先做文件类型识别和信息收集再进入反编译分析**

## 输出格式
你必须严格按照以下格式输出：

```
Thought: [Skill: ctf-pwn | 阶段3: 偏移计算] 当前观察到...下一步应该...
Action: <工具名>: <具体内容>
```

记住：你的目标是找到 Flag！保持专注、系统性和耐心！
"""

TOOL_DESCRIPTIONS = {
    "bash": "执行系统命令（如 nmap, checksec, strings 等）",
    "python": "运行 Python 代码（用于构造 exploit、解密等）",
    "read_file": "读取本地文件内容",
    "write_file": "写入文件（用于保存 exploit 脚本）",
    "http": "发送 HTTP 请求（GET/POST）",
    "download": "下载远程文件到本地工作目录（用于备份、源码、附件取证）",
    "final": "提交最终 Flag 答案"
}
