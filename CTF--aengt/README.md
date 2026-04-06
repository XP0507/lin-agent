# CyberStrike-Agent

> 基于 LLM 的 **CTF 自动化解题 Agent** — 让 AI 帮你打 CTF

CyberStrike-Agent 是一个智能化的 CTF（Capture The Flag）解题框架，通过 ReAct 推理循环驱动大语言模型，自动完成 Web、Pwn、Crypto、Reverse、Misc、Forensics、OSINT、Malware 等全类型题目的分析与 Flag 提取。

## ✨ 核心特性

- **ReAct 推理引擎**：Thought → Action → Observation 循环，Agent 自主思考、执行、观察、迭代
- **全题型技能覆盖**：Web / Pwn / Crypto / Reverse / Misc / Forensics / OSINT / Malware
- **流式实时看板**（可选）：Rich Live 驱动的 50/50 分屏 TUI，实时展示思维流与终端输出
- **RAG 长期记忆**：基于 ChromaDB 的向量记忆系统，跨会话保留解题经验
- **MCP 工具扩展**：支持 MCP (Model Context Protocol) 外部工具集成
- **自动检查点**：任务中断后可从断点恢复，不丢失进度
- **超时熔断保护**：LLM 调用 45s 硬超时 + 上下文自动截断，防止死锁
- **常见坑点预警**：每个技能内置领域专家级避坑策略

## 🏗️ 架构

```
main.py                    # 入口 & CLI 交互
├── core/
│   ├── brain.py           # ReAct 大脑：推理/决策/上下文管理
│   ├── executor.py        # 命令执行器：Bash/Python/HTTP/File
│   ├── skills.py          # 技能管理器：8 类 CTF 题型策略
│   ├── tools.py           # 工具集：文件读写/网络请求/编码解码...
│   ├── memory.py          # RAG 向量记忆 (ChromaDB)
│   ├── monitor.py         # 执行监控 & Flag 检测
│   └── mcp_client.py      # MCP 客户端
├── config.py              # 全局配置 (dataclass)
├── .env.example           # 环境变量模板
└── requirements.txt       # Python 依赖
```

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置 LLM

复制环境变量模板并填入你的 API Key：

```bash
cp .env.example .env
```

编辑 `.env`：

```env
# DeepSeek (推荐，性价比高)
LLM_PROVIDER=openai
LLM_API_KEY=sk-xxxxxxxxxxxxxxxx
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_MODEL=deepseek-chat

# 或使用 OpenAI / 其他兼容接口
# LLM_MODEL=gpt-4o
# LLM_BASE_URL=https://api.openai.com/v1
```

### 3. 运行

**交互模式**（推荐）：

```bash
python main.py
```

**直接指定题目**：

```bash
python main.py -t "nc pwn.challenge.ctf.com 9001 上有一个栈溢出漏洞"
python main.py -t "http://web.challenge.ctf.com/admin 存在 SQL 注入"
```

**启用实时看板**：

```bash
python main.py --live
```

## 📖 使用指南

### 支持的命令

| 命令 | 说明 |
|------|------|
| `run <题目描述>` | 开始自动解题 |
| `chat <消息>` | 与 Agent 对话 |
| `status` | 查看当前状态 |
| `history` | 查看历史记录 |
| `clear` | 清空对话历史 |
| `help` | 显示帮助信息 |
| `quit` | 退出 |

### 技能体系

Agent 会根据题目特征自动选择对应技能：

| 技能 | 适用场景 | 内置工具 |
|------|---------|---------|
| **Web** | SQLi / XSS / SSRF / 文件上传 / SSTI | sqlmap, curl, Burp 思路 |
| **Pwn** | 栈溢出 / 堆利用 / 格式化字符串 | pwntools, gdb, ROP |
| **Crypto** | RSA / AES / ECC / 编码密码学 | z3, gmpy2, pycryptodome |
| **Reverse** | 逆向分析 / 混淆还原 | ghidra, r2, capstone |
| **Misc** | 隐写 / 编码 / 取证 / 杂项 | binwalk, steghide, strings |
| **Forensics** | 内存取证 / 流量分析 / 日志 | volatility, wireshark |
| **OSINT** | 信息搜集 / 地理定位 / 用户枚举 | whois, shodan, theHarvester |
| **Malware** | 恶意样本分析 / C2 追踪 | yara, pefile, sandbox |

### 配置参数

在 `config.py` 中调整核心参数：

```python
@dataclass
class ReActConfig:
    max_iterations: int = 50        # 最大推理轮数
    max_history_length: int = 20     # 历史对话保留轮数
    stop_on_flag: bool = True       # 发现 Flag 后自动停止
```

## 🔒 安全说明

- `.env` 文件包含 API 密钥，**已被 .gitignore 忽略**
- 沙箱模式 (`sandbox_mode=True`) 可限制危险命令执行
- 所有命令执行均有超时保护
- 建议在隔离环境中运行（Docker / VM）

## 📦 依赖清单

详见 [requirements.txt](requirements.txt)，核心依赖：

- `openai` / `langchain-openai` — LLM 接口
- `pwntools` — Pwn 题工具链
- `z3-solver` / `pycryptodome` — Crypto 数学求解
- `chromadb` — RAG 向量记忆
- `rich` — 终端 UI 美化
- `capstone` / `keystone-engine` — 反汇编/汇编引擎

## ⚠️ 免责声明

本项目仅供 **安全研究** 和 **CTF 竞赛学习** 使用。请勿用于非法用途。使用者需自行承担相关法律责任。

## License

MIT License
