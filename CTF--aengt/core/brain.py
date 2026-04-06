"""
CyberStrike-Agent Brain Module
LLM 大脑模块 - 负责推理和决策
"""

import re
import json
from typing import Optional, Dict, Any, Tuple, List
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from pathlib import Path
from datetime import datetime

try:
    from langchain_openai import ChatOpenAI
    from langchain_anthropic import ChatAnthropic
    from langchain_core.messages import HumanMessage, SystemMessage, AIMessage
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False

from config import Config, LLMConfig, SYSTEM_PROMPT
from core.skills import SkillManager, SkillProfile
from core.mcp_client import MCPClientManager, MCPToolDescriptor

try:
    from core.memory import get_memory
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False


@dataclass
class ReActOutput:
    """ReAct 输出结构"""
    thought: str
    action: str
    action_input: str
    raw_response: str
    is_final: bool = False
    flag: Optional[str] = None


@dataclass
class ConversationTurn:
    """对话轮次"""
    thought: str
    action: str
    action_input: str
    observation: str


class LLMProvider(ABC):
    """LLM 提供者抽象基类"""
    
    @abstractmethod
    def invoke(self, messages: List[Dict]) -> str:
        pass


class OpenAIProvider(LLMProvider):
    """OpenAI 提供者"""
    
    def __init__(self, config: LLMConfig):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain 未安装，请运行: pip install langchain langchain-openai")
        
        self.llm = ChatOpenAI(
            model=config.model_name,
            api_key=config.api_key,
            base_url=config.base_url,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=config.timeout
        )
    
    def invoke(self, messages: List[Dict]) -> str:
        lc_messages = []
        for msg in messages:
            if msg["role"] == "system":
                lc_messages.append(SystemMessage(content=msg["content"]))
            elif msg["role"] == "user":
                lc_messages.append(HumanMessage(content=msg["content"]))
            elif msg["role"] == "assistant":
                lc_messages.append(AIMessage(content=msg["content"]))
        
        response = self.llm.invoke(lc_messages)
        return response.content


class AnthropicProvider(LLMProvider):
    """Anthropic Claude 提供者"""
    
    def __init__(self, config: LLMConfig):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("LangChain 未安装，请运行: pip install langchain langchain-anthropic")
        
        self.llm = ChatAnthropic(
            model=config.model_name,
            api_key=config.api_key,
            temperature=config.temperature,
            max_tokens=config.max_tokens,
            timeout=config.timeout
        )
    
    def invoke(self, messages: List[Dict]) -> str:
        lc_messages = []
        for msg in messages:
            if msg["role"] == "system":
                lc_messages.append(SystemMessage(content=msg["content"]))
            elif msg["role"] == "user":
                lc_messages.append(HumanMessage(content=msg["content"]))
            elif msg["role"] == "assistant":
                lc_messages.append(AIMessage(content=msg["content"]))
        
        response = self.llm.invoke(lc_messages)
        return response.content


class SimpleOpenAIProvider(LLMProvider):
    """简单 OpenAI 提供者（不依赖 LangChain）"""

    _STREAM_TIMEOUT = 45

    def __init__(self, config: LLMConfig):
        import openai
        import httpx
        self.client = openai.OpenAI(
            api_key=config.api_key,
            base_url=config.base_url,
            timeout=httpx.Timeout(
                connect=10.0,
                read=self._STREAM_TIMEOUT,
                write=30.0,
                pool=10.0,
            ),
        )
        self.config = config
    
    def invoke(self, messages: List[Dict]) -> str:
        response = self.client.chat.completions.create(
            model=self.config.model_name,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens
        )
        return response.choices[0].message.content
    
    def stream_invoke(self, messages: List[Dict]):
        """
        流式调用 LLM，逐 chunk yield (delta_text, is_finished)
        
        内置 45 秒硬超时：若 API 在此时间内无任何数据返回，
        抛出 TimeoutError 由上层 think_stream 捕获并转换为友好错误。
        
        Yields:
            (str, bool): (文本片段, 是否结束)
        """
        import httpx
        try:
            stream = self.client.chat.completions.create(
                model=self.config.model_name,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                stream=True
            )
            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta and delta.content:
                    yield (delta.content, False)
            yield ("", True)
        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.PoolTimeout) as e:
            raise TimeoutError(
                f"LLM API 请求超时 ({self._STREAM_TIMEOUT}s 无响应)，"
                f"可能原因: 中转API挂起/网络抖动/上下文过长 → {type(e).__name__}: {e}"
            ) from e
        except (httpx.RemoteProtocolError, httpx.ReadError) as e:
            raise ConnectionError(
                f"LLM API 连接中断: {type(e).__name__} - {e}"
            ) from e


class Brain:
    """
    Agent 大脑 - 负责推理和决策
    
    核心功能：
    1. 维护系统提示词和对话历史
    2. 调用 LLM 进行推理
    3. 解析 ReAct 格式输出
    4. 管理上下文窗口
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.llm_config = config.llm
        self.react_config = config.react
        self.skill_manager = SkillManager()
        self.active_skills: List[SkillProfile] = []
        self.last_unknown_skills: List[str] = []
        self.checkpoint_path = Path("checkpoint.json")
        self.loaded_checkpoint: Optional[Dict[str, Any]] = None
        self.mcp_manager = MCPClientManager(config.mcp)
        self.mcp_tools: List[MCPToolDescriptor] = []
        self.mcp_errors: List[str] = []
        
        self._init_llm_provider()
        
        self.messages: List[Dict] = []
        self.chat_messages: List[Dict] = []
        self.history: List[ConversationTurn] = []
        
        self._init_system_prompt()
        self._init_chat_prompt()
        self._try_resume_from_checkpoint()
    
    def _init_llm_provider(self):
        """初始化 LLM 提供者"""
        provider = self.llm_config.provider.lower()
        
        if provider == "openai":
            try:
                self.llm = OpenAIProvider(self.llm_config)
            except ImportError:
                self.llm = SimpleOpenAIProvider(self.llm_config)
        elif provider == "anthropic":
            self.llm = AnthropicProvider(self.llm_config)
        else:
            raise ValueError(f"不支持的 LLM 提供者: {provider}")
    
    def _init_system_prompt(self):
        """初始化系统提示词"""
        self._load_mcp_tools()
        mcp_prompt = self._build_mcp_tools_prompt()
        system_content = SYSTEM_PROMPT
        if mcp_prompt:
            system_content += "\n\n" + mcp_prompt

        self.messages.append({
            "role": "system",
            "content": system_content
        })

    def _load_mcp_tools(self):
        """加载 MCP Tools 列表"""
        tools, errors = self.mcp_manager.list_tools()
        self.mcp_tools = tools
        self.mcp_errors = errors

    def _build_mcp_tools_prompt(self) -> str:
        """将 MCP Tools 注入系统提示词"""
        if not self.mcp_tools and not self.mcp_errors:
            return ""

        lines = [
            "## MCP Tools（动态加载）",
            "你可以通过 `Action: mcp: <server>/<tool>(<json_args>)` 调用 MCP 工具。",
            "示例: `Action: mcp: fetch/fetch({\"url\":\"https://example.com\"})`",
            "",
        ]

        if self.mcp_tools:
            lines.append("### 可用 MCP 工具")
            for t in self.mcp_tools:
                lines.append(f"- {t.server}/{t.name}: {t.description}")
            lines.append("")

        if self.mcp_errors:
            lines.append("### MCP 连接告警")
            for err in self.mcp_errors:
                lines.append(f"- {err}")

        return "\n".join(lines)

    def _init_chat_prompt(self):
        """初始化预对话提示词（非 ReAct）"""
        self.chat_messages = [{
            "role": "system",
            "content": (
                "你是 CyberStrike-Agent 的预对话助手。"
                "你的目标是在正式解题前，帮助用户澄清题目目标、环境、已知信息与限制条件。"
                "请使用简体中文，回答简洁清晰。"
            )
        }]

    def _try_resume_from_checkpoint(self):
        """检测并注入 checkpoint 恢复上下文"""
        if not self.checkpoint_path.exists():
            return

        try:
            data = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
        except Exception:
            return

        resume_state = data.get("resume_state", {})
        libc_base = resume_state.get("libc_base")
        known_gadgets = resume_state.get("known_gadgets", [])
        current_strategy = resume_state.get("current_strategy", "")
        checkpoint_time = data.get("created_at", "unknown")

        self.loaded_checkpoint = data

        lines = [
            "## Initial Context (Auto Resume)",
            f"- checkpoint 时间: {checkpoint_time}",
            f"- libc 基址: {libc_base or 'unknown'}",
            f"- 已知 Gadgets 地址: {', '.join(known_gadgets) if known_gadgets else 'none'}",
            f"- 当前利用策略: {current_strategy or 'unknown'}",
            "",
            "请在后续思考中优先复用以上状态，避免重复枚举。若状态无效，请明确说明并更新策略。"
        ]
        self.messages.append({
            "role": "system",
            "content": "\n".join(lines)
        })
    
    def set_task(
        self,
        task_description: str,
        context: Optional[str] = None,
        forced_skills: Optional[List[str]] = None
    ):
        """
        设置任务描述
        
        Args:
            task_description: CTF 题目描述
            context: 额外上下文信息（如目标 URL、文件路径等）
        """
        ctx = context or ""
        self.last_unknown_skills = []

        if forced_skills:
            forced_profiles, unknown = self.skill_manager.get_skills_by_names(forced_skills)
            self.last_unknown_skills = unknown
            self.active_skills = forced_profiles
        else:
            self.active_skills = self.skill_manager.detect_skills(task_description, ctx)

        skill_prompt = self.skill_manager.render_skill_prompt(self.active_skills)
        if skill_prompt:
            self.messages.append({
                "role": "system",
                "content": skill_prompt
            })

        if self.last_unknown_skills:
            self.messages.append({
                "role": "system",
                "content": (
                    "提示：以下手动指定技能不存在，已忽略："
                    + ", ".join(self.last_unknown_skills)
                )
            })

        if MEMORY_AVAILABLE:
            try:
                memory = get_memory()
                memory_context = memory.get_context_for_task(task_description)
                if memory_context:
                    self.messages.append({
                        "role": "system",
                        "content": f"## 记忆库参考\n\n以下是记忆库中相似案例和相关知识点，供参考：\n\n{memory_context}"
                    })
                    print(f"[Memory] 📚 已注入记忆库参考信息")
            except Exception as e:
                print(f"[Memory] 检索记忆失败: {e}")

        user_message = f"## 任务描述\n{task_description}\n"
        if context:
            user_message += f"\n## 上下文信息\n{context}\n"
        user_message += "\n请开始分析并解决问题。"
        
        self.messages.append({
            "role": "user",
            "content": user_message
        })
    
    def think(self, observation: Optional[str] = None) -> ReActOutput:
        """
        执行一轮思考
        
        Args:
            observation: 上一轮的观察结果
            
        Returns:
            ReActOutput: 解析后的输出
        """
        if observation:
            self.messages.append({
                "role": "user",
                "content": f"Observation:\n{observation}"
            })
        
        try:
            response = self.llm.invoke(self.messages)
            
            self.messages.append({
                "role": "assistant",
                "content": response
            })
            
            return self._parse_response(response)
            
        except Exception as e:
            error_msg = f"LLM 调用失败: {str(e)}"
            return ReActOutput(
                thought=error_msg,
                action="error",
                action_input=str(e),
                raw_response="",
                is_final=False
            )
    
    _MAX_OBSERVATION_CHARS = 1000
    _OBS_HEAD_TAIL = 300

    def think_stream(self, observation: Optional[str] = None):
        """
        流式执行一轮思考，实时 yield Thought 片段和最终 ReActOutput
        
        内置保护机制:
        - 上下文截断: 单次 observation > 3000 字符时自动首尾截断
        - 超时熔断: LLM API 45s 无响应自动 TimeoutError → 友好 error yield
        - 网络中断: 连接断开/协议错误 → ConnectionError → 友好 error yield
        
        Yields:
            (str, str, Optional[ReActOutput]): (event_type, content, output)
            event_type: "thought_chunk" | "thought_done" | "error"
            - thought_chunk: content=当前文本片段
            - thought_done:  content=完整Thought文本,  output=ReActOutput
            - error:         content=错误信息,           output=None
        """
        if observation:
            observation = self._truncate_observation(observation)
            self.messages.append({
                "role": "user",
                "content": f"Observation:\n{observation}"
            })
        
        if not hasattr(self.llm, 'stream_invoke'):
            try:
                response = self.llm.invoke(self.messages)
            except TimeoutError as e:
                yield ("error", f"[API 思考超时] LLM 在规定时间内无响应，已触发熔断。{e}", None)
                return
            except Exception as e:
                yield ("error", f"[LLM 调用失败] {type(e).__name__}: {e}", None)
                return

            self.messages.append({"role": "assistant", "content": response})
            output = self._parse_response(response)
            yield ("thought_done", response, output)
            return
        
        try:
            full_response = ""
            for delta_text, is_finished in self.llm.stream_invoke(self.messages):
                if is_finished:
                    break
                full_response += delta_text
                yield ("thought_chunk", delta_text, None)
            
            self.messages.append({
                "role": "assistant",
                "content": full_response
            })
            
            output = self._parse_response(full_response)
            yield ("thought_done", full_response, output)
            
        except TimeoutError as e:
            yield ("error",
                   f"[API 思考超时] LLM 流式请求在 {SimpleOpenAIProvider._STREAM_TIMEOUT}s 内无任何数据返回。"
                   f"已自动熔断，本轮将跳过（不消耗迭代次数建议）。"
                   f"\n原因: {e}",
                   None)
        except ConnectionError as e:
            yield ("error",
                   f"[API 连接中断] 与 LLM 服务器的连接异常断开。\n"
                   f"详情: {e}",
                   None)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            exc_type = type(e).__name__
            yield ("error",
                   f"[LLM 流式调用异常] {exc_type}: {str(e)}\n"
                   f"建议检查: API Key / Base URL / 网络连通性 / 模型名称是否正确",
                   None)

    @staticmethod
    def _truncate_observation(observation: str) -> str:
        if len(observation) <= Brain._MAX_OBSERVATION_CHARS:
            return observation
        head = observation[:Brain._OBS_HEAD_TAIL]
        tail = observation[-Brain._OBS_HEAD_TAIL:]
        omitted = len(observation) - Brain._OBS_HEAD_TAIL * 2
        return (
            f"{head}\n\n"
            f"... [已截断 {omitted} 字符，原始输出过长可能导致 LLM 响应缓慢或超时] ...\n\n"
            f"{tail}"
        )

    def chat(self, user_input: str) -> str:
        """预对话模式：与用户聊天，不走 ReAct 解析"""
        self.chat_messages.append({
            "role": "user",
            "content": user_input
        })

        response = self.llm.invoke(self.chat_messages)
        self.chat_messages.append({
            "role": "assistant",
            "content": response
        })
        return response

    def _collect_resume_corpus(self) -> str:
        """汇总可用于恢复提取的文本语料"""
        chunks: List[str] = []
        for msg in self.messages:
            chunks.append(msg.get("content", ""))
        for turn in self.history:
            chunks.append(turn.thought or "")
            chunks.append(turn.action or "")
            chunks.append(turn.action_input or "")
            chunks.append(turn.observation or "")
        return "\n".join(chunks)

    def _extract_libc_base(self, corpus: str) -> Optional[str]:
        """提取 libc 基址"""
        patterns = [
            r'libc[^\\n]{0,60}?base[^\\n]{0,20}?(0x[0-9a-fA-F]+)',
            r'libc[^\\n]{0,60}?(0x[0-9a-fA-F]+)',
            r'(0x[0-9a-fA-F]+)[^\\n]{0,40}?libc'
        ]
        for pattern in patterns:
            matches = re.findall(pattern, corpus, flags=re.IGNORECASE)
            if matches:
                return matches[-1]
        return None

    def _extract_known_gadgets(self, corpus: str) -> List[str]:
        """提取已知 gadgets 地址"""
        gadget_keywords = ("gadget", "rop", "pop", "ret", "syscall")
        gadget_addrs: List[str] = []

        for line in corpus.splitlines():
            low = line.lower()
            if any(key in low for key in gadget_keywords):
                addrs = re.findall(r'0x[0-9a-fA-F]{6,16}', line)
                gadget_addrs.extend(addrs)

        if not gadget_addrs:
            # 兜底：当未显式出现 gadget 关键词时，保留少量高置信地址
            gadget_addrs = re.findall(r'0x[0-9a-fA-F]{8,16}', corpus)

        deduped: List[str] = []
        seen = set()
        for addr in gadget_addrs:
            if addr not in seen:
                seen.add(addr)
                deduped.append(addr)
        return deduped[:20]

    def _extract_current_strategy(self) -> str:
        """提取当前利用策略摘要"""
        if not self.history:
            return "暂无明确策略，建议从信息收集与漏洞面确认开始。"

        recent_turns = self.history[-5:]
        lines = []
        for i, turn in enumerate(recent_turns, 1):
            thought = (turn.thought or "").strip().replace("\n", " ")
            action = (turn.action or "").strip()
            action_input = (turn.action_input or "").strip().replace("\n", " ")
            if len(thought) > 120:
                thought = thought[:120] + "..."
            if len(action_input) > 80:
                action_input = action_input[:80] + "..."
            lines.append(f"[{i}] thought={thought} | action={action} | input={action_input}")
        return " -> ".join(lines)

    def save_checkpoint(self, reason: str = "max_iterations") -> Optional[Path]:
        """保存 auto-resume checkpoint"""
        try:
            corpus = self._collect_resume_corpus()
            resume_state = {
                "libc_base": self._extract_libc_base(corpus),
                "known_gadgets": self._extract_known_gadgets(corpus),
                "current_strategy": self._extract_current_strategy()
            }

            payload = {
                "version": 1,
                "created_at": datetime.now().isoformat(),
                "reason": reason,
                "resume_state": resume_state,
                "meta": {
                    "history_turns": len(self.history),
                    "message_count": len(self.messages)
                }
            }

            self.checkpoint_path.write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            return self.checkpoint_path
        except Exception:
            return None
    
    def _parse_response(self, response: str) -> ReActOutput:
        """
        解析 LLM 响应
        
        支持的格式：
        1. Thought: ... Action: tool: input
        2. 直接的 tool: input 格式
        3. final: flag 格式
        """
        thought = ""
        action = ""
        action_input = ""
        is_final = False
        flag = None
        
        thought_match = re.search(r'Thought:\s*(.+?)(?=Action:|$)', response, re.DOTALL | re.IGNORECASE)
        if thought_match:
            thought = thought_match.group(1).strip()
        
        # 解析 Action，优先按行匹配，兼容 download: <url> <filename> 等包含空格的输入
        lines = response.splitlines()
        for line in lines:
            match = re.match(r'^\s*Action:\s*([a-zA-Z_]\w*)\s*:\s*(.+?)\s*$', line)
            if match:
                action = match.group(1).strip().lower()
                action_input = match.group(2).strip()
                break

        if not action:
            for line in lines:
                direct_action = re.match(r'^\s*([a-zA-Z_]\w*)\s*:\s*(.+?)\s*$', line)
                if direct_action:
                    action = direct_action.group(1).strip().lower()
                    action_input = direct_action.group(2).strip()
                    break
        
        if action == "final":
            is_final = True
            flag = action_input
            flag = self._extract_flag(flag)
        elif action == "mcp":
            action_input = self._normalize_mcp_action_input(action_input)
        
        return ReActOutput(
            thought=thought,
            action=action,
            action_input=action_input,
            raw_response=response,
            is_final=is_final,
            flag=flag
        )

    def _normalize_mcp_action_input(self, action_input: str) -> str:
        """
        规范化 mcp 参数为 JSON:
        {"server":"...","tool":"...","arguments":{...}}
        """
        raw = action_input.strip()
        if not raw:
            return raw

        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict) and "server" in parsed and "tool" in parsed:
                if "arguments" not in parsed or not isinstance(parsed.get("arguments"), dict):
                    parsed["arguments"] = {}
                return json.dumps(parsed, ensure_ascii=False)
        except Exception:
            pass

        match = re.match(r'^\s*([a-zA-Z0-9_\-]+)/([a-zA-Z0-9_\-]+)\((.*)\)\s*$', raw)
        if not match:
            return raw

        server_name = match.group(1).strip()
        tool_name = match.group(2).strip()
        args_raw = match.group(3).strip()

        args_obj: Dict[str, Any] = {}
        if args_raw:
            try:
                parsed_args = json.loads(args_raw)
                if isinstance(parsed_args, dict):
                    args_obj = parsed_args
                else:
                    args_obj = {"value": parsed_args}
            except Exception:
                args_obj = {"raw": args_raw}

        normalized = {
            "server": server_name,
            "tool": tool_name,
            "arguments": args_obj
        }
        return json.dumps(normalized, ensure_ascii=False)
    
    def _extract_flag(self, text: str) -> str:
        """从文本中提取 Flag"""
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'hctf\{[^}]+\}',
            r'key\{[^}]+\}',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                return match.group(0)
        
        return text.strip()
    
    def add_turn(self, turn: ConversationTurn):
        """添加一轮对话到历史"""
        self.history.append(turn)
        
        if len(self.history) > self.react_config.max_history_length:
            self._compress_history()
    
    def _compress_history(self):
        """压缩历史记录以节省上下文窗口"""
        if len(self.history) <= self.react_config.max_history_length:
            return
        
        keep_count = self.react_config.max_history_length // 2
        self.history = self.history[-keep_count:]
        
        summary = "之前的探索已压缩。关键发现：\n"
        self.messages.append({
            "role": "system",
            "content": summary
        })
    
    def get_conversation_summary(self) -> str:
        """获取对话摘要"""
        summary_lines = []
        for i, turn in enumerate(self.history, 1):
            summary_lines.append(f"=== 第 {i} 轮 ===")
            summary_lines.append(f"Thought: {turn.thought[:100]}...")
            summary_lines.append(f"Action: {turn.action}")
            summary_lines.append(f"Observation: {turn.observation[:200]}...")
        
        return "\n".join(summary_lines)
    
    def reset(self):
        """重置大脑状态"""
        self.messages = []
        self.chat_messages = []
        self.history = []
        self.active_skills = []
        self.last_unknown_skills = []
        self._init_system_prompt()
        self._init_chat_prompt()
