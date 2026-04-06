"""
CyberStrike-Agent Monitor Module
监控模块 - 捕获执行结果并反馈给大脑
"""

import time
import re
import hashlib
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import json

from config import Config
from core.executor import ExecutionResult
from core.brain import ConversationTurn

try:
    from core.memory import get_memory, CaseRecord
    MEMORY_AVAILABLE = True
except ImportError:
    MEMORY_AVAILABLE = False


@dataclass
class ExecutionLog:
    """执行日志"""
    timestamp: str
    iteration: int
    action: str
    action_input: str
    success: bool
    output: str
    error: str
    execution_time: float
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "iteration": self.iteration,
            "action": self.action,
            "action_input": self.action_input[:500],
            "success": self.success,
            "output": self.output[:1000],
            "error": self.error[:500],
            "execution_time": self.execution_time
        }


class Monitor:
    """
    监控模块
    
    功能：
    1. 捕获和记录执行结果
    2. 格式化 Observation 反馈
    3. 检测 Flag
    4. 生成执行报告
    5. 自动保存成功案例到记忆库
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.logs: List[ExecutionLog] = []
        self.iteration = 0
        self.start_time = time.time()
        self.found_flags: List[str] = []
        self.errors: List[str] = []
        
        self.current_task: str = ""
        self.current_context: str = ""
        self.thought_chain: List[str] = []
        self.action_history: List[Dict[str, str]] = []
        self.case_saved: bool = False
    
    def capture(
        self,
        action: str,
        action_input: str,
        result: ExecutionResult
    ) -> ConversationTurn:
        """
        捕获执行结果并生成对话轮次
        
        Args:
            action: 执行的动作
            action_input: 动作输入
            result: 执行结果
            
        Returns:
            ConversationTurn: 对话轮次记录
        """
        self.iteration += 1
        
        log = ExecutionLog(
            timestamp=datetime.now().isoformat(),
            iteration=self.iteration,
            action=action,
            action_input=action_input,
            success=result.success,
            output=result.output,
            error=result.error,
            execution_time=result.execution_time
        )
        self.logs.append(log)
        
        if not result.success and result.error:
            self.errors.append(f"[{self.iteration}] {action}: {result.error}")
        
        self._detect_flag(result.output)
        self._detect_flag(result.error)
        
        observation = self._format_observation(result)
        
        return ConversationTurn(
            thought="",
            action=action,
            action_input=action_input,
            observation=observation
        )
    
    def _format_observation(self, result: ExecutionResult) -> str:
        """
        格式化 Observation
        
        将执行结果转换为清晰的反馈格式
        """
        parts = []
        
        if result.success:
            parts.append("✅ 执行成功")
        else:
            parts.append("❌ 执行失败")
        
        if result.execution_time > 0:
            parts.append(f"⏱️ 耗时: {result.execution_time:.2f}秒")
        
        parts.append("")
        
        if result.output:
            output_display = result.output
            if len(output_display) > 3000:
                output_display = output_display[:3000] + "\n... [输出已截断]"
            parts.append(f"📤 输出:\n```\n{output_display}\n```")
        
        if result.error:
            error_display = result.error
            if len(error_display) > 2000:
                error_display = error_display[:2000] + "\n... [错误已截断]"
            parts.append(f"🔴 错误:\n```\n{error_display}\n```")
        
        return "\n".join(parts)
    
    def _detect_flag(self, text: str):
        """检测文本中的 Flag"""
        if not text:
            return
        
        patterns = [
            r'flag\{[^}]+\}',
            r'FLAG\{[^}]+\}',
            r'ctf\{[^}]+\}',
            r'CTF\{[^}]+\}',
            r'hctf\{[^}]+\}',
            r'key\{[^}]+\}',
            r'KEY\{[^}]+\}',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if match not in self.found_flags:
                    self.found_flags.append(match)
    
    def has_found_flag(self) -> bool:
        """检查是否找到 Flag"""
        return len(self.found_flags) > 0
    
    def get_flags(self) -> List[str]:
        """获取所有找到的 Flag"""
        return self.found_flags
    
    def get_errors(self) -> List[str]:
        """获取所有错误"""
        return self.errors
    
    def get_statistics(self) -> Dict:
        """获取执行统计"""
        total_time = time.time() - self.start_time
        success_count = sum(1 for log in self.logs if log.success)
        
        return {
            "总迭代次数": self.iteration,
            "成功执行": success_count,
            "失败执行": self.iteration - success_count,
            "成功率": f"{success_count / max(self.iteration, 1) * 100:.1f}%",
            "总耗时": f"{total_time:.2f}秒",
            "找到的Flag数量": len(self.found_flags),
            "错误数量": len(self.errors)
        }
    
    def generate_report(self) -> str:
        """生成执行报告"""
        stats = self.get_statistics()
        
        report_lines = [
            "=" * 60,
            "CyberStrike-Agent 执行报告",
            "=" * 60,
            "",
            "📊 执行统计:",
        ]
        
        for key, value in stats.items():
            report_lines.append(f"  • {key}: {value}")
        
        if self.found_flags:
            report_lines.extend([
                "",
                "🚩 发现的 Flag:",
            ])
            for i, flag in enumerate(self.found_flags, 1):
                report_lines.append(f"  {i}. {flag}")
        
        if self.errors:
            report_lines.extend([
                "",
                "⚠️ 错误摘要:",
            ])
            for error in self.errors[-5:]:
                report_lines.append(f"  • {error[:100]}...")
        
        report_lines.extend([
            "",
            "=" * 60,
        ])
        
        return "\n".join(report_lines)
    
    def save_logs(self, filepath: str):
        """保存执行日志到文件"""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "statistics": self.get_statistics(),
            "flags": self.found_flags,
            "logs": [log.to_dict() for log in self.logs]
        }
        
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def set_task(self, task: str, context: str = ""):
        """设置当前任务信息"""
        self.current_task = task
        self.current_context = context
        self.case_saved = False
    
    def record_thought(self, thought: str):
        """记录思考过程"""
        if thought and thought not in self.thought_chain:
            self.thought_chain.append(thought)
    
    def record_action(self, action: str, action_input: str):
        """记录动作"""
        self.action_history.append({
            "action": action,
            "action_input": action_input[:200]
        })
    
    def _extract_key_payload(self) -> str:
        """提取关键 Payload"""
        payloads = []
        
        for log in self.logs:
            if log.success and log.action in ["bash", "python", "execute"]:
                if len(log.action_input) > 10:
                    payloads.append(log.action_input)
        
        for action in self.action_history:
            if action["action"] in ["bash", "python", "execute"]:
                payloads.append(action["action_input"])
        
        if payloads:
            return payloads[-1] if len(payloads[-1]) > 20 else "\n---\n".join(payloads[-3:])
        
        return ""
    
    def _detect_category(self) -> str:
        """检测题目类型"""
        text = f"{self.current_task} {self.current_context}".lower()
        
        categories = {
            "pwn": ["pwn", "溢出", "overflow", "rop", "heap", "stack", "shell", "libc", "got", "plt"],
            "web": ["web", "sql", "注入", "injection", "xss", "ssti", "ssrf", "csrf", "rce", "文件上传"],
            "crypto": ["crypto", "加密", "rsa", "aes", "des", "xor", "hash", "密钥", "cipher"],
            "reverse": ["reverse", "逆向", "反编译", "decompile", "汇编", "assembly", "调试"],
            "misc": ["misc", "隐写", "stego", "取证", "forensic", "图片", "音频", "压缩包"],
        }
        
        for cat, keywords in categories.items():
            if any(kw in text for kw in keywords):
                return cat
        
        return "unknown"
    
    def _extract_keywords(self) -> List[str]:
        """提取关键词"""
        text = f"{self.current_task} {self.current_context}"
        keywords = []
        
        patterns = [
            r'\b(pwn|web|crypto|reverse|misc)\b',
            r'\b(overflow|injection|xss|ssti|ssrf|rce)\b',
            r'\b(ret2libc|rop|uaf|format string)\b',
            r'\b(rsa|aes|des|xor|hash)\b',
            r'\b(flag|shell|exec)\b',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            keywords.extend(matches)
        
        return list(set(keywords))[:10]
    
    def save_success_case(self):
        """保存成功案例到记忆库"""
        if not MEMORY_AVAILABLE:
            return
        
        if self.case_saved:
            return
        
        if not self.found_flags:
            return
        
        if not self.current_task:
            return
        
        try:
            memory = get_memory()
            
            case_id = hashlib.md5(
                f"{self.current_task}_{self.found_flags[0]}".encode()
            ).hexdigest()[:12]
            
            key_payload = self._extract_key_payload()
            
            case = CaseRecord(
                id=case_id,
                task_description=self.current_task,
                category=self._detect_category(),
                flag=self.found_flags[0],
                key_payload=key_payload,
                thought_chain=self.thought_chain[-10:],
                actions=self.action_history[-20:],
                success_time=datetime.now().isoformat(),
                iterations=self.iteration,
                keywords=self._extract_keywords()
            )
            
            memory.add_case(case)
            self.case_saved = True
            
            print(f"\n[Memory] ✅ 已保存成功案例到记忆库: {case_id}")
            
        except Exception as e:
            print(f"[Memory] 保存案例失败: {e}")
    
    def reset(self):
        """重置监控状态"""
        self.logs = []
        self.iteration = 0
        self.start_time = time.time()
        self.found_flags = []
        self.errors = []
        
        self.current_task = ""
        self.current_context = ""
        self.thought_chain = []
        self.action_history = []
        self.case_saved = False
