"""
CyberStrike-Agent Executor Module
动作执行器 - 负责执行各种操作
"""

import os
import re
import sys
import json
import subprocess
import tempfile
import traceback
from typing import Optional, Dict, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, unquote
import zipfile
import tarfile
import requests

from config import Config, ExecutorConfig
from core.mcp_client import MCPClientManager


@dataclass
class ExecutionResult:
    """执行结果"""
    success: bool
    output: str
    error: str
    return_code: int = 0
    execution_time: float = 0.0


class Executor:
    """
    动作执行器
    
    支持的操作：
    1. bash - 执行系统命令
    2. python - 运行 Python 脚本
    3. read_file - 读取文件
    4. write_file - 写入文件
    5. http - 发送 HTTP 请求
    6. download - 下载远程文件到工作目录
    7. mcp - 调用 MCP Server 工具
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.executor_config = config.executor
        self.workspace = Path(self.executor_config.working_directory)
        self.session = requests.Session()
        self.mcp_manager = MCPClientManager(config.mcp)
        self.mcp_servers = self.mcp_manager.available_servers()
        self._ensure_workspace()
    
    def _ensure_workspace(self):
        """确保工作目录存在"""
        self.workspace.mkdir(parents=True, exist_ok=True)
    
    def execute(self, action: str, action_input: str) -> ExecutionResult:
        """
        执行动作
        
        Args:
            action: 动作类型
            action_input: 动作输入
            
        Returns:
            ExecutionResult: 执行结果
        """
        action = action.lower().strip()
        
        handlers = {
            "bash": self._execute_bash,
            "python": self._execute_python,
            "read_file": self._execute_read_file,
            "write_file": self._execute_write_file,
            "http": self._execute_http,
            "download": self._execute_download,
            "mcp": self._execute_mcp_action,
            "error": self._handle_error,
        }
        
        handler = handlers.get(action)
        if not handler:
            return ExecutionResult(
                success=False,
                output="",
                error=f"未知的动作类型: {action}。可用动作: {list(handlers.keys())}"
            )
        
        try:
            return handler(action_input)
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=f"执行异常: {str(e)}\n{traceback.format_exc()}"
            )
    
    def _execute_bash(self, command: str) -> ExecutionResult:
        """
        执行 Bash 命令
        
        安全措施：
        1. 检查命令白名单
        2. 设置超时
        3. 沙箱模式限制
        """
        command = command.strip()
        
        if not command:
            return ExecutionResult(
                success=False,
                output="",
                error="命令不能为空"
            )
        
        if self.executor_config.sandbox_mode:
            cmd_parts = command.split()
            if cmd_parts:
                base_cmd = cmd_parts[0]
                if base_cmd not in self.executor_config.allowed_commands:
                    return ExecutionResult(
                        success=False,
                        output="",
                        error=f"沙箱模式: 命令 '{base_cmd}' 不在允许列表中"
                    )
        
        try:
            import time
            start_time = time.time()
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.executor_config.max_command_timeout,
                cwd=str(self.workspace),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"}
            )
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr,
                return_code=result.returncode,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                output="",
                error=f"命令执行超时 (>{self.executor_config.max_command_timeout}秒)"
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=f"命令执行失败: {str(e)}\n{traceback.format_exc()}"
            )
    
    def _execute_python(self, code: str) -> ExecutionResult:
        """
        执行 Python 代码
        
        特点：
        1. 在隔离的命名空间中执行
        2. 捕获 stdout/stderr
        3. 支持导入常用库
        """
        code = code.strip()
        
        if not code:
            return ExecutionResult(
                success=False,
                output="",
                error="Python 代码不能为空"
            )
        
        try:
            import time
            import io
            from contextlib import redirect_stdout, redirect_stderr
            
            start_time = time.time()
            
            stdout_capture = io.StringIO()
            stderr_capture = io.StringIO()
            
            safe_globals = {
                "__builtins__": __builtins__,
                "os": os,
                "sys": sys,
                "json": json,
                "re": re,
                "requests": requests,
                "subprocess": subprocess,
                "Path": Path,
                "zipfile": zipfile,
                "tarfile": tarfile,
            }
            
            try:
                import pwn
                safe_globals["pwn"] = pwn
                safe_globals["pwntools"] = pwn
            except ImportError:
                pass
            
            try:
                import z3
                safe_globals["z3"] = z3
            except ImportError:
                pass
            
            try:
                from Crypto.Cipher import AES, DES
                from Crypto.Util import number
                safe_globals["AES"] = AES
                safe_globals["DES"] = DES
                safe_globals["Crypto"] = __import__("Crypto")
                safe_globals["number"] = number
            except ImportError:
                pass
            
            local_vars = {}
            
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                exec(code, safe_globals, local_vars)
            
            execution_time = time.time() - start_time
            
            output = stdout_capture.getvalue()
            error = stderr_capture.getvalue()
            
            if local_vars.get("result"):
                output += f"\n返回值: {local_vars['result']}"
            
            return ExecutionResult(
                success=True,
                output=output,
                error=error,
                execution_time=execution_time
            )
            
        except Exception as e:
            error_msg = f"Python 执行错误:\n{traceback.format_exc()}"
            return ExecutionResult(
                success=False,
                output="",
                error=error_msg
            )
    
    def _execute_read_file(self, file_path: str) -> ExecutionResult:
        """读取文件内容"""
        file_path = file_path.strip()
        
        if not file_path:
            return ExecutionResult(
                success=False,
                output="",
                error="文件路径不能为空"
            )
        
        try:
            path = Path(file_path)
            if not path.is_absolute():
                path = self.workspace / path
            path = path.resolve()
            
            if not path.exists():
                return ExecutionResult(
                    success=False,
                    output="",
                    error=f"文件不存在: {path}"
                )
            
            if path.stat().st_size > 100 * 1024 * 1024:
                return ExecutionResult(
                    success=False,
                    output="",
                    error="文件过大 (>100MB)，请使用分块读取或专用分析工具"
                )
            
            try:
                content = path.read_text(encoding='utf-8')
                return ExecutionResult(
                    success=True,
                    output=content,
                    error=""
                )
            except UnicodeDecodeError:
                content = path.read_bytes()
                hex_preview = content[:1000].hex()
                return ExecutionResult(
                    success=True,
                    output=f"二进制文件 (前1000字节 hex):\n{hex_preview}",
                    error=""
                )
                
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=f"读取文件失败: {str(e)}\n{traceback.format_exc()}"
            )

    def _execute_mcp_action(self, action_input: str) -> ExecutionResult:
        """
        MCP 动作入口（兼容格式）：
        1) server/tool({"k":"v"})
        2) {"server":"fetch","tool":"fetch","arguments":{...}}
        """
        action_input = action_input.strip()
        if not action_input:
            return ExecutionResult(
                success=False,
                output="",
                error="mcp 动作参数不能为空"
            )

        server_name = ""
        tool_name = ""
        arguments: Dict[str, Any] = {}

        try:
            parsed = json.loads(action_input)
            if isinstance(parsed, dict):
                server_name = str(parsed.get("server", "")).strip()
                tool_name = str(parsed.get("tool", "")).strip()
                args_obj = parsed.get("arguments", {})
                if isinstance(args_obj, dict):
                    arguments = args_obj
        except Exception:
            match = re.match(r'^\s*([a-zA-Z0-9_\-]+)/([a-zA-Z0-9_\-]+)\((.*)\)\s*$', action_input)
            if match:
                server_name = match.group(1).strip()
                tool_name = match.group(2).strip()
                raw_args = match.group(3).strip()
                if raw_args:
                    try:
                        args_json = json.loads(raw_args)
                        if isinstance(args_json, dict):
                            arguments = args_json
                        else:
                            arguments = {"value": args_json}
                    except Exception:
                        arguments = {"raw": raw_args}

        if not server_name or not tool_name:
            return ExecutionResult(
                success=False,
                output="",
                error=(
                    "mcp 参数格式错误。请使用 "
                    "server/tool({\"arg\":\"value\"}) 或 JSON 格式"
                )
            )

        return self._execute_mcp(server_name, tool_name, arguments)

    def _execute_mcp(self, server_name: str, tool_name: str, arguments: Dict[str, Any]) -> ExecutionResult:
        """调用 MCP Server 工具"""
        import time
        start_time = time.time()

        result = self.mcp_manager.call_tool(server_name, tool_name, arguments)
        execution_time = time.time() - start_time

        if result.get("ok"):
            return ExecutionResult(
                success=True,
                output=(
                    f"MCP 调用成功\n"
                    f"Server: {server_name}\n"
                    f"Tool: {tool_name}\n"
                    f"Result:\n{result.get('result')}"
                ),
                error="",
                execution_time=execution_time
            )

        return ExecutionResult(
            success=False,
            output="",
            error=f"MCP 调用失败: {result.get('error', 'unknown error')}",
            execution_time=execution_time
        )

    def _execute_download(self, action_input: str) -> ExecutionResult:
        """
        下载远程文件到 workspace

        格式:
        1) URL
        2) URL filename
        """
        action_input = action_input.strip()
        if not action_input:
            return ExecutionResult(
                success=False,
                output="",
                error="下载参数不能为空。正确格式: <url> [filename]"
            )

        parts = action_input.split(maxsplit=1)
        url = parts[0]
        filename = parts[1].strip() if len(parts) > 1 else ""

        if not filename:
            parsed = urlparse(url)
            name_from_url = Path(unquote(parsed.path)).name
            filename = name_from_url or "downloaded.bin"

        # 强制保存到 workspace，避免写入到意外路径
        save_path = self.workspace / Path(filename).name

        try:
            import time
            start_time = time.time()

            response = self.session.get(
                url,
                stream=True,
                timeout=60,
                allow_redirects=True
            )
            response.raise_for_status()

            total = 0
            with open(save_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        total += len(chunk)

            execution_time = time.time() - start_time
            return ExecutionResult(
                success=True,
                output=(
                    f"下载成功: {url}\n"
                    f"保存路径: {save_path}\n"
                    f"文件大小: {total} bytes"
                ),
                error="",
                execution_time=execution_time
            )
        except requests.exceptions.RequestException as e:
            return ExecutionResult(
                success=False,
                output="",
                error=f"下载失败: {str(e)}"
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=f"下载异常: {str(e)}\n{traceback.format_exc()}"
            )
    
    def _execute_write_file(self, action_input: str) -> ExecutionResult:
        """
        写入文件
        
        格式: file_path\ncontent
        """
        try:
            parts = action_input.split('\n', 1)
            if len(parts) < 2:
                return ExecutionResult(
                    success=False,
                    output="",
                    error="格式错误。正确格式: file_path\\ncontent"
                )
            
            file_path = parts[0].strip()
            content = parts[1]
            
            if not file_path:
                return ExecutionResult(
                    success=False,
                    output="",
                    error="文件路径不能为空"
                )
            
            path = Path(file_path)
            if not path.is_absolute():
                path = self.workspace / path
            
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
            
            return ExecutionResult(
                success=True,
                output=f"文件已写入: {path}",
                error=""
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=f"写入文件失败: {str(e)}\n{traceback.format_exc()}"
            )
    
    def _execute_http(self, action_input: str) -> ExecutionResult:
        """
        发送 HTTP 请求
        
        格式: METHOD URL [headers_json] [data]
        """
        try:
            parts = action_input.strip().split(None, 3)
            
            if len(parts) < 2:
                return ExecutionResult(
                    success=False,
                    output="",
                    error="格式错误。正确格式: METHOD URL [headers] [data]"
                )
            
            method = parts[0].upper()
            url = parts[1]
            headers = {}
            data = None
            
            if len(parts) >= 3:
                try:
                    headers = json.loads(parts[2])
                except json.JSONDecodeError:
                    headers = {}
            
            if len(parts) >= 4:
                data = parts[3]
            
            response = self.session.request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                timeout=30,
                allow_redirects=True
            )
            
            output = f"状态码: {response.status_code}\n"
            output += f"响应头:\n{json.dumps(dict(response.headers), indent=2)}\n"
            output += f"响应体:\n{response.text[:5000]}"
            
            return ExecutionResult(
                success=200 <= response.status_code < 400,
                output=output,
                error=""
            )
            
        except requests.exceptions.Timeout:
            return ExecutionResult(
                success=False,
                output="",
                error="HTTP 请求超时"
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                output="",
                error=f"HTTP 请求失败: {str(e)}\n{traceback.format_exc()}"
            )
    
    def _handle_error(self, error_msg: str) -> ExecutionResult:
        """处理错误动作"""
        return ExecutionResult(
            success=False,
            output="",
            error=f"错误: {error_msg}"
        )
    
    def get_workspace_path(self) -> Path:
        """获取工作目录路径"""
        return self.workspace
