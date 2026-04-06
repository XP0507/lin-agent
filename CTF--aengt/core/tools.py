"""
CyberStrike-Agent Tools Module
工具集成模块 - 提供常用 CTF 工具封装
"""

import os
import re
import subprocess
import base64
import hashlib
from typing import Optional, Dict, Any, List, Union
from pathlib import Path
from dataclasses import dataclass


@dataclass
class ToolResult:
    """工具执行结果"""
    success: bool
    output: str
    error: str = ""


class ToolManager:
    """
    工具管理器
    
    集成常用 CTF 工具：
    1. 二进制分析工具
    2. 网络扫描工具
    3. 编码/解码工具
    4. 密码学工具
    """
    
    def __init__(self, workspace: str = "./workspace"):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
    
    def checksec(self, binary_path: str) -> ToolResult:
        """
        检查二进制文件安全选项
        
        Args:
            binary_path: 二进制文件路径
        """
        try:
            result = subprocess.run(
                ["checksec", "--file=" + binary_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            return ToolResult(
                success=True,
                output=result.stdout
            )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="",
                error="checksec 未安装。安装: pip install pwntools"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def strings(self, file_path: str, min_length: int = 4) -> ToolResult:
        """
        提取文件中的可打印字符串
        
        Args:
            file_path: 文件路径
            min_length: 最小字符串长度
        """
        try:
            result = subprocess.run(
                ["strings", "-n", str(min_length), file_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            return ToolResult(
                success=True,
                output=result.stdout
            )
        except FileNotFoundError:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                
                pattern = rb'[\x20-\x7e]{' + str(min_length).encode() + rb',}'
                strings = re.findall(pattern, data)
                output = '\n'.join(s.decode('ascii', errors='ignore') for s in strings)
                
                return ToolResult(
                    success=True,
                    output=output
                )
            except Exception as e:
                return ToolResult(
                    success=False,
                    output="",
                    error=str(e)
                )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def file_type(self, file_path: str) -> ToolResult:
        """
        识别文件类型
        
        Args:
            file_path: 文件路径
        """
        try:
            result = subprocess.run(
                ["file", file_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            return ToolResult(
                success=True,
                output=result.stdout
            )
        except FileNotFoundError:
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(512)
                
                signatures = {
                    b'\x7fELF': 'ELF 可执行文件',
                    b'MZ': 'Windows PE 文件',
                    b'\xca\xfe\xba\xbe': 'Java Class 文件',
                    b'PK': 'ZIP 压缩文件',
                    b'\x89PNG': 'PNG 图像',
                    b'GIF8': 'GIF 图像',
                    b'\xff\xd8\xff': 'JPEG 图像',
                    b'%PDF': 'PDF 文档',
                }
                
                file_type = "未知文件类型"
                for sig, desc in signatures.items():
                    if header.startswith(sig):
                        file_type = desc
                        break
                
                return ToolResult(
                    success=True,
                    output=f"{file_path}: {file_type}"
                )
            except Exception as e:
                return ToolResult(
                    success=False,
                    output="",
                    error=str(e)
                )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def nmap_scan(self, target: str, ports: Optional[str] = None, 
                  options: Optional[List[str]] = None) -> ToolResult:
        """
        Nmap 端口扫描
        
        Args:
            target: 目标地址
            ports: 端口范围 (如 "1-1000")
            options: 额外选项
        """
        try:
            cmd = ["nmap"]
            
            if ports:
                cmd.extend(["-p", ports])
            
            if options:
                cmd.extend(options)
            
            cmd.append(target)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return ToolResult(
                success=True,
                output=result.stdout
            )
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="",
                error="nmap 未安装"
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def base64_decode(self, data: str) -> ToolResult:
        """Base64 解码"""
        try:
            decoded = base64.b64decode(data).decode('utf-8', errors='replace')
            return ToolResult(
                success=True,
                output=decoded
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def base64_encode(self, data: str) -> ToolResult:
        """Base64 编码"""
        try:
            encoded = base64.b64encode(data.encode()).decode()
            return ToolResult(
                success=True,
                output=encoded
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def hash_compute(self, data: str, algorithm: str = "md5") -> ToolResult:
        """
        计算哈希值
        
        Args:
            data: 输入数据
            algorithm: 算法 (md5, sha1, sha256, sha512)
        """
        try:
            algorithm = algorithm.lower()
            
            if algorithm == "md5":
                h = hashlib.md5()
            elif algorithm == "sha1":
                h = hashlib.sha1()
            elif algorithm == "sha256":
                h = hashlib.sha256()
            elif algorithm == "sha512":
                h = hashlib.sha512()
            else:
                return ToolResult(
                    success=False,
                    output="",
                    error=f"不支持的算法: {algorithm}"
                )
            
            h.update(data.encode())
            
            return ToolResult(
                success=True,
                output=h.hexdigest()
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def hex_decode(self, hex_string: str) -> ToolResult:
        """十六进制解码"""
        try:
            hex_string = hex_string.replace(" ", "").replace("\\x", "")
            decoded = bytes.fromhex(hex_string).decode('utf-8', errors='replace')
            return ToolResult(
                success=True,
                output=decoded
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def hex_encode(self, data: str) -> ToolResult:
        """十六进制编码"""
        try:
            encoded = data.encode().hex()
            formatted = ' '.join(encoded[i:i+2] for i in range(0, len(encoded), 2))
            return ToolResult(
                success=True,
                output=formatted
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def url_decode(self, data: str) -> ToolResult:
        """URL 解码"""
        try:
            from urllib.parse import unquote
            decoded = unquote(data)
            return ToolResult(
                success=True,
                output=decoded
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def url_encode(self, data: str) -> ToolResult:
        """URL 编码"""
        try:
            from urllib.parse import quote
            encoded = quote(data, safe='')
            return ToolResult(
                success=True,
                output=encoded
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def rot13(self, data: str) -> ToolResult:
        """ROT13 编码/解码"""
        try:
            result = []
            for char in data:
                if 'a' <= char <= 'z':
                    result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
                elif 'A' <= char <= 'Z':
                    result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
                else:
                    result.append(char)
            
            return ToolResult(
                success=True,
                output=''.join(result)
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )
    
    def xor_decode(self, data: bytes, key: Union[bytes, int]) -> ToolResult:
        """XOR 解码"""
        try:
            if isinstance(key, int):
                key = bytes([key])
            
            result = []
            for i, byte in enumerate(data):
                result.append(byte ^ key[i % len(key)])
            
            decoded = bytes(result).decode('utf-8', errors='replace')
            return ToolResult(
                success=True,
                output=decoded
            )
        except Exception as e:
            return ToolResult(
                success=False,
                output="",
                error=str(e)
            )


TOOL_REGISTRY = {
    "checksec": ToolManager.checksec,
    "strings": ToolManager.strings,
    "file": ToolManager.file_type,
    "nmap": ToolManager.nmap_scan,
    "base64_decode": ToolManager.base64_decode,
    "base64_encode": ToolManager.base64_encode,
    "hash": ToolManager.hash_compute,
    "hex_decode": ToolManager.hex_decode,
    "hex_encode": ToolManager.hex_encode,
    "url_decode": ToolManager.url_decode,
    "url_encode": ToolManager.url_encode,
    "rot13": ToolManager.rot13,
    "xor": ToolManager.xor_decode,
}
