"""
CyberStrike-Agent MCP Client Module
MCP 客户端管理模块 - 管理多服务工具发现与调用
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional, Tuple
import asyncio

from config import MCPConfig, MCPServerConfig

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    MCP_SDK_AVAILABLE = True
except Exception:
    MCP_SDK_AVAILABLE = False


@dataclass
class MCPToolDescriptor:
    server: str
    name: str
    description: str
    input_schema: Dict[str, Any]


class MCPClientManager:
    """MCP 多服务客户端管理器（按调用临时建立 stdio 会话）"""

    def __init__(self, mcp_config: MCPConfig):
        self.config = mcp_config
        self.server_map: Dict[str, MCPServerConfig] = {
            s.name: s for s in mcp_config.servers
        }

    def available_servers(self) -> List[str]:
        return list(self.server_map.keys())

    def list_tools(self) -> Tuple[List[MCPToolDescriptor], List[str]]:
        if not self.config.enabled:
            return [], []
        if not MCP_SDK_AVAILABLE:
            return [], ["Python 包 `mcp` 未安装，无法列出 MCP 工具"]

        tools: List[MCPToolDescriptor] = []
        errors: List[str] = []

        for server_name, server_cfg in self.server_map.items():
            try:
                server_tools = asyncio.run(self._list_tools_async(server_cfg))
                tools.extend(server_tools)
            except Exception as e:
                errors.append(f"{server_name}: {str(e)}")

        return tools, errors

    def call_tool(self, server_name: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if not self.config.enabled:
            return {"ok": False, "error": "MCP 未启用"}
        if not MCP_SDK_AVAILABLE:
            return {"ok": False, "error": "Python 包 `mcp` 未安装，无法调用 MCP 工具"}

        server_cfg = self.server_map.get(server_name)
        if not server_cfg:
            return {"ok": False, "error": f"未找到 MCP Server: {server_name}"}

        try:
            result = asyncio.run(self._call_tool_async(server_cfg, tool_name, arguments))
            return {"ok": True, "result": result}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    async def _list_tools_async(self, server_cfg: MCPServerConfig) -> List[MCPToolDescriptor]:
        params = StdioServerParameters(
            command=server_cfg.command,
            args=server_cfg.args,
            env=server_cfg.env or None
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                descriptors: List[MCPToolDescriptor] = []
                for tool in result.tools:
                    descriptors.append(MCPToolDescriptor(
                        server=server_cfg.name,
                        name=tool.name,
                        description=getattr(tool, "description", "") or "",
                        input_schema=getattr(tool, "inputSchema", {}) or {}
                    ))
                return descriptors

    async def _call_tool_async(self, server_cfg: MCPServerConfig, tool_name: str, arguments: Dict[str, Any]) -> Any:
        params = StdioServerParameters(
            command=server_cfg.command,
            args=server_cfg.args,
            env=server_cfg.env or None
        )

        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(tool_name, arguments or {})
                return result
