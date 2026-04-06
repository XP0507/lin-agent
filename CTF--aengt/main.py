#!/usr/bin/env python3
"""
CyberStrike-Agent - CTF 自动化解题框架
主程序入口

基于 ReAct (Reasoning and Acting) 架构
"""

import os
import sys
import argparse
import signal
import time
from typing import Optional
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.markdown import Markdown
    from rich.syntax import Syntax
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.live import Live
    from rich.layout import Layout
    from rich.table import Table
    from rich.text import Text
    from rich.box import ROUNDED, DOUBLE, HEAVY
    from rich.spinner import Spinner
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    from prompt_toolkit import prompt as pt_prompt
    from prompt_toolkit.history import InMemoryHistory
    from prompt_toolkit.key_binding import KeyBindings
    PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    PROMPT_TOOLKIT_AVAILABLE = False

from config import Config, SYSTEM_PROMPT
from core.brain import Brain, ReActOutput, ConversationTurn
from core.executor import Executor, ExecutionResult
from core.monitor import Monitor


class CyberStrikeAgent:
    """
    CyberStrike Agent 主类
    
    实现 ReAct 循环：
    1. Thought - 分析当前情况
    2. Action - 执行操作
    3. Observation - 观察结果
    """
    
    def __init__(self, config: Optional[Config] = None, verbose: bool = True):
        self.config = config or Config.from_env()
        self.verbose = verbose
        
        self.brain = Brain(self.config)
        self.executor = Executor(self.config)
        self.monitor = Monitor(self.config)
        
        if RICH_AVAILABLE:
            self.console = Console()
        else:
            self.console = None
        
        self.running = True
        self._in_task = False
        self._sigint_count = 0
        self._last_sigint_at = 0.0
        self._setup_signal_handlers()
    
    def _setup_signal_handlers(self):
        """设置信号处理器"""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """处理中断信号"""
        if signum == signal.SIGTERM:
            self._print("\n\n🛑 收到终止信号，立即退出...", "bold red")
            os._exit(143)

        now = time.monotonic()
        if now - self._last_sigint_at > 2.0:
            self._sigint_count = 0
        self._last_sigint_at = now
        self._sigint_count += 1

        if self._sigint_count >= 2:
            self._print("\n\n🛑 再次收到 Ctrl+C，强制退出进程", "bold red")
            os._exit(130)

        self.running = False
        if self._in_task:
            self._print("\n\n⚠️ 收到 Ctrl+C，正在中断当前任务（再次 Ctrl+C 可强制退出）", "yellow")
        else:
            self._print("\n\n⚠️ 收到 Ctrl+C，正在退出...", "yellow")
        raise KeyboardInterrupt
    
    def _print(self, message: str, style: Optional[str] = None):
        """打印消息"""
        if self.console:
            if style:
                self.console.print(message, style=style)
            else:
                self.console.print(message)
        else:
            print(message)
    
    def _print_panel(self, title: str, content: str, style: str = "blue"):
        """打印面板"""
        if self.console:
            self.console.print(Panel(content, title=title, border_style=style))
        else:
            print(f"\n{'='*60}")
            print(f" {title}")
            print('='*60)
            print(content)
            print('='*60)
    
    def run(
        self,
        task_description: str,
        context: Optional[str] = None,
        forced_skills: Optional[list] = None,
        use_live_dashboard: bool = False
    ) -> Optional[str]:
        """
        运行 Agent 解决 CTF 题目（支持实时流式看板）
        
        Args:
            task_description: 题目描述
            context: 额外上下文（如 URL、文件路径等）
            use_live_dashboard: 是否启用 rich.live 动态看板
            
        Returns:
            找到的 Flag，如果未找到则返回 None
        """
        self._print_banner()
        self.running = True
        self._in_task = True
        self._sigint_count = 0
        
        self._print(f"\n🎯 任务: {task_description}", "bold yellow")
        if context:
            self._print(f"📋 上下文: {context}", "dim")
        
        self.monitor.set_task(task_description, context)
        self.brain.set_task(task_description, context, forced_skills=forced_skills)

        if forced_skills:
            self._print(f"🧩 强制技能: {', '.join(forced_skills)}", "bold magenta")
            if self.brain.last_unknown_skills:
                self._print(
                    f"⚠️ 未识别技能已忽略: {', '.join(self.brain.last_unknown_skills)}",
                    "yellow"
                )
            elif self.brain.active_skills:
                active_names = [s.name for s in self.brain.active_skills]
                self._print(f"✅ 生效技能: {', '.join(active_names)}", "green")

        iteration = 0
        max_iterations = self.config.react.max_iterations
        
        if use_live_dashboard and RICH_AVAILABLE and self.console:
            return self._run_with_live_dashboard(task_description, iteration, max_iterations)
        else:
            return self._run_classic(task_description, iteration, max_iterations)

    def _run_classic(self, task_description: str, iteration: int, max_iterations: int) -> Optional[str]:
        """经典模式运行（无 Live 看板，保持原有逻辑）"""
        try:
            while iteration < max_iterations and self.running:
                iteration += 1
                
                self._print(f"\n{'─'*60}", "dim")
                self._print(f"🔄 迭代 {iteration}/{max_iterations}", "bold cyan")
                
                output = self.brain.think(
                    observation=self._get_last_observation()
                )
                
                if output.thought:
                    self._print_panel("💭 Thought", output.thought, "green")
                    self.monitor.record_thought(output.thought)
                
                if output.is_final:
                    self._print(f"\n🚩 找到 Flag: {output.flag}", "bold red")
                    self.monitor.record_action("final", output.flag or "")
                    self.monitor.save_success_case()
                    self._generate_final_report()
                    return output.flag
                
                if output.action and output.action != "error":
                    self._print(f"\n⚡ Action: {output.action}", "bold blue")
                    self.monitor.record_action(output.action, output.action_input)
                    
                    if self.verbose and output.action_input:
                        preview = output.action_input[:200]
                        if len(output.action_input) > 200:
                            preview += "..."
                        self._print(f"📝 Input: {preview}", "dim")
                    
                    result = self.executor.execute(output.action, output.action_input)
                    
                    turn = self.monitor.capture(
                        output.action,
                        output.action_input,
                        result
                    )
                    
                    turn.thought = output.thought
                    self.brain.add_turn(turn)
                    
                    self._print_panel("👁️ Observation", turn.observation, "yellow")
                    
                    if self.monitor.has_found_flag():
                        flags = self.monitor.get_flags()
                        self._print(f"\n🎉 检测到可能的 Flag!", "bold green")
                        for flag in flags:
                            self._print(f"   {flag}", "bold red")
                        self.monitor.save_success_case()
                else:
                    self._print(f"\n⚠️ 无有效动作或发生错误", "red")
                    if output.action_input:
                        self._print(f"错误信息: {output.action_input}", "red")
                    if output.action == "error":
                        self._print("\n🛑 检测到不可恢复错误，提前结束本次任务", "bold red")
                        break
        except KeyboardInterrupt:
            self.running = False
            self._print("\n🛑 已强制中断当前任务", "bold red")
        finally:
            self._in_task = False
        
        if iteration >= max_iterations:
            self._print(f"\n⏰ 达到最大迭代次数 ({max_iterations})", "yellow")
            checkpoint_path = self.brain.save_checkpoint(reason="max_iterations")
            if checkpoint_path:
                self._print(f"💾 已保存自动恢复检查点: {checkpoint_path}", "bold cyan")
            else:
                self._print("⚠️ 检查点保存失败", "yellow")
        
        self._generate_final_report()
        return None

    def _run_with_live_dashboard(self, task_description: str, start_iteration: int, max_iterations: int) -> Optional[str]:
        dashboard = LiveDashboard(self.console, max_iterations=max_iterations)
        dashboard.start(task_description, context="")

        iteration = start_iteration
        final_flag = None

        with Live(dashboard, console=self.console, refresh_per_second=10, screen=True) as live:
            try:
                while iteration < max_iterations and self.running:
                    iteration += 1
                    dashboard.set_iteration(iteration)

                    dashboard.clear_observation()
                    dashboard.set_state("thinking")
                    dashboard._thought_lines.clear()

                    for event_type, content, output in self.brain.think_stream(
                        observation=self._get_last_observation()
                    ):
                        if event_type == "thought_chunk":
                            dashboard.append_thought_chunk(content)
                        elif event_type == "thought_done":
                            dashboard.set_thought_complete(content or "")
                            if output:
                                break
                        elif event_type == "error":
                            dashboard.set_state("error")
                            dashboard.add_observation(f"[ERROR] {content}")
                            output = ReActOutput(
                                thought=content,
                                action="error",
                                action_input=content,
                                raw_response="",
                                is_final=False
                            )
                            break

                    if output is None:
                        continue

                    if output.thought:
                        self.monitor.record_thought(output.thought)

                    if output.is_final:
                        final_flag = output.flag
                        dashboard.set_state("done")
                        dashboard.add_flag(final_flag or "")
                        dashboard.add_observation(f"[bold red]🚩 找到 Flag: {final_flag}[/]")

                        self.monitor.record_action("final", final_flag or "")
                        self.monitor.save_success_case()
                        self._in_task = False
                        self._generate_final_report()
                        return final_flag

                    if output.action and output.action != "error":
                        dashboard.set_state("acting")
                        dashboard.set_action(output.action, output.action_input)
                        self.monitor.record_action(output.action, output.action_input)

                        def _stream_cb(line: str):
                            dashboard.add_observation(line)

                        result = self.executor.execute(output.action, output.action_input, stream_callback=_stream_cb)

                        turn = self.monitor.capture(
                            output.action,
                            output.action_input,
                            result
                        )
                        turn.thought = output.thought
                        self.brain.add_turn(turn)

                        obs_text = turn.observation or ""
                        if result.output:
                            obs_preview = result.output[:800]
                            if len(result.output) > 800:
                                obs_preview += "\n... (输出已截断)"
                            dashboard.add_observation(f"[Output]\n{obs_preview}")
                        if result.error:
                            err_preview = result.error[:400]
                            dashboard.add_observation(f"[Error]\n{err_preview}")

                        if self.monitor.has_found_flag():
                            flags = self.monitor.get_flags()
                            for flag in flags:
                                dashboard.add_flag(flag)
                                dashboard.add_observation(f"[bold green]🎉 发现 Flag: {flag}[/]")
                            self.monitor.save_success_case()

                        dashboard.set_state("running")
                    else:
                        dashboard.set_state("error")
                        if output.action_input:
                            dashboard.add_observation(f"[错误] {output.action_input}")
                        if output.action == "error":
                            dashboard.add_observation("[bold red]🛑 不可恢复错误，结束任务[/]")
                            break

            except KeyboardInterrupt:
                self.running = False
                dashboard.set_state("error")
                dashboard.add_observation("[bold yellow]⚠️ 用户中断 (Ctrl+C)[/]")
                self._print("\n🛑 已强制中断当前任务", "bold red")
            finally:
                self._in_task = False
        
        if iteration >= max_iterations and not final_flag:
            self._print(f"\n⏰ 达到最大迭代次数 ({max_iterations})", "yellow")
            checkpoint_path = self.brain.save_checkpoint(reason="max_iterations")
            if checkpoint_path:
                self._print(f"💾 已保存自动恢复检查点: {checkpoint_path}", "bold cyan")
            else:
                self._print("⚠️ 检查点保存失败", "yellow")
        
        self._generate_final_report()
        return final_flag
    
    def _get_last_observation(self) -> Optional[str]:
        """获取最后一轮的观察结果"""
        if self.monitor.logs:
            last_log = self.monitor.logs[-1]
            observation = ""
            if last_log.output:
                observation += f"输出:\n{last_log.output}\n"
            if last_log.error:
                observation += f"错误:\n{last_log.error}"
            return observation if observation else None
        return None
    
    def _print_banner(self):
        """打印 Banner"""
        banner = """
   ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗ █████╗ ███████╗███████╗
  ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██╔══██╗██╔════╝██╔════╝
  ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║███████╗█████╗  
  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══██║╚════██║██╔══╝  
  ╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║██║  ██║███████║███████╗
   ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝
                        🤖 CTF Auto-Solving Agent v1.0
        """
        if self.console:
            self.console.print(banner, style="bold blue")
        else:
            print(banner)
    
    def _generate_final_report(self):
        """生成最终报告"""
        report = self.monitor.generate_report()
        self._print(f"\n{report}", "bold")
        
        log_dir = Path("./logs")
        log_dir.mkdir(exist_ok=True)
        
        from datetime import datetime
        log_file = log_dir / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.monitor.save_logs(str(log_file))
        self._print(f"\n📁 日志已保存: {log_file}", "dim")


class LiveDashboard:
    """
    实时动态看板 — rich.live 驱动的 50/50 经典分屏 TUI
    
    布局体系:
    ┌──────────────────────────────────────────────────┐
    │ ⏱ 12.3s │ #3/50 │ ⠋思考中 │ bash: checksec ./pwn │
    ├────────────────────┬─────────────────────────────┤
    │ 🧠 思维与决策流     │ 💻 终端执行与观察区          │
    │                    │                             │
    │ Thought: ...       │ [Out] flag{...}             │
    │ Action: bash: ...  │ [Err] timeout               │
    │ (自动滚动到底部)     │ (overflow=fold 防撑爆)       │
    │                    │                             │
    └────────────────────┴─────────────────────────────┘
    
    全局: split_row(left=1, right=1) 严格 50/50 平分
    顶部: 单行状态栏 (耗时|迭代|状态|动作)
    左侧: Thought+Action 流式区 (cyan + HEAVY, 行列表截断)
    右侧: Observation 日志区 (green + HEAVY, overflow fold)
    
    __rich__: 供 Live 自动刷新调用，即使主线程阻塞也能更新时间/Spinner
    """

    def __init__(self, console: Console, max_iterations: int = 50):
        self.console = console
        self.max_iterations = max_iterations

        self._thought_lines: list[str] = []
        self._max_thought_lines = 28
        self._action_text: str = ""
        self._observation_lines: list[str] = []
        self._max_obs_lines = 30
        self._current_iteration = 0
        self._start_time: float = 0
        self._flags: list[str] = []
        self._current_action = ""
        self._state = "idle"
        self._spinner_phase = 0
        self._spinner_chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __rich__(self):
        return self._build_layout()

    def start(self, task_desc: str, context: str = ""):
        import time
        self._start_time = time.monotonic()
        self._task_desc = task_desc[:60]
        self._context = (context or "")[:40]
        self._state = "running"

    @property
    def _elapsed(self) -> str:
        import time
        if not self._start_time:
            return "0s"
        elapsed = time.monotonic() - self._start_time
        if elapsed < 60:
            return f"{elapsed:.1f}s"
        m, s = divmod(int(elapsed), 60)
        return f"{m}m{s}s"

    def _get_spinner(self) -> str:
        self._spinner_phase = (self._spinner_phase + 1) % len(self._spinner_chars)
        ch = self._spinner_chars[self._spinner_phase]
        state_map = {
            "thinking": f"[cyan]{ch}[/] 思考中",
            "acting":   f"[blue]{ch}[/] 执行中",
            "idle":     "[dim]●[/] 待命",
            "done":     "[green]✓[/] 完成",
            "error":    "[red]✗[/] 错误",
        }
        return state_map.get(self._state, ch)

    def append_thought_chunk(self, chunk: str):
        lines = chunk.split("\n")
        for line in lines:
            if line:
                self._thought_lines.append(line)
        if len(self._thought_lines) > self._max_thought_lines * 3:
            self._thought_lines = self._thought_lines[-self._max_thought_lines * 2:]

    def set_thought_complete(self, full_thought: str):
        if full_thought:
            new_lines = full_thought.split("\n")
            for line in new_lines:
                if line.strip():
                    self._thought_lines.append(line)
        self._trim_thought_lines()

    def _trim_thought_lines(self):
        if len(self._thought_lines) > self._max_thought_lines:
            self._thought_lines = self._thought_lines[-self._max_thought_lines:]

    def set_state(self, state: str):
        self._state = state

    def set_action(self, action: str, action_input: str = ""):
        self._current_action = action
        if action_input:
            preview = action_input[:40].replace("\n", " ")
            if len(action_input) > 40:
                preview += "..."
            self._current_action = f"{action}: {preview}"
        self._action_text = self._current_action

    def set_iteration(self, iteration: int):
        self._current_iteration = iteration

    def add_observation(self, text: str):
        lines = text.splitlines()
        for line in lines:
            self._observation_lines.append(line)
        if len(self._observation_lines) > self._max_obs_lines:
            self._observation_lines = self._observation_lines[-self._max_obs_lines:]

    def add_flag(self, flag: str):
        if flag not in self._flags:
            self._flags.append(flag)

    def clear_observation(self):
        self._observation_lines.clear()

    def _build_status_bar(self) -> Text:
        parts = [
            f"[bold yellow]⏱ {self._elapsed}[/]",
            f"[bold cyan]#{self._current_iteration}/{self.max_iterations}[/]",
            self._get_spinner(),
        ]
        if self._current_action:
            act = self._current_action[:35]
            parts.append(f"[dim]{act}[/]")
        if self._flags:
            parts.append(f"[bold red]🚩 {self._flags[-1]}[/]")

        bar = Text("  │  ").join(Text.from_markup(p) for p in parts)
        return Text.assemble(
            (" ", ""),
            bar,
            (" ", ""),
            style="on #1a1a2e",
        )

    def _build_left_panel(self) -> Panel:
        content_parts: list[tuple] = []

        if self._action_text:
            content_parts.append(("\n", ""))
            content_parts.append((f"⚡ Action: ", "bold magenta"))
            content_parts.append((self._action_text, "cyan"))
            content_parts.append(("\n", ""))
            content_parts.append(("─" * 50, "dim"))
            content_parts.append(("\n", ""))

        self._trim_thought_lines()
        visible_lines = self._thought_lines[-self._max_thought_lines:] if self._thought_lines else []
        if visible_lines:
            thought_body = Text.assemble(
                ("💭 Thought:\n", "bold green"),
                ("\n".join(visible_lines), "white"),
            )
        else:
            thought_body = Text.from_markup("[dim](等待 LLM 推理输出...)[/]")

        content_parts.append(("", "\n"))
        content_parts.append(thought_body)
        body = Text.assemble(*content_parts)
        return Panel(
            body,
            title="[bold cyan] 🧠 思维与决策流 [/]",
            border_style="cyan",
            box=HEAVY,
            padding=(1, 2),
        )

    def _build_right_panel(self) -> Panel:
        if self._observation_lines:
            raw = "\n".join(self._observation_lines)
            obs_body = Text(raw, overflow="fold")
        else:
            obs_body = Text.from_markup("[dim](等待命令执行输出...)[/]")

        return Panel(
            obs_body,
            title="[bold green] 💻 终端执行与观察区 [/]",
            border_style="green",
            box=HEAVY,
            padding=(1, 2),
        )

    def _build_layout(self) -> Layout:
        layout = Layout()
        status_bar = self._build_status_bar()
        layout.split_column(
            Layout(status_bar, name="statusbar", size=1),
            Layout(name="main", ratio=1),
        )
        layout["main"].split_row(
            Layout(name="left", ratio=1),
            Layout(name="right", ratio=1),
        )
        layout["left"].update(self._build_left_panel())
        layout["right"].update(self._build_right_panel())
        return layout

    def render(self) -> Layout:
        return self._build_layout()


def interactive_mode(agent: CyberStrikeAgent):
    """交互模式 - 支持多行输入和粘贴"""
    
    _history = InMemoryHistory() if PROMPT_TOOLKIT_AVAILABLE else None
    
    def _ask_text(prompt_rich: str, prompt_plain: str, multiline: bool = False) -> str:
        """智能输入函数，优先使用 prompt_toolkit"""
        if PROMPT_TOOLKIT_AVAILABLE:
            try:
                return pt_prompt(
                    prompt_rich,
                    history=_history,
                    multiline=multiline,
                ).strip()
            except (EOFError, KeyboardInterrupt):
                return ""
        else:
            if RICH_AVAILABLE:
                from rich.prompt import Prompt
                return Prompt.ask(prompt_rich).strip()
            return input(prompt_plain).strip()

    def _read_multiline_block(end_markers=None) -> str:
        """
        读取多行块输入
        """
        if end_markers is None:
            TRIPLE_QUOTE = '"' * 3
            end_markers = {":done", TRIPLE_QUOTE}
        
        agent._print(
            f"\n  [dim]粘贴模式 — [bold]:done[/] 结束输入，[red]:cancel[/] 取消，Ctrl+C 退出[/]\n",
            "dim"
        )
        
        lines = []
        line_num = 0
        while True:
            line_num += 1
            
            try:
                if PROMPT_TOOLKIT_AVAILABLE:
                    from prompt_toolkit.key_binding import KeyBindings
                    
                    kb = KeyBindings()
                    exit_flag = False
                    
                    @kb.add('c-c')
                    def _(event):
                        nonlocal exit_flag
                        event.app.exit(result="")
                        exit_flag = True
                    
                    from prompt_toolkit import prompt as _pt_prompt
                    line = _pt_prompt(
                        f"{line_num:>3}>>> ",
                        key_bindings=kb,
                        history=_history,
                    )
                    
                    if exit_flag:
                        raise KeyboardInterrupt()
                        
                elif RICH_AVAILABLE:
                    from rich.prompt import Prompt
                    line = Prompt.ask("[cyan]>>[/]")
                else:
                    line = input(">> ")
                    
            except (EOFError, KeyboardInterrupt):
                if lines:
                    result = "\n".join(lines).strip()
                    agent._print(f"\n✅ 已接收 [green]{len(lines)} 行[/]，共 {len(result)} 字符 (Ctrl+C 结束)", "green")
                else:
                    agent._print("\n⚠️ 已取消本次输入", "yellow")
                return "\n".join(lines).strip()
            
            stripped = line.strip()
            
            if not lines and stripped in {"", ":cancel"}:
                continue
                
            if stripped in end_markers:
                break
            
            if stripped == ":cancel":
                agent._print("⚠️ 已取消本次输入", "yellow")
                return ""
            
            lines.append(line)
        
        result = "\n".join(lines).strip()
        if result:
            agent._print(
                f"✅ 已接收 [green]{len(lines)} 行[/]，共 {len(result)} 字符",
                "green"
            )
        return result

    def _detect_multiline_trigger(raw_input: str) -> tuple[bool, str]:
        """
        检测是否触发多行输入模式
        
        Returns:
            (should_enter_block_mode, processed_text)
        """
        TQ = '"' * 3
        text = raw_input.strip()
        
        if text == TQ:
            return True, ""
        
        if text.startswith(TQ):
            remainder = text[3:]
            if TQ in remainder:
                return False, remainder[:remainder.index(TQ)].strip()
            return True, remainder.strip()
        
        if text.endswith(TQ):
            prefix = text[:-3]
            if prefix.startswith(TQ):
                return False, prefix[3:].strip()
            return False, prefix.strip()
        
        if text.lower() in {"/block", "/paste", "/multi"}:
            return True, ""
        
        if text.lower().startswith("/file"):
            return False, text
        
        return False, raw_input

    def _load_text_from_file(command_text: str) -> str:
        """从本地文件加载文本内容"""
        parts = command_text.split(maxsplit=1)
        if len(parts) < 2:
            path_text = _ask_text("📁 {LIN}文件路径>>> ", "📁 文件路径>>> ")
        else:
            path_text = parts[1].strip()
        
        if not path_text:
            agent._print("⚠️ 文件路径不能为空。", "yellow")
            return ""
        
        try:
            content = Path(path_text).read_text(encoding="utf-8")
            line_count = len(content.splitlines())
            agent._print(f"📥 已加载文件（{line_count} 行）: {path_text}", "green")
            return content.strip()
        except Exception as e:
            agent._print(f"❌ 读取文件失败: {e}", "red")
            return ""

    def _chat_before_task():
        """预对话模式"""
        agent._print("\n  [dim]对话模式 — [bold]/start[/] 开始解题，[bold]/exit[/] 返回[/]\n", "dim")
        
        while True:
            try:
                user_msg = _ask_text("💬 LIN >>> ", "💬 你 >>> ")
                
                is_block, processed = _detect_multiline_trigger(user_msg)
                if is_block:
                    user_msg = _read_multiline_block()
                else:
                    user_msg = processed
                
                if not user_msg:
                    continue
                    
                low = user_msg.lower()
                if low in ["/start", "start"]:
                    agent._print("✅ 已结束预对话，开始输入题目", "green")
                    return
                if low in ["/exit", "exit", "q", "quit"]:
                    agent._print("↩️ 已退出预对话", "yellow")
                    return
                
                reply = agent.brain.chat(user_msg)
                agent._print_panel("🤖 回复", reply, "cyan")
                
            except KeyboardInterrupt:
                agent._print("\n⚠️ 已中断预对话", "yellow")
                return

    def _get_task_input() -> str:
        """获取题目描述输入(支持多行)"""
        task_raw = _ask_text(
            "🎯 LIN >>> ",
            "🎯 >>> "
        )
        
        is_block, processed = _detect_multiline_trigger(task_raw)
        
        if is_block:
            first_line = processed
            block_content = _read_multiline_block()
            
            if first_line and block_content:
                return f"{first_line}\n{block_content}"
            return first_line or block_content
        
        if processed.lower().startswith("/file"):
            return _load_text_from_file(processed)
        
        return processed

    def _get_context_input() -> Optional[str]:
        """获取上下文输入(支持多行)"""
        has_ctx = input("\n📎 是否有上下文? (y/n): ").strip().lower()
        if has_ctx != 'y':
            return None
        
        ctx_raw = _ask_text(
            "🔗 LIN >>> ",
            "🔗 >>> "
        )
        
        is_block, processed = _detect_multiline_trigger(ctx_raw)
        
        if is_block:
            first_line = processed
            block_content = _read_multiline_block()
            
            if first_line and block_content:
                return f"{first_line}\n{block_content}"
            return first_line or block_content or None
        
        if processed.lower().startswith("/file"):
            result = _load_text_from_file(processed)
            return result or None
        
        return processed or None

    agent._print_banner()
    agent._print("\n  [dim]输入题目描述开始解题，或输入 [bold]/help[/] 查看命令[/]\n", "dim")

    def _show_help():
        agent._print("")
        agent._print("  [bold]命令列表:[/]", "yellow")
        TQ = '"' * 3
        agent._print(f"  [dim]  {TQ}      [/]  多行粘贴模式", "dim")
        agent._print("  [dim]  /block   [/]  多行粘贴模式", "dim")
        agent._print("  [dim]  /file p  [/]  从文件读取内容", "dim")
        agent._print("  [dim]  /chat    [/]  先与 Agent 对话", "dim")
        agent._print("  [dim]  /help    [/]  显示帮助", "dim")
        agent._print("  [dim]  quit     [/]  退出程序", "dim")
        agent._print("")

    while True:
        try:
            print()
            task = _get_task_input()
            
            low = task.lower() if task else ""
            if low in ['quit', 'exit', 'q']:
                break
            if low in ['/chat', 'chat']:
                _chat_before_task()
                continue
            if low in ['/help', 'help', '/?']:
                _show_help()
                continue
            if not task:
                continue
            
            context = _get_context_input()
            
            agent.run(task, context)
            
            agent.brain.reset()
            agent.monitor.reset()
            
        except KeyboardInterrupt:
            agent._print("\n\n👋 再见!", "bold green")
            break
        except EOFError:
            break


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="CyberStrike-Agent - CTF 自动化解题框架",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 直接运行题目
  python main.py -t "Web 题目，目标 http://target.com"
  
  # 带上下文
  python main.py -t "Pwn 题" -c "./challenge/binary"
  
  # 交互模式
  python main.py -i
  
  # 指定模型
  python main.py -t "题目描述" --model gpt-4 --provider openai
        """
    )
    
    parser.add_argument(
        "-t", "--task",
        type=str,
        help="CTF 题目描述"
    )
    
    parser.add_argument(
        "-c", "--context",
        type=str,
        help="额外上下文信息（URL、文件路径等）"
    )
    
    parser.add_argument(
        "-i", "--interactive",
        action="store_true",
        help="进入交互模式"
    )
    
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="LLM 模型名称（不传则使用 .env 中的 LLM_MODEL）"
    )
    
    parser.add_argument(
        "--provider",
        type=str,
        choices=["openai", "anthropic"],
        default="openai",
        help="LLM 提供者 (default: openai)"
    )
    
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=50,
        help="最大迭代次数 (default: 50)"
    )
    
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.7,
        help="LLM 温度参数 (default: 0.7)"
    )

    parser.add_argument(
        "--skills",
        type=str,
        default=None,
        help="手动指定技能，逗号分隔（如: --skills web,crypto）"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=True,
        help="详细输出模式"
    )
    
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="安静模式，减少输出"
    )
    
    args = parser.parse_args()
    
    config = Config.from_env()
    if args.model:
        config.llm.model_name = args.model
    if args.provider:
        config.llm.provider = args.provider
    if args.temperature is not None:
        config.llm.temperature = args.temperature
    if args.max_iterations is not None:
        config.react.max_iterations = args.max_iterations
    
    verbose = not args.quiet
    forced_skills = None
    if args.skills:
        forced_skills = [item.strip() for item in args.skills.split(",") if item.strip()]
    
    try:
        agent = CyberStrikeAgent(config=config, verbose=verbose)
        
        if args.interactive:
            interactive_mode(agent)
        elif args.task:
            flag = agent.run(args.task, args.context, forced_skills=forced_skills)
            if flag:
                print(f"\n🎉 成功! Flag: {flag}")
                sys.exit(0)
            else:
                print("\n❌ 未能找到 Flag")
                sys.exit(1)
        else:
            parser.print_help()
            
    except Exception as e:
        print(f"\n❌ 错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
