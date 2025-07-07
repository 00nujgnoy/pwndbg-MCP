#!/usr/bin/env python3
"""
pwndbg MCP Server - Bridge between AI agents and pwndbg/GDB
Architecture: AI Agent ←→ MCP Server ←→ GDB Python API ←→ pwndbg
"""

import os
import sys
import json
import argparse
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# MCP Server 설정
mcp = FastMCP("pwndbg-mcp-server", log_level="ERROR")

class GDBSession:
    """GDB 세션을 관리하는 클래스"""
    
    def __init__(self):
        self.gdb_process = None
        self.is_connected = False
        
    def start_gdb(self, binary_path=None):
        """GDB 프로세스 시작"""
        try:
            # GDB 명령어 구성
            gdb_cmd = ["gdb", "-q"]  # -q는 quiet 모드
            
            if binary_path:
                gdb_cmd.append(binary_path)
            
            # pwndbg가 자동으로 로드되도록 설정
            gdb_cmd.extend([
                "-ex", "set confirm off",  # 확인 메시지 비활성화
                "-ex", "set pagination off",  # 페이지네이션 비활성화
            ])
            
            self.gdb_process = subprocess.Popen(
                gdb_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=0
            )
            
            self.is_connected = True
            return True
            
        except Exception as e:
            print(f"GDB 시작 실패: {e}")
            return False
    
    def execute_command(self, command):
        """GDB 명령어 실행"""
        if not self.is_connected or not self.gdb_process:
            return "Error: GDB 세션이 연결되지 않음"
        
        try:
            # 명령어 전송
            self.gdb_process.stdin.write(f"{command}\n")
            self.gdb_process.stdin.flush()
            
            # 결과 읽기 (간단한 구현)
            # 실제로는 더 정교한 출력 파싱이 필요
            output = ""
            return f"Executed: {command}"
            
        except Exception as e:
            return f"Error executing command: {e}"
    
    def close(self):
        """GDB 세션 종료"""
        if self.gdb_process:
            self.gdb_process.terminate()
            self.gdb_process = None
            self.is_connected = False

# 전역 GDB 세션
gdb_session = GDBSession()

@mcp.tool()
def check_pwndbg_connection() -> str:
    """pwndbg 연결 상태 확인"""
    try:
        # pwndbg가 설치되어 있는지 확인
        result = subprocess.run(
            ["which", "gdb"], 
            capture_output=True, 
            text=True
        )
        
        if result.returncode != 0:
            return "Error: GDB가 설치되지 않음"
        
        # pwndbg 설치 여부 확인 (홈 디렉토리의 .gdbinit 또는 pwndbg 경로 확인)
        pwndbg_paths = [
            Path.home() / ".gdbinit",
            Path("/usr/share/pwndbg"),
            Path.home() / "pwndbg"
        ]
        
        pwndbg_found = any(path.exists() for path in pwndbg_paths)
        
        if not pwndbg_found:
            return "Warning: pwndbg가 설치되지 않았을 수 있음"
        
        if gdb_session.is_connected:
            return "✓ pwndbg MCP 서버 연결됨 (GDB 세션 활성)"
        else:
            return "✓ pwndbg 사용 가능 (GDB 세션 비활성)"
            
    except Exception as e:
        return f"Error: {e}"

def get_python_executable():
    """Python 실행 파일 경로 반환"""
    return sys.executable

def print_mcp_config():
    """MCP 설정 JSON 출력"""
    config = {
        "mcpServers": {
            mcp.name: {
                "command": get_python_executable(),
                "args": [__file__],
                "timeout": 1800,
                "disabled": False,
            }
        }
    }
    print(json.dumps(config, indent=2))

def install_mcp_servers(*, uninstall=False, quiet=False):
    """MCP 서버를 여러 클라이언트에 설치"""
    if sys.platform == "win32":
        # WSL에서 실행되므로 Windows 경로는 제외
        configs = {}
    elif sys.platform == "darwin":
        configs = {
            "Claude": (os.path.join(os.path.expanduser("~"), "Library", "Application Support", "Claude"), "claude_desktop_config.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
        }
    elif sys.platform == "linux":
        configs = {
            "Cline": (os.path.join(os.path.expanduser("~"), ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings"), "cline_mcp_settings.json"),
            "Cursor": (os.path.join(os.path.expanduser("~"), ".cursor"), "mcp.json"),
        }
    else:
        print(f"지원하지 않는 플랫폼: {sys.platform}")
        return

    installed = 0
    for name, (config_dir, config_file) in configs.items():
        config_path = os.path.join(config_dir, config_file)
        
        if not os.path.exists(config_dir):
            action = "제거" if uninstall else "설치"
            if not quiet:
                print(f"{name} {action} 건너뜀\n  설정: {config_path} (찾을 수 없음)")
            continue
            
        if not os.path.exists(config_path):
            config = {}
        else:
            with open(config_path, "r") as f:
                data = f.read().strip()
                if len(data) == 0:
                    config = {}
                else:
                    try:
                        config = json.loads(data)
                    except json.JSONDecodeError:
                        if not quiet:
                            print(f"{name} 건너뜀\n  설정: {config_path} (잘못된 JSON)")
                        continue
        
        if "mcpServers" not in config:
            config["mcpServers"] = {}
        
        mcp_servers = config["mcpServers"]
        
        if uninstall:
            if mcp.name not in mcp_servers:
                if not quiet:
                    print(f"{name} 제거 건너뜀\n  설정: {config_path} (설치되지 않음)")
                continue
            del mcp_servers[mcp.name]
        else:
            mcp_servers[mcp.name] = {
                "command": get_python_executable(),
                "args": [__file__],
                "timeout": 1800,
                "disabled": False,
            }
        
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        
        if not quiet:
            action = "제거됨" if uninstall else "설치됨"
            print(f"{name} MCP 서버 {action} (재시작 필요)\n  설정: {config_path}")
        
        installed += 1
    
    if not uninstall and installed == 0:
        print("설치된 MCP 서버가 없습니다. 지원하지 않는 MCP 클라이언트의 경우 다음 설정을 사용하세요:\n")
        print_mcp_config()

def main():
    parser = argparse.ArgumentParser(description="pwndbg MCP Server")
    parser.add_argument("--install", action="store_true", help="MCP 서버 설치")
    parser.add_argument("--uninstall", action="store_true", help="MCP 서버 제거")
    parser.add_argument("--config", action="store_true", help="MCP 설정 JSON 생성")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP 전송 프로토콜 (stdio 또는 http://127.0.0.1:8744)")
    
    args = parser.parse_args()
    
    if args.install and args.uninstall:
        print("설치와 제거를 동시에 할 수 없습니다")
        return
    
    if args.install:
        install_mcp_servers()
        return
    
    if args.uninstall:
        install_mcp_servers(uninstall=True)
        return
    
    if args.config:
        print_mcp_config()
        return
    
    try:
        if args.transport == "stdio":
            mcp.run(transport="stdio")
        else:
            from urllib.parse import urlparse
            url = urlparse(args.transport)
            if url.hostname is None or url.port is None:
                raise Exception(f"잘못된 전송 URL: {args.transport}")
            mcp.settings.host = url.hostname
            mcp.settings.port = url.port
            print(f"MCP 서버가 http://{mcp.settings.host}:{mcp.settings.port}/sse 에서 실행 중")
            mcp.settings.log_level = "INFO"
            mcp.run(transport="sse")
    except KeyboardInterrupt:
        pass
    finally:
        # 정리 작업
        gdb_session.close()

if __name__ == "__main__":
    main()
