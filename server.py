#!/usr/bin/env python3
"""
AI Agent (Claude)
    ↕ JSON-RPC over stdio
MCP Server (Python)
    ↕ subprocess stdin/stdout 
GDB Process + pwndbg
    ↕ text commands
Target Binary
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

@mcp.tool()
def start_debug_session(binary_path: str = "") -> str:
    """GDB 디버깅 세션 시작 (바이너리 경로 선택사항)"""
    global gdb_session
    
    if gdb_session.is_connected:
        return "이미 GDB 세션이 활성화되어 있습니다. stop_debug_session()을 먼저 실행하세요."
    
    try:
        # GDB 명령어 구성
        gdb_cmd = ["gdb", "-q"]
        
        if binary_path and os.path.exists(binary_path):
            gdb_cmd.append(binary_path)
            success_msg = f"✓ GDB 세션 시작됨 (바이너리: {binary_path})"
        else:
            success_msg = "✓ GDB 세션 시작됨 (바이너리 없음)"
        
        # 기본 설정으로 GDB 시작
        gdb_cmd.extend([
            "-ex", "set confirm off",
            "-ex", "set pagination off",
        ])
        
        gdb_session.gdb_process = subprocess.Popen(
            gdb_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        gdb_session.is_connected = True
        return success_msg
        
    except Exception as e:
        return f"GDB 세션 시작 실패: {e}"

@mcp.tool()
def stop_debug_session() -> str:
    """GDB 디버깅 세션 종료"""
    global gdb_session
    
    if not gdb_session.is_connected:
        return "GDB 세션이 활성화되어 있지 않습니다."
    
    try:
        gdb_session.close()
        return "✓ GDB 세션이 종료되었습니다."
    except Exception as e:
        return f"GDB 세션 종료 실패: {e}"

@mcp.tool()
def execute_pwndbg_command(command: str) -> str:
    """pwndbg 전용 명령어 실행 (heap, bins, checksec 등)"""
    global gdb_session
    
    if not gdb_session.is_connected:
        return "Error: GDB 세션이 연결되지 않음. start_debug_session()을 먼저 실행하세요."
    
    try:
        # 명령어 전송
        gdb_session.gdb_process.stdin.write(f"{command}\n")
        gdb_session.gdb_process.stdin.flush()
        
        # 출력 읽기 - 타임아웃 기반으로 수정
        import time
        import select
        
        output_lines = []
        start_time = time.time()
        timeout = 5.0  # 5초 타임아웃
        
        while time.time() - start_time < timeout:
            # select를 사용해서 읽을 데이터가 있는지 확인
            ready, _, _ = select.select([gdb_session.gdb_process.stdout], [], [], 0.1)
            
            if ready:
                line = gdb_session.gdb_process.stdout.readline()
                if line:
                    stripped_line = line.strip()
                    output_lines.append(stripped_line)
                    
                    # GDB 프롬프트가 나타나면 명령어 완료
                    if "(gdb)" in stripped_line:
                        break
                        
                    # 출력이 너무 길면 제한
                    if len(output_lines) > 100:
                        output_lines.append("... (출력이 너무 길어서 생략됨)")
                        break
                else:
                    # EOF 또는 프로세스 종료
                    break
            else:
                # 0.1초 동안 읽을 데이터가 없었다면 잠시 대기
                if output_lines:  # 이미 출력이 있다면 완료된 것으로 간주
                    break
                time.sleep(0.1)
        
        # 결과 정리
        if output_lines:
            # 마지막 (gdb) 프롬프트 제거
            if output_lines and "(gdb)" in output_lines[-1]:
                output_lines.pop()
            
            result = "\n".join(output_lines)
            return result if result.strip() else f"명령어 '{command}' 실행 완료 (출력 없음)"
        else:
            return f"명령어 '{command}' 실행됨 (응답 없음)"
            
    except Exception as e:
        return f"명령어 실행 실패: {e}"

def get_python_executable():
    """Python 실행 파일 경로 반환"""
    return sys.executable

def main():
    parser = argparse.ArgumentParser(description="pwndbg MCP Server")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP 전송 프로토콜 (stdio만 지원)")
    
    args = parser.parse_args()
    
    # MCP 서버 실행
    try:
        mcp.run()
    except KeyboardInterrupt:
        pass
    finally:
        # 정리 작업
        gdb_session.close()

if __name__ == "__main__":
    main()
