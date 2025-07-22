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

# 전역 GDB 세션 변수
gdb_process = None
is_connected = False

# 허용된 pwndbg 명령어 화이트리스트
ALLOWED_COMMANDS = {
    # 힙 관련
    'heap', 'bins', 'vis_heap_chunks', 'heap chunks', 'chunk', 
    'fastbins', 'smallbins', 'largebins', 'unsortedbin', 'tcache', 'arena',
    
    # 보안 관련
    'checksec', 'vmmap', 'canary', 'piebase', 'procinfo',
    
    # 레지스터/메모리
    'registers', 'regs', 'stack', 'telescope', 'context', 'hexdump',
    
    # 검색/분석
    'search', 'find', 'got', 'plt', 'rop', 'ropper', 'strings',
    
    # 디스어셈블리
    'disasm', 'disassemble', 'nearpc', 'pdisass',
    
    # 실행 제어
    'break', 'continue', 'step', 'next', 'finish', 'run',
    
    # 기본 GDB 명령어
    'info', 'print', 'x', 'examine', 'backtrace', 'bt', 'frame',
    'set', 'show', 'list', 'file', 'load'
}

def _execute_safe_command(command: str) -> str:
    """안전한 명령어 실행"""
    global gdb_process, is_connected
    
    if not is_connected:
        return "Error: GDB 세션이 연결되지 않음. start_debug_session()을 먼저 실행하세요."
    
    try:
        # 명령어 전송
        gdb_process.stdin.write(f"{command}\n")
        gdb_process.stdin.flush()
        
        import time
        import select
        
        output_lines = []
        start_time = time.time()
        timeout = 5.0
        buffer = ""
        
        while time.time() - start_time < timeout:
            ready, _, _ = select.select([gdb_process.stdout], [], [], 0.1)
            
            if ready:
                # 바이트 단위로 읽기
                char = gdb_process.stdout.read(1)
                if char:
                    buffer += char
                    
                    # 라인 완성 시 처리
                    if char == '\n':
                        line = buffer.rstrip('\n\r')
                        if line:  # 빈 줄 무시
                            output_lines.append(line)
                        buffer = ""
                        
                        # 프롬프트 감지 (라인 끝에서)
                        if line.endswith("pwndbg>") :
                            break
                    
                    # 프롬프트 감지 (개행 없는 경우)
                    elif buffer.endswith("pwndbg>") :
                        if buffer.strip():
                            output_lines.append(buffer.rstrip())
                        break
                        
                    # 출력 제한
                    if len(output_lines) > 200:
                        output_lines.append("... (출력 제한: 200줄)")
                        break
                else:
                    # EOF 또는 프로세스 종료
                    break
            else:
                # 대기 중이지만 출력이 있으면 계속
                if output_lines and buffer == "":
                    time.sleep(0.05)  # 짧은 대기 후 종료 판단
                    ready, _, _ = select.select([gdb_process.stdout], [], [], 0.01)
                    if not ready:
                        break
                else:
                    time.sleep(0.1)
        
        # 버퍼에 남은 내용 처리
        if buffer.strip():
            output_lines.append(buffer.strip())
        
        # 결과 반환
        if output_lines:
            result = "\n".join(output_lines)
            return result if result.strip() else f"명령어 '{command}' 실행 완료"
        else:
            return f"명령어 '{command}' 실행됨 (응답 없음)"
            
    except Exception as e:
        return f"명령어 실행 실패: {e}"

@mcp.tool()
def check_pwndbg_connection() -> str:
    """pwndbg 연결 상태 확인"""
    try:
        result = subprocess.run(["which", "gdb"], capture_output=True, text=True)
        if result.returncode != 0:
            return "Error: GDB가 설치되지 않음"
        
        pwndbg_paths = [
            Path.home() / ".gdbinit",
            Path("/usr/share/pwndbg"),
            Path.home() / "pwndbg"
        ]
        
        pwndbg_found = any(path.exists() for path in pwndbg_paths)
        if not pwndbg_found:
            return "Warning: pwndbg가 설치되지 않았을 수 있음"
        
        if is_connected:
            return "✓ pwndbg MCP 서버 연결됨 (GDB 세션 활성)"
        else:
            return "✓ pwndbg 사용 가능 (GDB 세션 비활성)"
            
    except Exception as e:
        return f"Error: {e}"

@mcp.tool()
def start_debug_session(binary_path: str = "") -> str:
    """GDB 디버깅 세션 시작 (바이너리 경로 선택사항)"""
    global gdb_process, is_connected
    
    if is_connected:
        return "이미 GDB 세션이 활성화되어 있습니다. stop_debug_session()을 먼저 실행하세요."
    
    if binary_path and not os.path.exists(binary_path):
        return f"Error: 바이너리 파일을 찾을 수 없습니다: {binary_path}"
    
    try:
        gdb_cmd = ["gdb", "-q"]
        
        if binary_path:
            gdb_cmd.append(binary_path)
            success_msg = f"✓ GDB 세션 시작됨 (바이너리: {binary_path})"
        else:
            success_msg = "✓ GDB 세션 시작됨 (바이너리 없음)"
        
        gdb_cmd.extend([
            "-ex", "set confirm off",
            "-ex", "set pagination off",
        ])
        
        gdb_process = subprocess.Popen(
            gdb_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # 초기화 메시지 읽기 및 프롬프트 대기
        import time
        import select
        
        start_time = time.time()
        timeout = 5.0
        buffer = ""
        
        while time.time() - start_time < timeout:
            ready, _, _ = select.select([gdb_process.stdout], [], [], 0.1)
            
            if ready:
                char = gdb_process.stdout.read(1)
                if char:
                    buffer += char
                    # 프롬프트 감지 (완전한 프롬프트 대기)
                    if buffer.endswith("pwndbg>") :
                        break
                else:
                    break
            else:
                time.sleep(0.1)
        
        # 프로세스 상태 확인
        if gdb_process.poll() is not None:
            gdb_process = None
            is_connected = False
            return "Error: GDB 프로세스가 예기치 않게 종료되었습니다."
        
        is_connected = True
        return success_msg
        
    except Exception as e:
        gdb_process = None
        is_connected = False
        return f"GDB 세션 시작 실패: {e}"

@mcp.tool()
def stop_debug_session() -> str:
    """GDB 디버깅 세션 종료"""
    global gdb_process, is_connected
    
    if not is_connected:
        return "GDB 세션이 활성화되어 있지 않습니다."
    
    try:
        if gdb_process:
            gdb_process.terminate()
        gdb_process = None
        is_connected = False
        return "✓ GDB 세션이 종료되었습니다."
    except Exception as e:
        return f"GDB 세션 종료 실패: {e}"

# ============================================================================
# 힙 분석 툴들
# ============================================================================

@mcp.tool()
def heap() -> str:
    """힙 상태 전체 요약"""
    return _execute_safe_command("heap")

@mcp.tool()
def bins() -> str:
    """모든 bin 상태 확인"""
    return _execute_safe_command("bins")

@mcp.tool()
def vis() -> str:
    """힙 청크 시각화"""
    return _execute_safe_command("vis_heap_chunks")

@mcp.tool()
def malloc_chunk(address: str) -> str:
    """특정 청크 분석"""
    if not address:
        return "Error: 주소를 입력해주세요"
    return _execute_safe_command(f"chunk {address}")

# ============================================================================
# 바이너리 보안 툴들
# ============================================================================

@mcp.tool()
def checksec() -> str:
    """바이너리 보안 기능 확인"""
    return _execute_safe_command("checksec")

@mcp.tool()
def vmmap() -> str:
    """메모리 매핑 정보"""
    return _execute_safe_command("vmmap")

@mcp.tool()
def canary() -> str:
    """스택 카나리 확인"""
    return _execute_safe_command("canary")

# ============================================================================
# 레지스터/메모리 툴들
# ============================================================================

@mcp.tool()
def regs() -> str:
    """레지스터 상태 확인"""
    return _execute_safe_command("registers")

@mcp.tool()
def stack() -> str:
    """스택 내용 확인"""
    return _execute_safe_command("stack")

@mcp.tool()
def telescope(address: str = "") -> str:
    """메모리 덤프 (포인터 추적)"""
    if address:
        return _execute_safe_command(f"telescope {address}")
    return _execute_safe_command("telescope")

@mcp.tool()
def context() -> str:
    """전체 컨텍스트 확인"""
    return _execute_safe_command("context")

# ============================================================================
# 검색/분석 툴들
# ============================================================================

@mcp.tool()
def search(pattern: str) -> str:
    """메모리 값 검색"""
    if not pattern:
        return "Error: 검색할 패턴을 입력해주세요"
    return _execute_safe_command(f"search {pattern}")

@mcp.tool()
def find(pattern: str) -> str:
    """패턴 검색"""
    if not pattern:
        return "Error: 검색할 패턴을 입력해주세요"
    return _execute_safe_command(f"find {pattern}")

@mcp.tool()
def got() -> str:
    """GOT 테이블 확인"""
    return _execute_safe_command("got")

@mcp.tool()
def plt() -> str:
    """PLT 테이블 확인"""
    return _execute_safe_command("plt")

@mcp.tool()
def rop() -> str:
    """ROP 가젯 검색"""
    return _execute_safe_command("rop")


# ============================================================================
# 예외 처리 툴
# ============================================================================

@mcp.tool()
def execute_custom_command(command: str) -> str:
    """AI가 기본 툴로 해결할 수 없는 경우를 위한 사용자 정의 명령어 실행 (안전성 검증됨)"""
    if not command:
        return "Error: 명령어를 입력해주세요"
    
    # 명령어 안전성 검증
    command_parts = command.split()
    if not command_parts:
        return "Error: 올바른 명령어를 입력해주세요"
    
    base_command = command_parts[0]
    
    # 화이트리스트 검증
    if base_command not in ALLOWED_COMMANDS:
        return f"Error: 허용되지 않은 명령어입니다. 사용 가능한 명령어: {', '.join(sorted(ALLOWED_COMMANDS))}"
    
    # 위험한 명령어 패턴 검사
    dangerous_patterns = [
        'rm', 'del', 'format', 'mkfs', 'dd if=', 'dd of=',
        'sudo', 'su', 'chmod +x', 'wget', 'curl', 'nc ', 'netcat',
        'python -c', 'perl -e', 'ruby -e', 'bash -c', 'sh -c',
        '$(', '`', '&&', '||', ';', '|', '>', '>>', '<'
    ]
    
    for pattern in dangerous_patterns:
        if pattern in command.lower():
            return f"Error: 보안상 위험한 패턴이 감지되었습니다: {pattern}"
    
    # 명령어 길이 제한 (너무 긴 명령어 방지)
    if len(command) > 200:
        return "Error: 명령어가 너무 깁니다 (최대 200자)"
    
    # 안전성 검증 통과 시 실행
    try:
        result = _execute_safe_command(command)
        return f"✓ 사용자 정의 명령어 실행됨: {command}\n\n{result}"
    except Exception as e:
        return f"사용자 정의 명령어 실행 실패: {e}"

@mcp.tool()
def list_available_commands() -> str:
    """사용 가능한 모든 pwndbg 명령어 목록 조회"""
    commands_by_category = {
        "힙 분석": ["heap", "bins", "vis_heap_chunks", "chunk", "fastbins", "smallbins", "largebin", "unsortedbin", "tcache", "arena"],
        "보안 분석": ["checksec", "vmmap", "canary", "piebase", "procinfo"],
        "레지스터/메모리": ["registers", "regs", "stack", "telescope", "context", "hexdump"],
        "검색/분석": ["search", "find", "got", "plt", "rop", "ropper", "strings"],
        "디스어셈블리": ["disasm", "disassemble", "nearpc", "pdisass"],
        "실행 제어": ["break", "continue", "step", "next", "finish", "run"],
        "기본 GDB": ["info", "print", "x", "examine", "backtrace", "bt", "frame", "set", "show", "list", "file", "load"]
    }
    
    result = "=== 사용 가능한 pwndbg 명령어 목록 ===\n\n"
    
    for category, commands in commands_by_category.items():
        result += f"📋 {category}:\n"
        for cmd in commands:
            result += f"  • {cmd}\n"
        result += "\n"
    
    result += "⚠️ 참고: execute_custom_command() 툴을 사용하여 위 명령어들을 직접 실행할 수 있습니다.\n"
    result += "하지만 각 기능별로 전용 툴을 사용하는 것을 권장합니다."
    
    return result

def main():
    parser = argparse.ArgumentParser(description="pwndbg MCP Server")
    parser.add_argument("--transport", type=str, default="stdio", help="MCP 전송 프로토콜 (stdio만 지원)")
    
    args = parser.parse_args()
    
    try:
        mcp.run()
    except KeyboardInterrupt:
        pass
    finally:
        global gdb_process, is_connected
        if gdb_process:
            gdb_process.terminate()
        gdb_process = None
        is_connected = False

if __name__ == "__main__":
    main()