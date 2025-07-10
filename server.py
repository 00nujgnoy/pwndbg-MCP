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
    
    # 바이너리 경로 검증
    if binary_path and not os.path.exists(binary_path):
        return f"Error: 바이너리 파일을 찾을 수 없습니다: {binary_path}"
    
    try:
        # GDB 명령어 구성
        gdb_cmd = ["gdb", "-q"]
        
        if binary_path:
            gdb_cmd.append(binary_path)
            success_msg = f"✓ GDB 세션 시작됨 (바이너리: {binary_path})"
        else:
            success_msg = "✓ GDB 세션 시작됨 (바이너리 없음)"
        
        # 기본 설정으로 GDB 시작
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
        
        is_connected = True
        return success_msg
        
    except Exception as e:
        # 실패시 상태 초기화
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

@mcp.tool()
def execute_pwndbg_command(command: str) -> str:
    """pwndbg 전용 명령어 실행 (heap, bins, checksec 등)"""
    global gdb_process, is_connected
    
    if not is_connected:
        return "Error: GDB 세션이 연결되지 않음. start_debug_session()을 먼저 실행하세요."
    
    try:
        # 명령어 전송
        gdb_process.stdin.write(f"{command}\n")
        gdb_process.stdin.flush()
        
        # 출력 읽기 - 타임아웃 기반으로 수정
        import time
        import select
        
        output_lines = []
        start_time = time.time()
        timeout = 5.0  # 5초 타임아웃
        
        while time.time() - start_time < timeout:
            # select를 사용해서 읽을 데이터가 있는지 확인
            ready, _, _ = select.select([gdb_process.stdout], [], [], 0.1)
            
            if ready:
                line = gdb_process.stdout.readline()
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

@mcp.tool()
def analyze_heap_status() -> str:
    """전체 heap 상태 요약 분석 - heap, arena, malloc_stats 조합"""
    global is_connected
    
    if not is_connected:
        return "Error: GDB 세션이 연결되지 않음. start_debug_session()을 먼저 실행하세요."
    
    try:
        results = []
        results.append("=== HEAP STATUS ANALYSIS ===\n")
        
        # 1. 기본 heap 정보
        heap_result = execute_pwndbg_command("heap")
        if "Error:" not in heap_result:
            results.append("📊 Heap Layout:")
            results.append(heap_result)
            results.append("")
        
        # 2. Arena 정보
        arena_result = execute_pwndbg_command("arena")
        if "Error:" not in arena_result:
            results.append("🏟️ Arena Information:")
            results.append(arena_result)
            results.append("")
        
        # 3. malloc_stats 정보 (가능한 경우)
        stats_result = execute_pwndbg_command("p malloc_stats()")
        if "Error:" not in stats_result and "No symbol" not in stats_result:
            results.append("📈 Malloc Statistics:")
            results.append(stats_result)
            results.append("")
        
        # 4. 요약 정보 생성
        results.append("📋 Summary:")
        if "heap" in heap_result.lower():
            results.append("✓ Heap is active and accessible")
        else:
            results.append("⚠️ Heap may not be initialized or accessible")
            
        return "\n".join(results)
        
    except Exception as e:
        return f"Heap 상태 분석 실패: {e}"

@mcp.tool()
def examine_bins() -> str:
    """모든 bin 상태 검사 (fastbin, smallbin, largebin, unsortedbin, tcache)"""
    global is_connected
    
    if not is_connected:
        return "Error: GDB 세션이 연결되지 않음. start_debug_session()을 먼저 실행하세요."
    
    try:
        results = []
        results.append("=== BINS ANALYSIS ===\n")
        
        # 1. 전체 bins 상태
        bins_result = execute_pwndbg_command("bins")
        if "Error:" not in bins_result:
            results.append("🗂️ All Bins Overview:")
            results.append(bins_result)
            results.append("")
        
        # 2. tcache 상세 (glibc 2.26+)
        tcache_result = execute_pwndbg_command("tcache")
        if "Error:" not in tcache_result and "not available" not in tcache_result.lower():
            results.append("⚡ Tcache Details:")
            results.append(tcache_result)
            results.append("")
        
        # 3. fastbins 상세
        fastbins_result = execute_pwndbg_command("fastbins")
        if "Error:" not in fastbins_result:
            results.append("🏃 Fastbins Details:")
            results.append(fastbins_result)
            results.append("")
        
        # 4. smallbins 상세
        smallbins_result = execute_pwndbg_command("smallbins")
        if "Error:" not in smallbins_result:
            results.append("📦 Smallbins Details:")
            results.append(smallbins_result)
            results.append("")
        
        # 5. largebins 상세
        largebins_result = execute_pwndbg_command("largebins")
        if "Error:" not in largebins_result:
            results.append("📊 Largebins Details:")
            results.append(largebins_result)
            results.append("")
        
        # 6. unsortedbin 상세
        unsorted_result = execute_pwndbg_command("unsortedbin")
        if "Error:" not in unsorted_result:
            results.append("🔄 Unsorted Bin Details:")
            results.append(unsorted_result)
            results.append("")
        
        # 7. 분석 요약
        results.append("📋 Bins Summary:")
        bin_types = []
        if "chunks" in tcache_result.lower() or "entries" in tcache_result.lower():
            bin_types.append("✓ Tcache has entries")
        if "0x" in fastbins_result:
            bin_types.append("✓ Fastbins have chunks")
        if "0x" in smallbins_result:
            bin_types.append("✓ Smallbins have chunks")
        if "0x" in largebins_result:
            bin_types.append("✓ Largebins have chunks")
        if "0x" in unsorted_result:
            bin_types.append("✓ Unsorted bin has chunks")
            
        if bin_types:
            results.extend(bin_types)
        else:
            results.append("ℹ️ All bins appear to be empty")
            
        return "\n".join(results)
        
    except Exception as e:
        return f"Bins 분석 실패: {e}"

@mcp.tool()
def check_heap_chunks(address: str = "") -> str:
    """특정 주소 또는 전체 heap chunk 상태 확인"""
    global is_connected
    
    if not is_connected:
        return "Error: GDB 세션이 연결되지 않음. start_debug_session()을 먼저 실행하세요."
    
    try:
        results = []
        results.append("=== HEAP CHUNKS ANALYSIS ===\n")
        
        if address:
            # 특정 주소의 chunk 분석
            results.append(f"🎯 Analyzing chunk at address: {address}")
            
            # chunk 명령어로 특정 주소 분석
            chunk_result = execute_pwndbg_command(f"chunk {address}")
            if "Error:" not in chunk_result:
                results.append("📦 Chunk Details:")
                results.append(chunk_result)
                results.append("")
            
            # 해당 주소 주변의 메모리 덤프
            mem_result = execute_pwndbg_command(f"x/8gx {address}")
            if "Error:" not in mem_result:
                results.append("🔍 Memory Dump:")
                results.append(mem_result)
                results.append("")
                
        else:
            # 전체 heap chunks 분석
            results.append("📋 All Heap Chunks Overview:")
            
            # heap chunks 명령어
            chunks_result = execute_pwndbg_command("heap chunks")
            if "Error:" not in chunks_result:
                results.append("🧱 Heap Chunks:")
                results.append(chunks_result)
                results.append("")
            
            # vis_heap_chunks (시각화된 heap chunks)
            vis_result = execute_pwndbg_command("vis_heap_chunks")
            if "Error:" not in vis_result and "not found" not in vis_result.lower():
                results.append("👁️ Visual Heap Chunks:")
                results.append(vis_result)
                results.append("")
        
        # chunk 상태 분석
        results.append("📊 Chunk Analysis:")
        chunk_analysis = []
        
        full_output = "\n".join(results)
        if "PREV_INUSE" in full_output:
            chunk_analysis.append("✓ Found chunks with PREV_INUSE flag")
        if "IS_MMAPPED" in full_output:
            chunk_analysis.append("✓ Found mmapped chunks")
        if "NON_MAIN_ARENA" in full_output:
            chunk_analysis.append("✓ Found chunks in non-main arena")
        if "size:" in full_output.lower():
            chunk_analysis.append("✓ Chunk size information available")
            
        if chunk_analysis:
            results.extend(chunk_analysis)
        else:
            results.append("ℹ️ Basic chunk information retrieved")
            
        return "\n".join(results)
        
    except Exception as e:
        return f"Heap chunks 분석 실패: {e}"

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
        global gdb_process, is_connected
        if gdb_process:
            gdb_process.terminate()
        gdb_process = None
        is_connected = False

if __name__ == "__main__":
    main()
