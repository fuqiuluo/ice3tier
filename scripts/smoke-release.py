#!/usr/bin/env python3
"""验证编译好的发布程序：版本号、内嵌 WebUI、Linux glibc 兼容上限，以及 Windows zip 结构。

跨平台（Linux / macOS / Windows），只用 Python 标准库。

用法示例：
  python3 scripts/smoke-release.py --bin-dir target/release --check-webui
  python3 scripts/smoke-release.py --bin-dir target/dist/x86_64-unknown-linux-gnu/dist --version 0.1.34 --check-webui --check-glibc 2.28
  python3 scripts/smoke-release.py --bin-dir target/dist/aarch64-unknown-linux-gnu/dist --no-run --check-glibc 2.28
  python  scripts/smoke-release.py --bin-dir target/x86_64-pc-windows-msvc/dist --version 0.1.34 --check-webui --check-zip dist/i3t-windows-x86_64.zip
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

PROGRAMS = ("i3t", "i3t-controller", "i3tctl")
NOT_INCLUDED_MARKER = "没有带 WebUI"


def find_program(bin_dir: Path, name: str) -> Path:
    for suffix in ("", ".exe"):
        candidate = bin_dir / f"{name}{suffix}"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"在 {bin_dir} 下找不到 {name}")


def parse_version_tuple(text: str) -> tuple[int, ...]:
    return tuple(int(part) for part in text.split("."))


def check_files_exist(bin_dir: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for name in PROGRAMS:
        path = find_program(bin_dir, name)
        size = path.stat().st_size
        if size == 0:
            raise RuntimeError(f"{path} 是空文件")
        found[name] = path
        print(f"OK  file {path.name} ({size} bytes)")
    return found


def check_versions(programs: dict[str, Path], expected: str | None) -> None:
    for name, path in programs.items():
        proc = subprocess.run([str(path), "--version"], check=True, capture_output=True, text=True, timeout=15)
        output = proc.stdout.strip()
        if not output:
            raise RuntimeError(f"{name} --version 没有输出")
        reported = output.split()[-1]
        if expected and reported != expected:
            raise RuntimeError(f"{name} --version 报的是 {reported!r}，期望 {expected!r}（完整输出：{output!r}）")
        print(f"OK  {name} --version -> {output}")


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def fetch(opener: urllib.request.OpenerDirector, url: str, timeout: float = 5.0) -> tuple[int, str, bytes]:
    with opener.open(url, timeout=timeout) as resp:
        return resp.status, resp.headers.get("Content-Type", ""), resp.read()


def check_embedded_webui(controller_bin: Path) -> None:
    node_port = free_loopback_port()
    admin_port = free_loopback_port()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    with tempfile.TemporaryDirectory(prefix="i3t-smoke-ctl-") as tmp:
        data_dir = Path(tmp) / "data"
        cmd = [
            str(controller_bin),
            "--data-dir", str(data_dir),
            "--public-addr", f"127.0.0.1:{node_port}",
            "--listen", f"127.0.0.1:{node_port}",
            "--admin-listen", f"127.0.0.1:{admin_port}",
        ]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            base = f"http://127.0.0.1:{admin_port}"
            deadline = time.monotonic() + 30.0
            html = ""
            while True:
                if proc.poll() is not None:
                    out, err = proc.communicate(timeout=5)
                    raise RuntimeError(f"i3t-controller 提前退出（{proc.returncode}）：\nstdout:\n{out}\nstderr:\n{err}")
                try:
                    status, _ctype, body = fetch(opener, f"{base}/")
                    if status == 200:
                        html = body.decode("utf-8", errors="replace")
                        break
                except (urllib.error.URLError, OSError):
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("等了 30 秒，i3t-controller 仍未在管理端口应答")
                time.sleep(0.25)

            if NOT_INCLUDED_MARKER in html:
                raise RuntimeError("i3t-controller 返回的是“未包含 WebUI”占位页，web/dist 没有成功打进二进制")
            if '<div id="root">' not in html:
                raise RuntimeError(f"i3t-controller 返回的首页缺少 <div id=\"root\">：{html[:400]!r}")

            match = re.search(r"""(?:src|href)=["'](/assets/[^"']+\.js)["']""", html)
            if not match:
                raise RuntimeError(f"首页里找不到构建出的 /assets/*.js 引用：{html[:600]!r}")
            asset_path = match.group(1)
            asset_status, asset_ctype, asset_body = fetch(opener, f"{base}{asset_path}")
            if asset_status != 200 or not asset_body or "javascript" not in asset_ctype.lower():
                raise RuntimeError(
                    f"内嵌静态资源 {asset_path} 异常：status={asset_status}, content-type={asset_ctype!r}, len={len(asset_body)}"
                )

            spa_status, _spa_ctype, spa_body = fetch(opener, f"{base}/nodes")
            spa_html = spa_body.decode("utf-8", errors="replace")
            if spa_status != 200 or '<div id="root">' not in spa_html:
                raise RuntimeError(f"SPA 回退路由 /nodes 异常：status={spa_status}")

            print(f"OK  embedded WebUI served on {base}/ (asset {asset_path}, {len(asset_body)} bytes)")
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


def check_glibc(programs: dict[str, Path], max_version: str) -> None:
    ceiling = parse_version_tuple(max_version)
    env = {**os.environ, "LC_ALL": "C"}
    for name, path in programs.items():
        proc = subprocess.run(["readelf", "-V", str(path)], check=True, capture_output=True, text=True, env=env)
        versions = {parse_version_tuple(m.group(1)) for m in re.finditer(r"GLIBC_(\d+(?:\.\d+)+)", proc.stdout)}
        if not versions:
            raise RuntimeError(f"readelf -V 未在 {path} 中找到任何 GLIBC_* 符号版本")
        highest = max(versions)
        highest_str = ".".join(str(x) for x in highest)
        if highest > ceiling:
            too_new = sorted(".".join(str(x) for x in v) for v in versions if v > ceiling)
            raise RuntimeError(f"{name} 依赖高于 GLIBC_{max_version} 的符号版本：{', '.join(too_new)}")
        print(f"OK  {name} max GLIBC_{highest_str} <= GLIBC_{max_version}")


def check_windows_zip(zip_path: Path) -> None:
    if not zip_path.is_file():
        raise FileNotFoundError(f"找不到 Windows 压缩包：{zip_path}")
    required = ("i3t.exe", "wintun.dll", "wintun-LICENSE.txt")
    with zipfile.ZipFile(zip_path, "r") as archive:
        entries = {info.filename: info.file_size for info in archive.infolist()}
    missing = [name for name in required if entries.get(name, 0) <= 0]
    if missing:
        raise RuntimeError(f"{zip_path} 缺少或包含空文件：{missing}（现有：{sorted(entries)}）")
    print(f"OK  zip {zip_path.name}: " + ", ".join(f"{name} ({entries[name]} B)" for name in required))


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke-test built ice3tier release binaries.")
    parser.add_argument("--bin-dir", required=True, type=Path, help="包含 i3t、i3t-controller、i3tctl 的目录")
    parser.add_argument("--version", default=None, help="期望的 --version 版本号")
    parser.add_argument("--check-webui", action="store_true", help="启动 i3t-controller 并验证内嵌 WebUI 可访问")
    parser.add_argument("--check-glibc", default=None, help="检查 Linux ELF 符号最高 GLIBC 版本不超过该值（如 2.28）")
    parser.add_argument("--check-zip", default=None, type=Path, help="校验 Windows 发布 zip 包含 i3t.exe/wintun.dll/许可")
    parser.add_argument("--no-run", action="store_true", help="交叉编译产物无法在本机执行，跳过运行检查")
    args = parser.parse_args()

    programs = check_files_exist(args.bin_dir)
    if not args.no_run:
        check_versions(programs, args.version)
        if args.check_webui:
            check_embedded_webui(programs["i3t-controller"])
    if args.check_glibc:
        check_glibc(programs, args.check_glibc)
    if args.check_zip:
        check_windows_zip(args.check_zip)
    return 0


if __name__ == "__main__":
    sys.exit(main())
