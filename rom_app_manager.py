#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ROM APP Manager - 独立版 (支持 Android 1.0 ~ 16)
从 ROM 解包目录中扫描、查看、卸载和添加系统 APP

用法：py rom_app_manager.py

支持的 APK 解析工具（放在 phone_tool/ 下，按优先级）：
  1. aapt2.exe  — 推荐，支持全版本 Android（含 Android 16）
  2. aapt_tool.exe — 回退，支持到 Android 8.x APK
"""

import os
import re
import sys
import shutil
import subprocess
import threading
import zipfile
import struct
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
import urllib.request
import urllib.parse
import webbrowser
import json
import ssl

# 声明 DPI 感知：阻止 Windows 自动放大 UI（否则 PhotoImage 会被放大显示）
try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per-Monitor DPI Aware
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PHONE_TOOL_DIR = SCRIPT_DIR / "phone_tool"

# 按优先级查找 aapt 工具
AAPT_CANDIDATES = [
    PHONE_TOOL_DIR / "aapt2.exe",
    PHONE_TOOL_DIR / "aapt_tool.exe",
    PHONE_TOOL_DIR / "aapt.exe",
]
AAPT_PATH = next((p for p in AAPT_CANDIDATES if p.exists()), None)

# ROM 中扫描的目录（覆盖 Android 1.0 ~ 16 所有分区）
APP_DIRS = [
    ("system/app",         "app"),
    ("system/priv-app",    "priv-app"),
    ("system_ext/app",     "app"),          # Android 10+
    ("system_ext/priv-app","priv-app"),     # Android 10+
    ("vendor/app",         "app"),          # Android 8.0+
    ("vendor/priv-app",    "priv-app"),     # Android 8.0+
    ("product/app",        "app"),          # Android 10+
    ("product/priv-app",   "priv-app"),     # Android 10+
    ("odm/app",            "app"),          # Android 10+
    ("odm/priv-app",       "priv-app"),     # Android 10+
    ("oem/app",            "app"),          # 厂商自定义
    ("system/vendor/app",  "app"),          # Android 7.x（vendor 嵌套在 system 内）
]

ICON_SIZE = 24

# 全局 SSL 上下文（跳过证书验证，解决 Windows Python SSL 问题）
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

def safe_urlopen(url, data=None, headers=None, timeout=15, method=None):
    """安全的 URL 请求，自动处理 SSL 证书问题"""
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    return urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX)

def normalize_api_url(url: str) -> str:
    """自动补全 API 路径，兼容只填域名的用户（OpenAI 兼容格式）"""
    url = url.rstrip("/")
    if "/v1/" in url or "/chat/completions" in url:
        return url
    return url + "/v1/chat/completions"


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass
class ApkInfo:
    app_name: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    apk_path: str = ""           # APK 文件绝对路径
    app_dir: str = ""            # 相对于 ROM 根目录的路径
    app_type: str = "app"        # app 或 priv-app
    file_size: int = 0           # APK 文件大小
    is_split: bool = False       # 是否为 split APK
    shared_uid: str = ""         # sharedUserId（如 android.uid.system）
    permissions: list = field(default_factory=list)  # APK 声明的权限列表
    icon_data: bytes = field(default=b"", repr=False)  # PNG 图标数据


# ---------------------------------------------------------------------------
# 二进制 AndroidManifest.xml 简易解析器（提取包名和版本）
# ---------------------------------------------------------------------------
class ManifestParser:
    """从 APK 内直接解析二进制 AndroidManifest.xml，提取基础信息。
    无需 aapt 也能工作，作为最终回退。"""

    @staticmethod
    def parse_from_apk(apk_path: str) -> Optional[dict]:
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                data = zf.read("AndroidManifest.xml")
        except Exception:
            return None

        if len(data) < 8 or data[:4] != b"\x03\x00\x08\x00":
            return None

        info = {}

        # 提取包名（UTF-16LE 字符串，在 header 后的 string pool 中）
        try:
            # String pool header
            sp_type, sp_header_size = struct.unpack_from("<HH", data, 8)
            if sp_type != 0x0001:
                return None
            sp_size, sp_string_count, sp_style_count, sp_flags = struct.unpack_from("<IIII", data, 12)
            sp_strings_start, sp_styles_start = struct.unpack_from("<II", data, 28)

            is_utf8 = bool(sp_flags & (1 << 8))

            # String offsets array starts after the string pool header
            so_start = 8 + sp_header_size
            strings_data_start = 8 + sp_strings_start

            # Read string offsets
            offsets = []
            for i in range(sp_string_count):
                off, = struct.unpack_from("<I", data, so_start + i * 4)
                offsets.append(off)

            def read_string(idx):
                if idx >= len(offsets):
                    return ""
                pos = strings_data_start + offsets[idx]
                if pos >= len(data):
                    return ""
                if is_utf8:
                    # UTF-8 string: skip char count (1-2 bytes), byte count (1-2 bytes)
                    charlen = data[pos]
                    pos += 1
                    if charlen & 0x80:
                        pos += 1
                    bytelen = data[pos]
                    pos += 1
                    if bytelen & 0x80:
                        bytelen = ((bytelen & 0x7F) << 8) | data[pos]
                        pos += 1
                    end = min(pos + bytelen, len(data))
                    null_pos = data.find(b'\x00', pos, end)
                    if null_pos != -1:
                        end = null_pos
                    return data[pos:end].decode("utf-8", errors="replace")
                else:
                    # UTF-16LE string
                    slen, = struct.unpack_from("<H", data, pos)
                    pos += 2
                    if slen & 0x8000:
                        slen = ((slen & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                        pos += 2
                    end = pos + slen * 2
                    null_pos = data.find(b'\x00\x00', pos, end)
                    if null_pos != -1 and (null_pos - pos) % 2 == 0:
                        end = null_pos
                    return data[pos:end].decode("utf-16-le", errors="replace")

            # 第一个字符串通常是包名
            if sp_string_count > 0:
                info["package"] = read_string(0)

        except Exception:
            pass

        return info if info else None


# ---------------------------------------------------------------------------
# APK 解析
# ---------------------------------------------------------------------------
class ApkParser:
    """解析 APK 信息，自动选择可用工具，支持 Android 1.0 ~ 16"""

    @staticmethod
    def parse(apk_path: str) -> Optional[ApkInfo]:
        info, _ = ApkParser.parse_with_icon(apk_path)
        return info

    @staticmethod
    def parse_with_icon(apk_path: str) -> tuple:
        """解析 APK，返回 (info, icon_candidates_from_aapt)。
        icon_candidates 供图标提取复用，避免重复调用 aapt。"""
        info = ApkInfo(apk_path=apk_path)
        icon_candidates = []

        # 尝试 aapt2 / aapt（只调用一次！）
        output = ApkParser._run_aapt(apk_path)
        if output:
            ApkParser._parse_aapt_output(info, output)
            icon_candidates = ApkParser.get_icon_candidates(output)
        else:
            manifest_info = ManifestParser.parse_from_apk(apk_path)
            if manifest_info and "package" in manifest_info:
                info.package_name = manifest_info["package"]

        try:
            info.file_size = os.path.getsize(apk_path)
        except OSError:
            pass

        if not info.package_name:
            info.package_name = Path(apk_path).stem
        if not info.app_name:
            info.app_name = info.package_name

        return info, icon_candidates

    @staticmethod
    def _run_aapt(apk_path: str) -> str:
        if not AAPT_PATH or not AAPT_PATH.exists():
            return ""
        try:
            result = subprocess.run(
                [str(AAPT_PATH), "d", "badging", apk_path],
                capture_output=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            return result.stdout.decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _parse_aapt_output(info: ApkInfo, output: str):
        if not output.strip():
            return

        # 包名（aapt / aapt2 通用）
        m = re.search(r"package:\s*(?:name=)?'([^']*)'", output)
        if m:
            info.package_name = m.group(1)

        # 版本号（兼容 aapt2 格式 versionCode='...' 和 aapt 格式 versionCode='...'）
        m = re.search(r"versionCode=(?:int=)?'(\d+)'", output)
        if m:
            info.version_code = m.group(1)
        m = re.search(r"versionName=(?:S=)?'([^']*)'", output)
        if m:
            info.version_name = m.group(1)

        # SDK 版本（兼容 aapt `sdkVersion:'N'` 和 aapt2 `minSdkVersion:'N'`）
        m = re.search(r"(?:sdkVersion|minSdkVersion)[:=](?:int=)?'(\d+)'", output)
        if m:
            info.min_sdk = m.group(1)
        m = re.search(r"targetSdkVersion[:=](?:int=)?'(\d+)'", output)
        if m:
            info.target_sdk = m.group(1)

        # 应用名称（支持多语言标签和 aapt2 格式）
        # 优先：无后缀的 application-label
        m = re.search(r"application-label:'([^']*)'", output)
        if m:
            info.app_name = m.group(1)
        else:
            # aapt2 格式
            m = re.search(r"application-label(?:-\w+)?:'([^']*)'", output)
            if m:
                info.app_name = m.group(1)
            else:
                # aapt2 有时用 label= 在 application 行
                m = re.search(r"application:\s.*label='([^']*)'", output)
                if m:
                    info.app_name = m.group(1)

        # sharedUserId
        m = re.search(r"sharedUserId=(?:S=)?'([^']*)'", output)
        if m:
            info.shared_uid = m.group(1)

        # 权限列表
        info.permissions = re.findall(r"uses-permission:\s+name='([^']*)'", output)

    @staticmethod
    def get_icon_candidates(output: str) -> list[str]:
        """从 aapt 输出中提取图标路径候选列表"""
        candidates = []
        # aapt 格式: application-icon-160:'res/...'
        for m in re.finditer(r"application-icon-\d+:'([^']*)'", output):
            candidates.append(m.group(1))
        # aapt2 格式: icon= 或 application-icon=
        for m in re.finditer(r"(?:application-)?icon(?:-\d+)?:'([^']*)'", output):
            path = m.group(1)
            if path not in candidates:
                candidates.append(path)
        return candidates


# ---------------------------------------------------------------------------
# 图标提取
# ---------------------------------------------------------------------------
class IconExtractor:
    """从 APK 中提取应用图标，支持 Android 1.0 ~ 16 的所有图标格式"""

    @staticmethod
    def extract_icon(apk_path: str, icon_candidates: list = None) -> bytes:
        """从 APK 中提取应用图标。
        icon_candidates: 由 ApkParser.parse_with_icon 返回，避免重复调用 aapt。"""
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                names = set(zf.namelist())

                # 1) 使用传入的图标候选路径（如果有的话）
                if icon_candidates is None:
                    icon_candidates = []
                    output = ApkParser._run_aapt(apk_path)
                    if output:
                        icon_candidates = ApkParser.get_icon_candidates(output)

                # 优先使用候选路径（aapt 解析结果最准确）
                for candidate in icon_candidates:
                    if candidate in names:
                        data = zf.read(candidate)
                        if data[:4] == b"\x89PNG":
                            return data
                        # 如果是 XML（adaptive icon），尝试解析
                        if data[:1] == b"<" or data[:4] == b"\x03\x00\x08\x00":
                            png = IconExtractor._resolve_xml_icon(zf, names, data, candidate)
                            if png:
                                return png

                # 2) 小尺寸 mipmap/drawable PNG（优先选小图标，避免缩放）
                #    ldpi=36px, mdpi=48px, hdpi=72px → 直接使用，无需缩放
                for density in ["ldpi", "mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"]:
                    for prefix in ["mipmap", "drawable"]:
                        for name in ["ic_launcher.png", "ic_launcher_round.png", "icon.png"]:
                            path = f"res/{prefix}-{density}/{name}"
                            if path in names:
                                data = zf.read(path)
                                if data[:4] == b"\x89PNG":
                                    return data

                # 3) 任何 mipmap-anydpi 中的自适应图标 XML
                for path in sorted(names):
                    if "mipmap-anydpi" in path and ("ic_launcher" in path) and path.endswith(".xml"):
                        data = zf.read(path)
                        png = IconExtractor._resolve_xml_icon(zf, names, data, path)
                        if png:
                            return png

                # 4) 最后回退：任何 ic_launcher PNG（优先小文件名排序）
                for path in sorted(names):
                    if "ic_launcher" in path and path.endswith(".png"):
                        data = zf.read(path)
                        if data[:4] == b"\x89PNG":
                            return data

                # 5) icon.png 回退
                for path in sorted(names, reverse=True):
                    if path.endswith("/icon.png") and ("drawable" in path or "mipmap" in path):
                        data = zf.read(path)
                        if data[:4] == b"\x89PNG":
                            return data

        except Exception:
            pass
        return b""

    @staticmethod
    def _resolve_xml_icon(zf, names: set, xml_data: bytes, xml_path: str) -> bytes:
        """尝试从自适应图标 XML 中提取前景 PNG。"""
        try:
            # 从同目录下找前景图
            dirname = os.path.dirname(xml_path)
            for suffix in ["ic_launcher_foreground.png", "ic_launcher_adaptive_fore.png"]:
                fg_path = f"{dirname}/{suffix}"
                if fg_path in names:
                    data = zf.read(fg_path)
                    if data[:4] == b"\x89PNG":
                        return data

            # 在 res/drawable* 和 res/mipmap* 中搜索前景 PNG
            for density in ["xxxhdpi", "xxhdpi", "xhdpi", "hdpi", "mdpi"]:
                for prefix in ["mipmap", "drawable"]:
                    fg_path = f"res/{prefix}-{density}/ic_launcher_foreground.png"
                    if fg_path in names:
                        data = zf.read(fg_path)
                        if data[:4] == b"\x89PNG":
                            return data

        except Exception:
            pass
        return b""


# ---------------------------------------------------------------------------
# 主界面
# ---------------------------------------------------------------------------
class RomAppManager:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("ROM APP Manager  v1.0.0 | by wuyu")
        self.root.geometry("1440x780")
        self.root.minsize(1000, 600)

        # Win11 风格主题
        style = ttk.Style()
        available = style.theme_names()
        if "vista" in available:
            style.theme_use("vista")
        elif "winnative" in available:
            style.theme_use("winnative")

        # Win11 配色
        self._bg = "#f3f3f3"
        self._accent = "#0078d4"
        self._text = "#1a1a1a"
        self._surface = "#ffffff"
        self._border = "#e0e0e0"

        self.root.configure(bg=self._bg)

        # 全局字体
        self._font = ("Segoe UI", 9)
        self._font_bold = ("Segoe UI", 9, "bold")

        style.configure(".", font=self._font)
        style.configure("TFrame", background=self._bg)
        style.configure("TLabel", background=self._bg, foreground=self._text)
        style.configure("TButton", padding=(10, 4))
        style.configure("Treeview", rowheight=ICON_SIZE + 4, font=self._font, background=self._surface, fieldbackground=self._surface)
        style.configure("Treeview.Heading", font=self._font_bold, background="#f9f9f9", foreground=self._text)
        style.map("Treeview", background=[("selected", self._accent)], foreground=[("selected", "white")])

        self.rom_root = ""
        self.apps: list[ApkInfo] = []
        self.icon_cache: dict[str, tk.PhotoImage] = {}
        self._default_icon: Optional[tk.PhotoImage] = None
        self._scanning = False
        self._search_after_id = None
        self._ai_click_times = []
        self._version = "v1.0.0"  # 记录AI批量分析按钮的点击时间戳

        self._build_ui()
        self._update_tool_status()

    def _build_ui(self):
        # ---------- 顶部工具栏 ----------
        toolbar = ttk.Frame(self.root, padding=5)
        toolbar.pack(fill=tk.X)

        ttk.Button(toolbar, text="选择解包目录…", command=self._select_dir).pack(side=tk.LEFT, padx=2)
        self.dir_label = ttk.Label(toolbar, text="未选择目录", foreground="gray")
        self.dir_label.pack(side=tk.LEFT, padx=10)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Label(toolbar, text="搜索:").pack(side=tk.LEFT, padx=(5, 2))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", self._on_search)
        ttk.Entry(toolbar, textvariable=self.search_var, width=25).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Button(toolbar, text="刷新", command=self._refresh).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Button(toolbar, text="全选", command=self._check_all).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="反选", command=self._invert_check).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="取消", command=self._uncheck_all).pack(side=tk.LEFT, padx=2)

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        ttk.Button(toolbar, text="AI 配置", command=self._show_ai_settings).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="AI 批量分析", command=self._ai_analyze_all).pack(side=tk.LEFT, padx=2)

        self.stats_label = ttk.Label(toolbar, text="", foreground="blue")
        self.stats_label.pack(side=tk.RIGHT, padx=10)

        # ---------- aapt 工具状态 ----------
        tool_frame = ttk.Frame(self.root, padding=(5, 0))
        tool_frame.pack(fill=tk.X)

        if AAPT_PATH and AAPT_PATH.exists():
            tool_name = AAPT_PATH.name
            if "aapt2" in tool_name:
                tool_text = f"✓ 解析工具: {tool_name} (支持 Android 1.0 ~ 16)"
                tool_color = "green"
            else:
                tool_text = f"⚠ 解析工具: {tool_name} (建议添加 aapt2.exe 以支持 Android 9+)"
                tool_color = "#CC6600"
        else:
            tool_text = "✗ 未找到 aapt 工具，仅显示文件列表（将 aapt2.exe 放入 phone_tool/ 目录）"
            tool_color = "red"

        ttk.Label(tool_frame, text=tool_text, foreground=tool_color, font=("", 8)).pack(side=tk.LEFT)

        # ---------- 主列表（全宽） ----------
        style = ttk.Style()
        style.configure("Treeview", rowheight=ICON_SIZE + 4)

        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))

        columns = ("checked", "ai_category", "ai_desc", "app_name", "package_name", "version", "app_type", "file_size", "app_dir")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings tree", selectmode="extended")
        self._checked: dict[str, bool] = {}
        self._ai_categories: dict[str, str] = {}
        self._sort_col = "app_name"
        self._sort_reverse = False

        self.tree.heading("#0", text="图标")
        self.tree.column("#0", width=48, minwidth=48, stretch=False, anchor=tk.CENTER)

        self.tree.heading("checked", text="✔", command=lambda: self._sort_tree("checked"))
        self.tree.column("checked", width=30, minwidth=30, stretch=False, anchor=tk.CENTER)

        self.tree.heading("ai_category", text="AI评估", command=lambda: self._sort_tree("ai_category"))
        self.tree.column("ai_category", width=80, minwidth=60, anchor=tk.CENTER)

        self.tree.heading("ai_desc", text="说明", command=lambda: self._sort_tree("ai_desc"))
        self.tree.column("ai_desc", width=180, minwidth=80)

        self.tree.heading("app_name", text="应用名称", command=lambda: self._sort_tree("app_name"))
        self.tree.column("app_name", width=180, minwidth=100, anchor=tk.W)

        self.tree.heading("package_name", text="包名", command=lambda: self._sort_tree("package_name"))
        self.tree.column("package_name", width=250, minwidth=150)

        self.tree.heading("version", text="版本", command=lambda: self._sort_tree("version"))
        self.tree.column("version", width=120, minwidth=80)

        self.tree.heading("app_type", text="类型", command=lambda: self._sort_tree("app_type"))
        self.tree.column("app_type", width=70, minwidth=50, anchor=tk.CENTER)

        self.tree.heading("file_size", text="大小", command=lambda: self._sort_tree("file_size"))
        self.tree.column("file_size", width=70, minwidth=50, anchor=tk.E)

        self.tree.heading("app_dir", text="路径", command=lambda: self._sort_tree("app_dir"))
        self.tree.column("app_dir", width=300, minwidth=150)

        vsb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        self.tree.bind("<Double-1>", self._show_detail)
        self.tree.bind("<ButtonRelease-1>", self._on_tree_click)
        self.tree.bind("<Return>", lambda e: self._ctx_ai_analyze())

        # AI 评估颜色标签
        self.tree.tag_configure("ai_safe", foreground="#2e7d32")
        self.tree.tag_configure("ai_caution", foreground="#e65100")
        self.tree.tag_configure("ai_danger", foreground="#c62828")

        # 右键菜单
        self.ctx_menu = tk.Menu(self.root, tearoff=0)
        self.ctx_menu.add_command(label="查看详情", command=lambda: self._show_detail(None))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="百度搜索", command=self._ctx_search_app)
        self.ctx_menu.add_command(label="百度AI", command=self._ctx_search_baidu_ai)
        self.ctx_menu.add_command(label="AI 分析此应用", command=self._ctx_ai_analyze)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="卸载选中 APP", command=self._uninstall_selected)
        self.ctx_menu.add_command(label="添加 APP…", command=self._add_apk)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="导出 CSV…", command=self._export_csv)
        self.ctx_menu.add_command(label="导出 JSON…", command=self._export_json)
        self.ctx_menu.add_command(label="分区统计", command=self._show_partition_stats)
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="打开目录", command=self._open_dir)
        self.tree.bind("<Button-3>", self._popup_menu)

        # ---------- 底部按钮栏 ----------
        btn_bar = ttk.Frame(self.root, padding=5)
        btn_bar.pack(fill=tk.X)

        ttk.Button(btn_bar, text="添加 APP…", command=self._add_apk).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_bar, text="卸载选中 APP", command=self._uninstall_selected).pack(side=tk.LEFT, padx=3)

        ttk.Separator(btn_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        ttk.Button(btn_bar, text="导出 CSV…", command=self._export_csv).pack(side=tk.LEFT, padx=3)
        ttk.Button(btn_bar, text="导出 JSON…", command=self._export_json).pack(side=tk.LEFT, padx=3)

        ttk.Separator(btn_bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        ttk.Button(btn_bar, text="分区统计", command=self._show_partition_stats).pack(side=tk.LEFT, padx=3)

        # ---------- 状态栏 ----------
        status_frame = ttk.Frame(self.root)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=2).pack(
            side=tk.LEFT, fill=tk.X, expand=True
        )

        self.progress_var = tk.DoubleVar(value=0)
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100, length=150, mode='determinate')
        self.progress_bar.pack(side=tk.RIGHT, padx=5, pady=2)
        self.progress_bar.pack_forget()  # 默认隐藏

        self._default_icon = self._create_default_icon()

    # ------------------------------------------------------------------ 右键菜单动作
    def _get_selected_info(self) -> Optional[ApkInfo]:
        """获取右键点击的应用信息"""
        selected = self.tree.selection()
        if not selected:
            return None
        tags = self.tree.item(selected[0], "tags")
        apk_path = tags[0] if tags else ""
        return next((a for a in self.apps if a.apk_path == apk_path), None)

    def _ctx_search_app(self):
        """右键：百度搜索"""
        info = self._get_selected_info()
        if info:
            query = f"{info.app_name} {info.package_name}"
            webbrowser.open(f"https://www.baidu.com/s?wd={urllib.parse.quote(query)}")

    def _ctx_search_baidu_ai(self):
        """右键：百度AI"""
        info = self._get_selected_info()
        if info:
            query = f"请介绍一下安卓应用 {info.app_name}（{info.package_name}）是做什么用的"
            webbrowser.open(f"https://chat.baidu.com/search?word={urllib.parse.quote(query)}")

    def _ctx_ai_analyze(self):
        """右键：AI分析单个应用"""
        info = self._get_selected_info()
        if info:
            self._ai_query_app(info)

    # ------------------------------------------------------------------ AI 功能
    def _get_ai_config_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0] if hasattr(sys, 'frozen') else __file__)), "ai_config.json")

    def _get_ai_cache_path(self) -> str:
        return os.path.join(os.path.dirname(os.path.abspath(sys.argv[0] if hasattr(sys, 'frozen') else __file__)), "ai_cache.json")

    def _load_ai_cache(self) -> dict:
        path = self._get_ai_cache_path()
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save_ai_cache(self, cache: dict):
        path = self._get_ai_cache_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)

    def _load_ai_config(self) -> dict:
        path = self._get_ai_config_path()
        defaults = {"api_url": "", "api_key": "", "model": ""}
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                    defaults.update(cfg)
            except Exception:
                pass
        return defaults

    def _save_ai_config(self, cfg: dict):
        path = self._get_ai_config_path()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)

    def _show_ai_settings(self):
        """AI 配置对话框"""
        cfg = self._load_ai_config()
        win = tk.Toplevel(self.root)
        win.title("AI 配置")
        win.geometry("560x420")
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        frame = ttk.Frame(win, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="AI 接口配置（OpenAI 兼容格式）", font=("", 13, "bold")).grid(row=0, column=0, columnspan=4, pady=(0, 10), sticky="w")

        # 快速预设
        preset_frame = ttk.LabelFrame(frame, text="快速预设", padding=8)
        preset_frame.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        def set_deepseek():
            url_var.set("https://api.deepseek.com/v1/chat/completions")
            model_var.set("deepseek-v4-flash")
        def set_custom():
            url_var.set("")
            model_var.set("")

        ttk.Button(preset_frame, text="DeepSeek", command=set_deepseek, width=15).pack(side=tk.LEFT, padx=3)
        ttk.Button(preset_frame, text="自定义", command=set_custom, width=15).pack(side=tk.LEFT, padx=3)

        # 详细配置
        ttk.Label(frame, text="API 地址:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
        url_var = tk.StringVar(value=cfg.get("api_url", ""))
        ttk.Entry(frame, textvariable=url_var, width=55).grid(row=2, column=1, columnspan=2, sticky="w", pady=5)

        ttk.Label(frame, text="API Key:").grid(row=3, column=0, sticky="e", padx=5, pady=5)
        key_var = tk.StringVar(value=cfg.get("api_key", ""))
        key_entry = ttk.Entry(frame, textvariable=key_var, width=48, show="*")
        key_entry.grid(row=3, column=1, sticky="w", pady=5)

        key_visible = [False]
        def toggle_key():
            key_visible[0] = not key_visible[0]
            key_entry.config(show="" if key_visible[0] else "*")
            eye_btn.config(text="隐藏" if key_visible[0] else "显示")
        eye_btn = ttk.Button(frame, text="显示", command=toggle_key, width=5)
        eye_btn.grid(row=3, column=2, padx=3, pady=5)

        ttk.Label(frame, text="模型名称:").grid(row=4, column=0, sticky="e", padx=5, pady=5)
        model_var = tk.StringVar(value=cfg.get("model", ""))
        ttk.Entry(frame, textvariable=model_var, width=50).grid(row=4, column=1, columnspan=2, sticky="w", pady=5)

        # 测试连接
        test_frame = ttk.Frame(frame)
        test_frame.grid(row=5, column=0, columnspan=4, sticky="ew", pady=(10, 5))

        test_status = ttk.Label(test_frame, text="", foreground="gray", wraplength=350)
        test_status.pack(side=tk.LEFT, fill=tk.X, expand=True)

        testing = [False]

        def test_connection():
            if testing[0]:
                return
            api_url = url_var.get().strip()
            api_key = key_var.get().strip()
            model = model_var.get().strip()
            if not api_url or not api_key:
                test_status.config(text="请填写 API 地址和 Key", foreground="red")
                return
            testing[0] = True
            test_status.config(text="正在测试...", foreground="#0078d4")

            def do_test():
                try:
                    payload = json.dumps({
                        "model": model or "deepseek-v4-flash",
                        "messages": [{"role": "user", "content": "Hi, reply OK only."}],
                        "max_tokens": 10,
                    }).encode("utf-8")
                    with safe_urlopen(normalize_api_url(api_url), data=payload, headers={
                        "Content-Type": "application/json",
                        "Authorization": f"Bearer {api_key}",
                    }, timeout=15) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                    # 递归解析任意格式的响应，提取文本内容
                    def find_text(obj, depth=0):
                        if depth > 5 or not obj:
                            return ""
                        if isinstance(obj, str) and len(obj) > 1:
                            return obj
                        if isinstance(obj, dict):
                            for key in ["content", "text", "message", "choices", "output", "result"]:
                                if key in obj:
                                    val = obj[key]
                                    if isinstance(val, str) and val.strip():
                                        return val
                                    if isinstance(val, (list, dict)):
                                        t = find_text(val, depth + 1)
                                        if t:
                                            return t
                        if isinstance(obj, list):
                            for item in obj:
                                t = find_text(item, depth + 1)
                                if t:
                                    return t
                        return ""

                    text = find_text(data)
                    if not text:
                        text = f"(原始响应: {json.dumps(data, ensure_ascii=False)[:200]})"
                    msg, color = f"连接成功! 回复: {text[:50]}", "green"
                except urllib.error.HTTPError as e:
                    msg, color = f"连接失败: HTTP {e.code} {e.reason}", "red"
                except urllib.error.URLError as e:
                    msg, color = f"连接失败: {str(e.reason)[:80]}", "red"
                except Exception as e:
                    msg, color = f"连接失败: {str(e)[:80]}", "red"
                finally:
                    testing[0] = False
                try:
                    win.after(0, lambda m=msg, c=color: test_status.config(text=m, foreground=c))
                except Exception:
                    pass

            threading.Thread(target=do_test, daemon=True).start()

        ttk.Button(test_frame, text="测试连接", command=test_connection).pack(side=tk.RIGHT)

        # 底部按钮
        def save():
            new_cfg = {"api_url": url_var.get().strip(), "api_key": key_var.get().strip(), "model": model_var.get().strip()}
            self._save_ai_config(new_cfg)
            win.destroy()
            self.status_var.set("AI 配置已保存")

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=6, column=0, columnspan=3, pady=(15, 0))
        ttk.Button(btn_frame, text="保存", command=save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="取消", command=win.destroy).pack(side=tk.LEFT, padx=5)

    def _ai_api_call(self, prompt: str, callback):
        """调用 AI API（后台线程）"""
        cfg = self._load_ai_config()
        if not cfg.get("api_url") or not cfg.get("api_key"):
            self.root.after(0, callback, "⚠ 请先配置 AI 接口（点击工具栏的「AI 配置」按钮）")
            return

        system_prompt = cfg.get("system_prompt", "你是一个资深 Android 系统工程师，专门分析 ROM 中的系统应用。\n评估标准：\n- 可安全卸载：预装推广、冗余工具、第三方合作应用\n- 谨慎卸载：厂商定制服务、云服务、主题壁纸等（卸载可能影响部分功能）\n- 不可卸载：系统核心服务、电话/短信/设置/相机等基础功能\n判断依据：包名前缀（com.android.系统核心）、sharedUserId（android.uid.system）、权限数量和敏感度\n请用中文回答，使用 Markdown 格式，给出明确结论。")

        messages = [{"role": "user", "content": prompt}]

        def do_call():
            try:
                payload = json.dumps({
                    "model": cfg.get("model", "deepseek-v4-flash"),
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        *messages
                    ],
                    "max_tokens": 16000,
                    "temperature": 0.3,
                }).encode("utf-8")

                with safe_urlopen(normalize_api_url(cfg["api_url"]), data=payload, headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {cfg['api_key']}",
                }, timeout=120) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                # 递归解析
                def find_text(obj, depth=0):
                    if depth > 5 or not obj:
                        return ""
                    if isinstance(obj, str) and len(obj) > 1:
                        return obj
                    if isinstance(obj, dict):
                        for key in ["content", "text", "message", "choices", "output", "result"]:
                            if key in obj:
                                val = obj[key]
                                if isinstance(val, str) and val.strip():
                                    return val
                                if isinstance(val, (list, dict)):
                                    t = find_text(val, depth + 1)
                                    if t:
                                        return t
                    if isinstance(obj, list):
                        for item in obj:
                            t = find_text(item, depth + 1)
                            if t:
                                return t
                    return ""

                content = find_text(data)
                if not content:
                    content = f"AI 返回为空。原始响应:\n{json.dumps(data, ensure_ascii=False, indent=2)[:500]}"

                self.root.after(0, callback, content)
            except Exception as e:
                self.root.after(0, callback, f"AI 请求失败: {e}")

        threading.Thread(target=do_call, daemon=True).start()

    def _ai_query_app(self, info: ApkInfo):
        """用 AI 查询单个应用，结果在弹窗中显示"""
        cfg = self._load_ai_config()
        if not cfg.get("api_url") or not cfg.get("api_key"):
            messagebox.showinfo("提示", "请先配置 AI 接口（点击工具栏的「AI 配置」按钮）")
            return

        tpl = cfg.get("single_app_prompt", "分析这个 Android 系统应用：\n\n应用名称: {app_name}\n包名: {package_name}\n版本: {version_name} ({version_code})\nSDK: {min_sdk} → {target_sdk}\n类型: {app_type}\nSharedUID: {shared_uid}\n权限数量: {perm_count}\n主要权限: {permissions}\n\n请按以下格式回答：\n\n## 应用简介\n这个应用是做什么的\n\n## 风险等级\n🟢 可安全卸载 / 🟡 谨慎卸载 / 🔴 不可卸载\n\n## 卸载影响\n卸载后会失去什么功能")

        prompt = tpl.format(
            app_name=info.app_name, package_name=info.package_name,
            version_name=info.version_name, version_code=info.version_code,
            min_sdk=info.min_sdk, target_sdk=info.target_sdk,
            app_type=info.app_type, shared_uid=info.shared_uid or '无',
            perm_count=len(info.permissions),
            permissions=', '.join(p.replace('android.permission.', '') for p in info.permissions[:10]) if info.permissions else '无',
        )

        # 创建弹窗
        win = tk.Toplevel(self.root)
        win.title(f"AI 分析: {info.app_name}")
        win.geometry("600x500")
        win.transient(self.root)

        text_widget = tk.Text(win, wrap=tk.WORD, font=("Segoe UI", 10), state=tk.DISABLED,
                              bg="#ffffff", padx=15, pady=15)
        text_widget.pack(fill=tk.BOTH, expand=True)

        text_widget.config(state=tk.NORMAL)
        text_widget.insert(tk.END, f"AI 正在分析 {info.app_name}...\n请稍候...")
        text_widget.config(state=tk.DISABLED)

        def on_response(content):
            text_widget.config(state=tk.NORMAL)
            text_widget.delete("1.0", tk.END)
            text_widget.insert(tk.END, content)
            text_widget.config(state=tk.DISABLED)

        self._ai_api_call(prompt, on_response)

    def _ai_analyze_all(self):
        """用 AI 批量分析所有应用（带缓存，结果稳定）
        3秒内连续点击3次可强制重新分析"""
        if not self.apps:
            messagebox.showinfo("提示", "没有应用数据，请先扫描 ROM 目录。")
            return

        # 检测3秒内连续3次点击 → 清除缓存重新分析
        import time
        now = time.time()
        self._ai_click_times.append(now)
        self._ai_click_times = [t for t in self._ai_click_times if now - t < 3]
        force_reanalyze = len(self._ai_click_times) >= 3

        # 加载缓存
        cache = {} if force_reanalyze else self._load_ai_cache()

        # 检查哪些应用需要分析（缓存中没有的）
        uncached = [a for a in self.apps if a.package_name not in cache]
        total_cached = len(self.apps) - len(uncached)

        if force_reanalyze:
            self._ai_click_times.clear()
            self.status_var.set(f"强制重新分析全部 {len(self.apps)} 个应用...")
        elif not uncached:
            # 全部命中缓存，直接应用
            for pkg, (cat, desc) in cache.items():
                self._ai_categories[pkg] = (cat, desc)
            self._sort_col = "ai_category"
            self._sort_reverse = False
            self._populate_tree(self.search_var.get())
            self.status_var.set(f"AI 分析完成（全部来自缓存，共 {len(self.apps)} 个）")
            return

        if total_cached > 0:
            # 部分命中缓存，先应用缓存结果
            for pkg, (cat, desc) in cache.items():
                self._ai_categories[pkg] = (cat, desc)
            self.status_var.set(f"AI 分析中... {total_cached} 个已缓存，{len(uncached)} 个需新分析")
        else:
            self.status_var.set(f"AI 正在分析 {len(uncached)} 个应用...")

        self.progress_bar.configure(mode='indeterminate')
        self.progress_bar.pack(side=tk.RIGHT, padx=5, pady=2)
        self.progress_bar.start(15)

        cfg = self._load_ai_config()
        app_list = []
        for i, a in enumerate(uncached):
            perms = ', '.join(p.replace('android.permission.', '') for p in a.permissions[:5]) if a.permissions else '无'
            app_list.append(f"{i+1}. {a.app_name} | {a.package_name} | {a.app_type} | {len(a.permissions)}个权限({perms})")

        tpl = cfg.get("batch_prompt", "ROM系统应用列表（{total}个）：\n\n{app_list}\n\n每个应用一行，格式：\n[类别] 应用名|包名|说明\n\n类别：可安全/谨慎/不可卸\n\n示例：\n[可安全] Browser|com.ume.browser|第三方浏览器\n[不可卸] Phone|com.android.dialer|拨号核心\n\n只输出列表，每个应用必须出现，说明限6字内")

        prompt = tpl.format(total=len(uncached), app_list='\n'.join(app_list))

        def on_response(content):
            self.root.after(0, self._show_analysis_result, content, cache)

        self._ai_api_call(prompt, on_response)

    def _show_analysis_result(self, content: str, cache: dict = None):
        """解析 AI 分析结果并更新应用列表，同时保存到缓存"""
        # 解析 AI 返回的内容
        for line in content.split('\n'):
            line = line.strip()
            if not line:
                continue
            # 匹配 [类别] 应用名 | 包名 | 说明
            m = re.match(r'\[([^\]]+)\]\s*(.+?)\s*\|\s*(.+?)\s*\|\s*(.+)', line)
            if m:
                cat_raw = m.group(1).strip()
                pkg_name = m.group(3).strip()
                desc = m.group(4).strip()
                # 归一化类别
                if '可安全' in cat_raw or '安全' in cat_raw:
                    category = '可安全卸载'
                elif '谨慎' in cat_raw:
                    category = '谨慎卸载'
                elif '不可卸' in cat_raw or '不可' in cat_raw or '核心' in cat_raw:
                    category = '不可卸载'
                else:
                    category = cat_raw
                self._ai_categories[pkg_name] = (category, desc)

        # 保存到缓存
        if cache is not None:
            for pkg, val in self._ai_categories.items():
                cache[pkg] = val
            self._save_ai_cache(cache)

        # 统计
        counts = {}
        for cat, _ in self._ai_categories.values():
            counts[cat] = counts.get(cat, 0) + 1

        self._sort_col = "ai_category"
        self._sort_reverse = False
        self._populate_tree(self.search_var.get())
        self.progress_bar.stop()
        self.progress_bar.configure(mode='determinate')
        self._hide_progress()
        self.status_var.set(f"AI 分析完成  |  可安全: {counts.get('可安全卸载', 0)}  谨慎: {counts.get('谨慎卸载', 0)}  不可卸: {counts.get('不可卸载', 0)}")

    def _update_tool_status(self):
        """更新状态栏中的工具信息"""
        if AAPT_PATH and AAPT_PATH.exists():
            self.status_var.set(f"就绪  |  解析工具: {AAPT_PATH.name}")
        else:
            self.status_var.set("就绪  |  警告: 未找到 aapt 工具，仅显示文件列表")

    def _create_default_icon(self) -> tk.PhotoImage:
        img = tk.PhotoImage(width=ICON_SIZE, height=ICON_SIZE)
        border_row = "{" + " ".join(["#999999"] * ICON_SIZE) + "}"
        inner_row = "{" + " ".join(["#999999"] + ["#E0E0E0"] * (ICON_SIZE - 2) + ["#999999"]) + "}"
        for y in range(ICON_SIZE):
            if y == 0 or y == ICON_SIZE - 1:
                img.put(border_row, to=(0, y))
            else:
                img.put(inner_row, to=(0, y))
        return img

    # ------------------------------------------------------------------ 目录 / 扫描
    def _select_dir(self):
        d = filedialog.askdirectory(title="选择 ROM 解包目录")
        if not d:
            return
        found = any(os.path.isdir(os.path.join(d, s)) for s, _ in APP_DIRS)
        if not found:
            messagebox.showwarning(
                "未找到 APP 目录",
                "所选目录下未找到 system/app、system/priv-app 等目录。\n请确认这是正确的 ROM 解包目录。",
            )
        self.rom_root = d
        self.dir_label.config(text=d, foreground="black")
        self._start_scan()

    def _refresh(self):
        if self.rom_root:
            self._start_scan()
        else:
            messagebox.showinfo("提示", "请先选择解包目录。")

    def _start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self.status_var.set("正在扫描…")
        self.stats_label.config(text="")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.apps.clear()
        self.icon_cache.clear()
        self._checked.clear()
        self._ai_categories.clear()
        self._show_progress(0)
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        """后台扫描线程，覆盖所有分区目录，多线程并行解析"""
        # 1) 收集所有待扫描的 APK 路径
        scan_items = []  # [(apk_path, subdir, entry, app_type, is_split)]
        for subdir, app_type in APP_DIRS:
            scan_dir = os.path.join(self.rom_root, subdir)
            if not os.path.isdir(scan_dir):
                continue
            for entry in sorted(os.listdir(scan_dir)):
                entry_path = os.path.join(scan_dir, entry)
                if not os.path.isdir(entry_path):
                    continue

                apk_file = None
                is_split = False

                base_apk = os.path.join(entry_path, "base.apk")
                if os.path.isfile(base_apk):
                    apk_file = base_apk
                    is_split = True
                else:
                    for f in sorted(os.listdir(entry_path)):
                        if f.lower().endswith(".apk"):
                            apk_file = os.path.join(entry_path, f)
                            break

                if apk_file:
                    scan_items.append((apk_file, subdir, entry, app_type, is_split))

        # 2) 并行解析 APK（多线程调用 aapt，每 APK 只调用一次）
        def parse_one(item):
            apk_path, subdir, entry, app_type, is_split = item
            info, icon_candidates = ApkParser.parse_with_icon(apk_path)
            info.app_dir = subdir + "/" + entry
            info.app_type = app_type
            info.is_split = is_split
            info.icon_data = IconExtractor.extract_icon(apk_path, icon_candidates)
            return info

        found_apps = []
        total = len(scan_items)
        done = [0]
        cpu_count = os.cpu_count() or 4
        workers = min(cpu_count, max(2, total))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(parse_one, item): item for item in scan_items}
            for future in as_completed(futures):
                try:
                    found_apps.append(future.result())
                except Exception:
                    pass
                done[0] += 1
                pct = done[0] / total * 100 if total else 100
                self.root.after(0, self._show_progress, pct)
                self.root.after(0, lambda d=done[0]: self.status_var.set(f"扫描中... {d}/{total}"))

        self.root.after(0, self._on_scan_done, found_apps)

    def _on_scan_done(self, found_apps: list[ApkInfo]):
        self.apps = found_apps
        self._populate_tree()
        self._scanning = False
        self._hide_progress()
        self.status_var.set(f"扫描完成，共 {len(self.apps)} 个应用  |  解析工具: {AAPT_PATH.name if AAPT_PATH else '无'}")
        self._update_stats()

    # ------------------------------------------------------------------ 列表填充
    def _populate_tree(self, filter_text: str = ""):
        for item in self.tree.get_children():
            self.tree.delete(item)
        ft = filter_text.lower()

        # 构建显示列表
        display_list = []
        for info in self.apps:
            if ft and ft not in info.app_name.lower() and ft not in info.package_name.lower():
                continue
            ai_info = self._ai_categories.get(info.package_name)
            ai_cat = ai_info[0] if ai_info else ""
            ai_desc = ai_info[1] if ai_info else ""

            version_str = info.version_name
            if info.version_code:
                version_str = f"{info.version_name} ({info.version_code})" if info.version_name else f"({info.version_code})"

            type_str = info.app_type
            if info.is_split:
                type_str += " [split]"

            checked = "☑" if self._checked.get(info.apk_path) else "☐"

            ai_label = ""
            tree_tag = ""
            if ai_cat == "可安全卸载":
                ai_label = "可安全"
                tree_tag = "ai_safe"
            elif ai_cat == "谨慎卸载":
                ai_label = "谨慎"
                tree_tag = "ai_caution"
            elif ai_cat == "不可卸载":
                ai_label = "不可卸"
                tree_tag = "ai_danger"

            display_list.append({
                "info": info, "checked": checked, "ai_label": ai_label,
                "ai_desc": ai_desc, "app_name": info.app_name,
                "package_name": info.package_name, "version": version_str,
                "app_type": type_str, "file_size": info.file_size,
                "size_str": self._format_size(info.file_size),
                "app_dir": info.app_dir, "tree_tag": tree_tag,
            })

        # 排序
        col = self._sort_col
        rev = self._sort_reverse
        ai_order = {"可安全": 0, "谨慎": 1, "不可卸": 2, "": 3}
        if col == "file_size":
            display_list.sort(key=lambda x: x["file_size"], reverse=rev)
        elif col == "checked":
            display_list.sort(key=lambda x: x["checked"], reverse=rev)
        elif col == "ai_category":
            display_list.sort(key=lambda x: ai_order.get(x["ai_label"], 3), reverse=rev)
        else:
            display_list.sort(key=lambda x: x.get(col, ""), reverse=rev)

        # 插入
        for d in display_list:
            icon = self._get_icon(d["info"])
            self.tree.insert(
                "", tk.END, text="", image=icon,
                values=(d["checked"], d["ai_label"], d["ai_desc"], d["app_name"],
                        d["package_name"], d["version"], d["app_type"], d["size_str"], d["app_dir"]),
                tags=(d["info"].apk_path, d["tree_tag"]) if d["tree_tag"] else (d["info"].apk_path,),
            )
        self._update_stats(len(display_list))

    @staticmethod
    def _format_size(size: int) -> str:
        if size <= 0:
            return "-"
        for unit in ["B", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.1f}{unit}" if unit != "B" else f"{size}{unit}"
            size /= 1024
        return f"{size:.1f}TB"

    def _get_icon(self, info: ApkInfo) -> tk.PhotoImage:
        if info.package_name in self.icon_cache:
            return self.icon_cache[info.package_name]
        if info.icon_data:
            try:
                result = self._make_icon(info.icon_data)
                self.icon_cache[info.package_name] = result
                return result
            except Exception:
                pass
        return self._default_icon

    def _make_icon(self, png_data: bytes, target_size: int = 0) -> tk.PhotoImage:
        """创建缩放后的图标 PhotoImage。
        仅用 subsample 降采样（不用 zoom），避免 Tcl/Tk 像素损坏。"""
        if target_size <= 0:
            target_size = ICON_SIZE
        img = tk.PhotoImage(data=png_data)
        w, h = img.width(), img.height()
        if w <= target_size and h <= target_size:
            return img
        # 计算降采样因子（向上取整，确保结果 ≤ target_size）
        factor = max(2, -(-min(w, h) // target_size))  # ceil division
        result = img.subsample(factor, factor)
        result._src = img
        return result

    def _show_progress(self, value: float):
        """显示进度条并设置进度值"""
        self.progress_bar.pack(side=tk.RIGHT, padx=5, pady=2)
        self.progress_var.set(value)

    def _hide_progress(self):
        """隐藏进度条"""
        self.progress_bar.pack_forget()
        self.progress_var.set(0)

    def _update_stats(self, filtered_count: Optional[int] = None):
        total = len(self.apps)
        checked = sum(1 for v in self._checked.values() if v)
        parts = [f"共 {total} 个应用"]
        if filtered_count is not None and filtered_count != total:
            parts = [f"显示 {filtered_count}/{total}"]
        if checked > 0:
            parts.append(f"已勾选 {checked}")
        ai_count = len(self._ai_categories)
        if ai_count > 0:
            parts.append(f"AI已评估 {ai_count}")
        self.stats_label.config(text="  |  ".join(parts))

    # ------------------------------------------------------------------ 排序
    def _sort_tree(self, col: str):
        """点击列标题排序"""
        if self._sort_col == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_col = col
            self._sort_reverse = False
        self._populate_tree(self.search_var.get())

    # ------------------------------------------------------------------ 搜索
    def _on_search(self, *_):
        if self._search_after_id is not None:
            self.root.after_cancel(self._search_after_id)
        self._search_after_id = self.root.after(200, lambda: self._populate_tree(self.search_var.get()))

    # ------------------------------------------------------------------ 右键菜单
    def _popup_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            if item not in self.tree.selection():
                self.tree.selection_set(item)
            self.ctx_menu.post(event.x_root, event.y_root)

    # ------------------------------------------------------------------ 勾选框
    def _on_tree_click(self, event):
        """点击勾选列切换勾选状态"""
        region = self.tree.identify_region(event.x, event.y)
        if region != "cell":
            return
        col = self.tree.identify_column(event.x)
        if col != "#1":
            return
        item = self.tree.identify_row(event.y)
        if not item:
            return
        tags = self.tree.item(item, "tags")
        apk_path = tags[0] if tags else ""
        if not apk_path:
            return
        self._checked[apk_path] = not self._checked.get(apk_path, False)
        checked = "☑" if self._checked[apk_path] else "☐"
        values = list(self.tree.item(item, "values"))
        values[0] = checked
        self.tree.item(item, values=values)
        self._update_check_count()

    def _get_checked_apps(self) -> list[ApkInfo]:
        """获取所有勾选的应用"""
        return [a for a in self.apps if self._checked.get(a.apk_path)]

    def _update_check_count(self):
        """更新状态栏的勾选计数"""
        self._update_stats()

    def _check_all(self):
        """全选当前显示的应用"""
        for item in self.tree.get_children():
            tags = self.tree.item(item, "tags")
            apk_path = tags[0] if tags else ""
            if apk_path:
                self._checked[apk_path] = True
            values = list(self.tree.item(item, "values"))
            values[0] = "☑"
            self.tree.item(item, values=values)
        self._update_check_count()

    def _uncheck_all(self):
        """取消所有勾选"""
        self._checked.clear()
        for item in self.tree.get_children():
            values = list(self.tree.item(item, "values"))
            values[0] = "☐"
            self.tree.item(item, values=values)
        self._update_check_count()

    def _invert_check(self):
        """反选"""
        for item in self.tree.get_children():
            tags = self.tree.item(item, "tags")
            apk_path = tags[0] if tags else ""
            if apk_path:
                self._checked[apk_path] = not self._checked.get(apk_path, False)
            checked = "☑" if self._checked.get(apk_path) else "☐"
            values = list(self.tree.item(item, "values"))
            values[0] = checked
            self.tree.item(item, values=values)
        self._update_check_count()

    # ------------------------------------------------------------------ 详情
    def _show_detail(self, _event):
        selected = self.tree.selection()
        if not selected:
            return
        tags = self.tree.item(selected[0], "tags")
        apk_path = tags[0] if tags else ""
        info = next((a for a in self.apps if a.apk_path == apk_path), None)
        if not info:
            return

        win = tk.Toplevel(self.root)
        win.title(f"应用详情 - {info.app_name}")
        win.geometry("580x560")
        win.resizable(False, False)
        win.transient(self.root)

        # 主框架（可滚动）
        main_frame = ttk.Frame(win)
        main_frame.pack(fill=tk.BOTH, expand=True)

        canvas = tk.Canvas(main_frame)
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        frame = ttk.Frame(scroll_frame, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        if info.icon_data:
            try:
                icon_img = self._make_icon(info.icon_data, 48)
                lbl = ttk.Label(frame, image=icon_img)
                lbl.image = icon_img
                lbl.grid(row=0, column=0, rowspan=13, padx=(0, 15), sticky="n")
            except Exception:
                pass

        fields = [
            ("应用名称:", info.app_name),
            ("包名:", info.package_name),
            ("版本名:", info.version_name),
            ("版本号:", info.version_code),
            ("最低 SDK:", info.min_sdk),
            ("目标 SDK:", info.target_sdk),
            ("SharedUID:", info.shared_uid or "-"),
            ("类型:", "priv-app" if info.app_type == "priv-app" else "app"),
            ("Split APK:", "是" if info.is_split else "否"),
            ("文件大小:", self._format_size(info.file_size)),
            ("权限数量:", str(len(info.permissions)) if info.permissions else "0"),
            ("相对路径:", info.app_dir),
            ("APK 路径:", info.apk_path),
        ]
        for i, (label, value) in enumerate(fields):
            ttk.Label(frame, text=label, font=("", 9, "bold")).grid(row=i, column=1, sticky="ne", padx=(0, 5), pady=2)
            ttk.Label(frame, text=value or "-", wraplength=320, justify=tk.LEFT).grid(row=i, column=2, sticky="nw", pady=2)

        # 权限列表（可折叠）
        row_offset = len(fields)
        if info.permissions:
            perm_label = ttk.Label(frame, text="权限列表:", font=("", 9, "bold"))
            perm_label.grid(row=row_offset, column=1, sticky="ne", padx=(0, 5), pady=(10, 2))

            perm_text = tk.Text(frame, height=8, width=45, wrap=tk.WORD, font=("", 8))
            perm_text.grid(row=row_offset, column=2, sticky="nw", pady=(10, 2))
            for p in info.permissions:
                short = p.replace("android.permission.", "")
                perm_text.insert(tk.END, short + "\n")
            perm_text.config(state=tk.DISABLED)

        ttk.Button(frame, text="关闭", command=win.destroy).grid(
            row=row_offset + 1, column=1, columnspan=2, pady=(15, 0))

    # ------------------------------------------------------------------ 打开目录
    def _open_dir(self):
        selected = self.tree.selection()
        if not selected:
            return
        tags = self.tree.item(selected[0], "tags")
        apk_path = tags[0] if tags else ""
        if apk_path:
            folder = os.path.dirname(apk_path)
            if os.path.isdir(folder) and sys.platform == "win32":
                os.startfile(folder)

    # ------------------------------------------------------------------ 关联文件清理
    def _find_associated_files(self, info: ApkInfo) -> list[str]:
        """查找与 APP 关联的文件和目录（权限XML、sysconfig、overlay、oat 缓存等）"""
        found = []
        pkg = info.package_name
        if not pkg:
            return found

        # 1) priv-app 权限 XML（system/etc/permissions/privapp-permissions-*.xml）
        # 2) sysconfig 白名单 XML — 一起扫描
        search_dirs = [
            ("system/etc/permissions", "system_ext/etc/permissions",
             "vendor/etc/permissions", "product/etc/permissions"),
            ("system/etc/sysconfig", "system_ext/etc/sysconfig",
             "vendor/etc/sysconfig", "product/etc/sysconfig"),
        ]
        # 精确匹配：package="com.xxx" 或 package='com.xxx'
        pkg_pattern = re.compile(r'package\s*=\s*["\']' + re.escape(pkg) + r'["\']')
        for dir_group in search_dirs:
            for xml_dir in dir_group:
                abs_dir = os.path.join(self.rom_root, xml_dir)
                if not os.path.isdir(abs_dir):
                    continue
                for fname in os.listdir(abs_dir):
                    if fname.endswith(".xml"):
                        fpath = os.path.join(abs_dir, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                if pkg_pattern.search(f.read()):
                                    found.append(fpath)
                        except OSError:
                            pass

        # 3) overlay 覆盖包（精确匹配包名）
        overlay_dirs = ["system/vendor/overlay", "vendor/overlay",
                        "product/overlay", "system_ext/overlay"]
        pkg_lower = pkg.lower()
        # overlay 文件名通常 == 包名，或 包名-overlay / 包名_auto / 包名_fwkr 等
        overlay_suffixes = ["-overlay", "_auto", "_fwkr", "_fwk", ".apk"]
        for ov_dir in overlay_dirs:
            abs_ov = os.path.join(self.rom_root, ov_dir)
            if not os.path.isdir(abs_ov):
                continue
            for fname in os.listdir(abs_ov):
                fname_lower = fname.lower()
                # 尝试去除常见后缀后与包名精确比较
                base = fname_lower
                for suffix in overlay_suffixes:
                    if base.endswith(suffix):
                        base = base[: -len(suffix)]
                        break
                if base == pkg_lower:
                    found.append(os.path.join(abs_ov, fname))

        # 4) 独立 oat 缓存目录（不在 app 目录内的）
        partition = info.app_dir.split("/")[0]  # e.g. "system", "vendor"
        app_basename = os.path.basename(info.app_dir)
        for oat_sub in ["oat", "dalvik-cache"]:
            oat_dir = os.path.join(self.rom_root, partition, oat_sub)
            if not os.path.isdir(oat_dir):
                continue
            pkg_lv = pkg.lower()
            for d in os.listdir(oat_dir):
                if d == app_basename or d == pkg or d == pkg_lv:
                    found.append(os.path.join(oat_dir, d))

        return found

    def _remove_xml_entries(self, xml_path: str, package_names: list[str]):
        """从 XML 文件中批量移除多个包名的条目（只读写一次文件）。"""
        try:
            with open(xml_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            new_content = content
            for pkg in package_names:
                if pkg not in new_content:
                    continue
                pattern = r'<privapp-permissions\s+package=["\']' + re.escape(pkg) + r'["\'][^>]*>.*?</privapp-permissions>'
                new_content = re.sub(pattern, "", new_content, flags=re.DOTALL)
                line_pattern = r'<(?:allow|deny)[^>]*package=["\']' + re.escape(pkg) + r'["\'][^>]*/?>'
                new_content = re.sub(line_pattern, "", new_content)

            new_content = re.sub(r"\n{3,}", "\n\n", new_content)

            if new_content != content:
                with open(xml_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
        except Exception:
            pass

    # ------------------------------------------------------------------ 卸载
    def _uninstall_selected(self):
        # 优先使用勾选框，没有勾选则使用树选择
        to_remove = self._get_checked_apps()
        if not to_remove:
            selected = self.tree.selection()
            for item in selected:
                tags = self.tree.item(item, "tags")
                apk_path = tags[0] if tags else ""
                info = next((a for a in self.apps if a.apk_path == apk_path), None)
                if info:
                    to_remove.append(info)
        if not to_remove:
            return

        # 收集所有关联文件
        all_associated = {}
        for info in to_remove:
            assoc = self._find_associated_files(info)
            if assoc:
                all_associated[info.package_name] = assoc

        # 构建确认窗口
        confirm_win = tk.Toplevel(self.root)
        confirm_win.title("确认卸载")
        confirm_win.geometry("500x400")
        confirm_win.resizable(False, False)
        confirm_win.transient(self.root)
        confirm_win.grab_set()

        cframe = ttk.Frame(confirm_win, padding=15)
        cframe.pack(fill=tk.BOTH, expand=True)

        ttk.Label(cframe, text=f"确定要卸载以下 {len(to_remove)} 个应用？", font=("", 11, "bold"), foreground="red").pack(anchor="w", pady=(0, 8))

        list_frame = ttk.Frame(cframe)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        list_text = tk.Text(list_frame, wrap=tk.WORD, font=("", 9))
        list_scroll = ttk.Scrollbar(list_frame, command=list_text.yview)
        list_text.configure(yscrollcommand=list_scroll.set)
        list_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        list_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        for i, info in enumerate(to_remove, 1):
            list_text.insert(tk.END, f"{i}. {info.app_name}  ({info.package_name})\n    路径: {info.app_dir}\n")

        if all_associated:
            list_text.insert(tk.END, "\n--- 关联文件将一同清理 ---\n")
            for pkg, files in all_associated.items():
                for f in files:
                    rel = os.path.relpath(f, self.rom_root)
                    list_text.insert(tk.END, f"  - {rel}\n")

        list_text.config(state=tk.DISABLED)

        ttk.Label(cframe, text="⚠ 此操作不可撤销！", foreground="red", font=("", 9, "bold")).pack(anchor="w")

        result = {"ok": False}
        def confirm_del():
            result["ok"] = True
            confirm_win.destroy()

        btn_f = ttk.Frame(cframe)
        btn_f.pack(pady=(8, 0))
        tk.Button(btn_f, text="确认卸载", command=confirm_del, bg="#e74c3c", fg="white", font=("", 10), padx=15, pady=3).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_f, text="取消", command=confirm_win.destroy, font=("", 10), padx=15, pady=3).pack(side=tk.LEFT, padx=5)

        self.root.wait_window(confirm_win)
        if not result["ok"]:
            return

        success, errors = 0, []

        # 1) 批量清理 XML：同一 XML 文件只读写一次
        xml_pkg_map: dict[str, list[str]] = {}  # xml_path -> [package_names]
        for info in to_remove:
            for xml_path in all_associated.get(info.package_name, []):
                if xml_path.endswith(".xml"):
                    xml_pkg_map.setdefault(xml_path, []).append(info.package_name)
        for xml_path, pkgs in xml_pkg_map.items():
            self._remove_xml_entries(xml_path, pkgs)

        # 2) 删除关联文件/目录（overlay、oat 缓存等）
        for info in to_remove:
            for assoc_path in all_associated.get(info.package_name, []):
                if not assoc_path.endswith(".xml"):
                    try:
                        if os.path.isdir(assoc_path):
                            shutil.rmtree(assoc_path)
                        else:
                            os.remove(assoc_path)
                    except Exception:
                        pass

        # 3) 删除 APP 主目录
        for info in to_remove:
            abs_dir = os.path.join(self.rom_root, info.app_dir)
            if os.path.isdir(abs_dir):
                try:
                    shutil.rmtree(abs_dir)
                    success += 1
                except Exception as e:
                    errors.append(f"{info.app_name}: {e}")
            else:
                errors.append(f"{info.app_name}: 目录不存在")

        self.apps = [a for a in self.apps if a not in to_remove]
        for info in to_remove:
            self._ai_categories.pop(info.package_name, None)
        self._populate_tree(self.search_var.get())

        if errors:
            messagebox.showwarning("卸载完成（部分失败）", f"成功: {success} 个\n失败: {len(errors)} 个\n\n" + "\n".join(errors[:10]))
        else:
            self.status_var.set(f"已卸载 {success} 个应用")

    # ------------------------------------------------------------------ 添加 APP
    def _add_apk(self):
        if not self.rom_root:
            messagebox.showinfo("提示", "请先选择解包目录。")
            return

        apk_files = filedialog.askopenfilenames(
            title="选择 APK 文件（可多选，split APK 全部选中）",
            filetypes=[("APK 文件", "*.apk"), ("所有文件", "*.*")],
        )
        if not apk_files:
            return

        pos_win = tk.Toplevel(self.root)
        pos_win.title("确认添加 APP")
        pos_win.geometry("480x440")
        pos_win.resizable(False, False)
        pos_win.transient(self.root)
        pos_win.grab_set()

        frame = ttk.Frame(pos_win, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=f"将添加以下 {len(apk_files)} 个 APK：", font=("", 10, "bold")).pack(anchor="w", pady=(0, 5))

        # 显示 APK 列表
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        list_text = tk.Text(list_frame, height=8, wrap=tk.WORD, font=("", 9), state=tk.NORMAL)
        list_scroll = ttk.Scrollbar(list_frame, command=list_text.yview)
        list_text.configure(yscrollcommand=list_scroll.set)
        list_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        list_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        for i, apk in enumerate(apk_files, 1):
            name = os.path.basename(apk)
            size = os.path.getsize(apk) if os.path.isfile(apk) else 0
            size_str = f"{size/1024/1024:.1f}MB" if size > 0 else ""
            list_text.insert(tk.END, f"{i}. {name}  ({size_str})\n")
        list_text.config(state=tk.DISABLED)

        ttk.Label(frame, text="安装到分区：", font=("", 10)).pack(anchor="w", pady=(0, 5))

        pos_var = tk.StringVar(value="system/app")

        available = []
        for s, _ in APP_DIRS:
            parent = os.path.join(self.rom_root, os.path.dirname(s))
            if os.path.isdir(parent) and s not in available:
                available.append(s)
        if not available:
            available = ["system/app"]

        canvas = ttk.Frame(frame)
        canvas.pack(fill=tk.BOTH, expand=True)

        # 分区选择
        priv_targets = {s for s, _ in APP_DIRS if "priv-app" in s}
        for target in available:
            ttk.Radiobutton(canvas, text=target, variable=pos_var, value=target).pack(anchor=tk.W, pady=2)

        # 初始状态：如果有 priv-app 分区存在则默认选中
        is_priv_default = any(t in priv_targets for t in available)
        if is_priv_default:
            pos_var.set(next(t for t in available if t in priv_targets))

        # 权限 XML 生成选项（仅 priv-app 时显示）
        perm_var = tk.BooleanVar(value=is_priv_default)
        perm_check = ttk.Checkbutton(canvas, text="自动生成 priv-app 权限 XML（推荐）", variable=perm_var)

        def on_target_change(*_):
            if pos_var.get() in priv_targets:
                perm_check.pack(anchor=tk.W, pady=(10, 0))
                perm_var.set(True)
            else:
                perm_check.pack_forget()
                perm_var.set(False)

        pos_var.trace_add("write", on_target_change)
        on_target_change()

        result = {"ok": False}
        def confirm():
            result["ok"] = True
            pos_win.destroy()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=(15, 0))
        tk.Button(btn_frame, text="确定安装", command=confirm, bg="#0078d4", fg="white", font=("", 10), padx=15, pady=3).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="取消", command=pos_win.destroy, font=("", 10), padx=15, pady=3).pack(side=tk.LEFT, padx=5)

        self.root.wait_window(pos_win)
        if not result["ok"]:
            return

        target_dir = pos_var.get()
        is_priv = "priv-app" in target_dir
        generate_perm = perm_var.get() and is_priv
        success, errors = 0, []

        # 分组：同一目录下的多个 APK 视为 split APK，放入同一 app 目录
        groups: dict[str, list[str]] = {}  # group_key -> [apk_files]
        for apk_file in apk_files:
            parent = str(Path(apk_file).parent)
            groups.setdefault(parent, []).append(apk_file)

        for group_key, group_apks in groups.items():
            # 目录名取自第一个 APK 的文件名
            apk_name = Path(group_apks[0]).stem
            dest_dir = os.path.join(self.rom_root, target_dir, apk_name)

            try:
                os.makedirs(dest_dir, exist_ok=True)

                # 复制该组的所有 APK 文件
                for apk_file in group_apks:
                    shutil.copy2(apk_file, os.path.join(dest_dir, os.path.basename(apk_file)))

                # 用主 APK（base.apk 或第一个）解析信息
                main_apk = dest_dir
                base = os.path.join(dest_dir, "base.apk")
                if os.path.isfile(base):
                    main_apk = base
                else:
                    for f in sorted(os.listdir(dest_dir)):
                        if f.lower().endswith(".apk"):
                            main_apk = os.path.join(dest_dir, f)
                            break

                info = ApkParser.parse(main_apk)
                if info is None:
                    info = ApkInfo(package_name=apk_name, app_name=apk_name, apk_path=main_apk)
                info.app_dir = target_dir + "/" + apk_name
                info.app_type = "priv-app" if is_priv else "app"
                info.is_split = len(group_apks) > 1
                info.icon_data = IconExtractor.extract_icon(main_apk)
                info.apk_path = main_apk
                try:
                    info.file_size = sum(os.path.getsize(os.path.join(dest_dir, f)) for f in os.listdir(dest_dir) if f.endswith(".apk"))
                except OSError:
                    pass

                # 生成 priv-app 权限 XML
                if generate_perm and info.package_name:
                    self._generate_privapp_permissions(info.package_name, target_dir)

                self.apps.append(info)
                success += 1
            except Exception as e:
                errors.append(f"{apk_name}: {e}")

        self._populate_tree(self.search_var.get())
        if errors:
            messagebox.showwarning("安装完成（部分失败）", f"成功: {success} 个\n失败: {len(errors)} 个\n\n" + "\n".join(errors[:10]))
        else:
            extra = "（含权限XML）" if generate_perm else ""
            self.status_var.set(f"已添加 {success} 个应用到 {target_dir} {extra}")

    def _generate_privapp_permissions(self, package_name: str, target_dir: str):
        """为 priv-app 生成权限声明 XML 文件。
        使用 allow-all-in-power-save / allow-in-data-usage 的通用权限模板。"""
        # 确定对应分区的 permissions 目录
        partition = target_dir.split("/")[0]  # "system", "vendor", "system_ext", "product"
        perm_dir = os.path.join(self.rom_root, partition, "etc", "permissions")
        os.makedirs(perm_dir, exist_ok=True)

        xml_path = os.path.join(perm_dir, f"privapp-permissions-{package_name}.xml")
        if os.path.exists(xml_path):
            return  # 已存在则不覆盖

        xml_content = f'''<?xml version="1.0" encoding="utf-8"?>
<!--
    Permissions for {package_name}
    Auto-generated by ROM APP Manager
-->
<permissions>
    <privapp-permissions package="{package_name}">
        <permission name="android.permission.INTERNET"/>
        <permission name="android.permission.ACCESS_NETWORK_STATE"/>
        <permission name="android.permission.READ_EXTERNAL_STORAGE"/>
        <permission name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    </privapp-permissions>
</permissions>
'''
        try:
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(xml_content)
        except OSError:
            pass

    # ------------------------------------------------------------------ 导出
    @staticmethod
    def _esc(s):
        """CSV 字段转义"""
        return str(s).replace('"', '""')

    def _export_csv(self):
        if not self.apps:
            messagebox.showinfo("提示", "没有可导出的数据。")
            return
        filepath = filedialog.asksaveasfilename(
            title="导出 CSV", defaultextension=".csv",
            filetypes=[("CSV 文件", "*.csv")],
        )
        if not filepath:
            return
        try:
            with open(filepath, "w", encoding="utf-8-sig") as f:
                f.write("应用名称,包名,版本名,版本号,最低SDK,目标SDK,SharedUID,类型,文件大小,权限数,AI评估,AI说明,路径\n")
                for i in self.apps:
                    t = i.app_type + (" [split]" if i.is_split else "")
                    ai_info = self._ai_categories.get(i.package_name)
                    ai_cat = ai_info[0] if ai_info else ""
                    ai_desc = ai_info[1] if ai_info else ""
                    e = self._esc
                    f.write(
                        f'"{e(i.app_name)}","{e(i.package_name)}","{e(i.version_name)}",'
                        f'"{e(i.version_code)}","{e(i.min_sdk)}","{e(i.target_sdk)}",'
                        f'"{e(i.shared_uid)}","{e(t)}",{i.file_size},{len(i.permissions)},'
                        f'"{e(ai_cat)}","{e(ai_desc)}","{e(i.app_dir)}"\n'
                    )
            self.status_var.set(f"已导出 CSV: {filepath}")
            messagebox.showinfo("导出成功", f"已导出 {len(self.apps)} 条记录到:\n{filepath}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def _export_json(self):
        if not self.apps:
            messagebox.showinfo("提示", "没有可导出的数据。")
            return
        filepath = filedialog.asksaveasfilename(
            title="导出 JSON", defaultextension=".json",
            filetypes=[("JSON 文件", "*.json")],
        )
        if not filepath:
            return
        try:
            data = []
            for i in self.apps:
                ai_info = self._ai_categories.get(i.package_name)
                data.append({
                    "app_name": i.app_name,
                    "package_name": i.package_name,
                    "version_name": i.version_name,
                    "version_code": i.version_code,
                    "min_sdk": i.min_sdk,
                    "target_sdk": i.target_sdk,
                    "shared_uid": i.shared_uid,
                    "app_type": i.app_type,
                    "is_split": i.is_split,
                    "file_size": i.file_size,
                    "permissions": i.permissions,
                    "ai_category": ai_info[0] if ai_info else "",
                    "ai_description": ai_info[1] if ai_info else "",
                    "app_dir": i.app_dir,
                })
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.status_var.set(f"已导出 JSON: {filepath}")
            messagebox.showinfo("导出成功", f"已导出 {len(self.apps)} 条记录到:\n{filepath}")
        except Exception as e:
            messagebox.showerror("导出失败", str(e))

    def _show_partition_stats(self):
        """显示各分区的应用数量和空间占用统计"""
        if not self.apps:
            messagebox.showinfo("提示", "请先扫描 ROM 目录。")
            return

        # 按分区统计
        partitions: dict[str, dict] = {}
        for info in self.apps:
            partition = info.app_dir.split("/")[0] if info.app_dir else "unknown"
            if partition not in partitions:
                partitions[partition] = {"count": 0, "app_count": 0, "priv_count": 0, "size": 0}
            partitions[partition]["count"] += 1
            partitions[partition]["size"] += info.file_size
            if info.app_type == "priv-app":
                partitions[partition]["priv_count"] += 1
            else:
                partitions[partition]["app_count"] += 1

        win = tk.Toplevel(self.root)
        win.title("分区空间统计")
        win.geometry("500x400")
        win.transient(self.root)

        frame = ttk.Frame(win, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="ROM 分区空间统计", font=("", 12, "bold")).pack(pady=(0, 15))

        columns = ("partition", "total", "app", "priv", "size")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=len(partitions))
        tree.heading("partition", text="分区")
        tree.heading("total", text="总应用数")
        tree.heading("app", text="普通应用")
        tree.heading("priv", text="特权应用")
        tree.heading("size", text="APK 总大小")
        tree.column("partition", width=120)
        tree.column("total", width=70, anchor=tk.CENTER)
        tree.column("app", width=70, anchor=tk.CENTER)
        tree.column("priv", width=70, anchor=tk.CENTER)
        tree.column("size", width=100, anchor=tk.E)
        tree.pack(fill=tk.BOTH, expand=True)

        total_count, total_size = 0, 0
        for p in sorted(partitions.keys()):
            d = partitions[p]
            tree.insert("", tk.END, values=(
                p, d["count"], d["app_count"], d["priv_count"], self._format_size(d["size"])
            ))
            total_count += d["count"]
            total_size += d["size"]

        # 合计行
        tree.insert("", tk.END, values=(
            "合计", total_count, "", "", self._format_size(total_size)
        ), tags=("total",))
        tree.tag_configure("total", font=("", 9, "bold"))

        ttk.Button(frame, text="关闭", command=win.destroy).pack(pady=(15, 0))

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    RomAppManager().run()
