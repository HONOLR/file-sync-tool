#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用增量文件同步工具 - 服务端

功能说明:
    对外提供一组 HTTP 接口, 让客户端能够以"增量"的方式同步一个或多个
    数据集目录。服务端在启动时扫描所有已配置的数据集, 逐个文件计算
    SHA-256 摘要并生成"快照"(文件清单)缓存在内存中; 客户端取得快照后
    与本地文件逐一比对, 只下载缺失或内容不一致的文件。

提供的接口:
    POST /register              客户端上报自身信息(便于服务端日志审计)
    GET  /snapshot?dataset=xxx  获取指定数据集的文件清单
    GET  /files/<数据集>/<相对路径>   下载单个文件
    GET  /datasets              列出所有可用数据集(不含路径等敏感信息)
    GET  /healthz               健康检查

安全说明:
    1. 所有接口均需携带访问令牌(Token), 可通过 HTTP 头
       `X-Auth-Token` 或查询参数 `token` 传入。
    2. 令牌比对使用 `hmac.compare_digest`, 避免计时侧信道攻击。
    3. 文件下载接口对最终路径做了严格的目录归属校验, 阻止通过
       `..` 或绝对路径跳出数据集根目录。
    4. 本服务使用 HTTP 明文传输。若需暴露到公网, 请在前面套一层
       Nginx / Caddy 等反向代理并启用 HTTPS。
"""

import configparser
import hashlib
import hmac
import json
import os
import re
import secrets
import socketserver
import sys
import threading
import urllib.parse
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


# --------------------------------------------------------------------------
# 控制台编码
# --------------------------------------------------------------------------

def setup_console_encoding():
    """
    把标准输出切换为 UTF-8, 确保中文提示不会显示成乱码。

    必须在任何输出之前调用。打包成可执行文件后尤其重要: 此时
    标准输出默认使用系统 ANSI 代码页(简体中文 Windows 为 cp936),
    与源码中的中文字符串编码不一致, 控制台就会出现乱码。
    """
    # 将 Windows 控制台的代码页切换为 UTF-8 (65001)
    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            # 在无控制台的环境(如重定向输出)中可能失败, 忽略即可
            pass

    # 重新配置 Python 自身的标准流编码
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


setup_console_encoding()


# --------------------------------------------------------------------------
# 常量定义
# --------------------------------------------------------------------------

# 配置文件名(与本脚本/可执行文件放在同一目录)
CONFIG_FILE = "server_config.ini"

# 读取 POST 请求体的上限, 防止超大请求耗尽内存
MAX_POST_BODY = 64 * 1024

# 读写文件时使用的分块大小
CHUNK_SIZE = 256 * 1024

# 计算哈希时使用的分块大小
HASH_CHUNK_SIZE = 1024 * 1024

# 默认的子目录过滤正则: 形如 A001、A002 这样的目录
DEFAULT_INCLUDE_DIRS = r"^A\d+$"

# 默认排除的子目录(多个之间用逗号分隔)
DEFAULT_EXCLUDE_DIRS = "A000"

# 任何情况下都不参与同步的文件名
ALWAYS_SKIP_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}

# 打印日志时使用的锁, 避免多线程下输出互相穿插
_PRINT_LOCK = threading.Lock()


# --------------------------------------------------------------------------
# 基础工具函数
# --------------------------------------------------------------------------

def log(message):
    """线程安全地输出一行带时间戳的日志"""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with _PRINT_LOCK:
        print(f"[{stamp}] {message}", flush=True)


def plain(message=""):
    """线程安全地输出一行不带时间戳的文本(用于启动横幅等)"""
    with _PRINT_LOCK:
        print(message, flush=True)


def get_base_dir():
    """
    取得基准目录, 所有相对路径都以此目录为起点。

    兼容两种运行方式:
        - 由 PyInstaller 打包成单文件可执行程序后运行, 取 .exe 所在目录;
        - 直接以 .py 脚本运行, 取脚本所在目录。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


BASE_DIR = get_base_dir()


def compute_sha256(file_path):
    """计算文件的 SHA-256 摘要, 读取失败时返回 None"""
    digest = hashlib.sha256()
    try:
        with open(file_path, "rb") as handle:
            while True:
                block = handle.read(HASH_CHUNK_SIZE)
                if not block:
                    break
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        log(f"[!] 计算文件摘要失败: {file_path} ({exc})")
        return None


def is_inside_directory(candidate_path, root_dir):
    """
    判断 candidate_path 是否真正位于 root_dir 内部。

    这里不使用简单的字符串前缀比较, 因为 "/data/set-1" 会被误判为
    "/data/set-1-private" 的父目录。改用 os.path.commonpath 做
    规范化后的路径归属判断, 并且会解析符号链接。
    """
    try:
        real_candidate = os.path.realpath(candidate_path)
        real_root = os.path.realpath(root_dir)
        return os.path.commonpath([real_candidate, real_root]) == real_root
    except ValueError:
        # 两个路径位于不同的驱动器时 commonpath 会抛出 ValueError
        return False


def parse_patterns(raw_value, fallback=""):
    """把逗号分隔的配置项拆成去空白、去空项的列表"""
    source = raw_value if raw_value is not None else fallback
    return [item.strip() for item in source.split(",") if item.strip()]


# --------------------------------------------------------------------------
# 配置文件处理
# --------------------------------------------------------------------------

DEFAULT_CONFIG_TEMPLATE = """\
; ==========================================================================
; 通用增量文件同步工具 - 服务端配置文件
; ==========================================================================
; 说明:
;   1. [server] 段用于设置监听地址、端口和访问令牌。
;   2. 其余每一个段(section)代表一个"数据集", 段名就是客户端
;      请求时使用的数据集名称, 只允许使用字母、数字、点、下划线
;      和连字符。
;   3. 修改本文件后需要重新启动服务端才会生效。
; ==========================================================================

[server]
; 监听地址。
;   127.0.0.1 表示只允许本机访问;
;   0.0.0.0   表示允许局域网/公网访问。
host = 127.0.0.1

; 监听端口。
port = 8000

; 访问令牌。客户端必须携带完全一致的令牌才能调用接口。
; 下面这一行是首次启动时自动生成的随机令牌, 请把它填写到
; 客户端的 config.ini 中。如需更换, 直接改成新的字符串即可。
token = {generated_token}

; 是否在日志中打印每一次文件下载请求。
; 数据集文件数量很多时建议设为 false, 以免日志过于嘈杂。
log_downloads = true

; ==========================================================================
; 下面是数据集示例, 请按实际情况修改后使用。
; 可以复制多个段以提供多个数据集。
; ==========================================================================

[example-dataset]
; 该数据集在服务端的真实目录。
; 支持相对路径(相对于本配置文件所在目录)和绝对路径两种写法。
;   相对路径示例: location = share/example-dataset
;   绝对路径示例: location = D:\\data\\example-dataset
location = share/example-dataset

; 只同步名称匹配该正则的一级子目录。
; 留空表示同步 location 下的全部内容。
; 示例: ^A\\d+$ 表示只同步 A001、A002 这类目录。
include_dirs = ^A\\d+$

; 需要排除的一级子目录名, 多个之间用逗号分隔。留空表示不排除。
exclude_dirs = A000
"""


def create_default_config(config_path):
    """当配置文件不存在时, 生成一份带随机令牌的中文模板"""
    content = DEFAULT_CONFIG_TEMPLATE.format(
        generated_token=secrets.token_urlsafe(32)
    )
    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write(content)

    plain()
    plain("=" * 68)
    plain(f"[!] 未找到配置文件 {CONFIG_FILE}, 已为你生成一份模板。")
    plain(f"[*] 文件位置: {config_path}")
    plain("[*] 请按以下步骤操作:")
    plain("      1. 打开该文件, 把 [example-dataset] 的 location")
    plain("         改成你真实的数据目录, 段名也可以自行重命名;")
    plain("      2. 记下 [server] 段里的 token, 稍后填入客户端配置;")
    plain("      3. 保存后重新启动本程序。")
    plain("=" * 68)
    plain()


# 数据集名称只允许这些字符, 避免出现路径分隔符等危险字符
DATASET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


class Dataset:
    """表示一个数据集及其同步规则"""

    def __init__(self, name, root_dir, include_dirs, exclude_dirs):
        self.name = name
        self.root_dir = root_dir
        self.include_patterns = [re.compile(p) for p in include_dirs]
        self.exclude_names = set(exclude_dirs)
        self.snapshot = {}
        self.total_bytes = 0

    def should_include_dir(self, dir_name):
        """判断某个一级子目录是否需要参与同步"""
        if dir_name in self.exclude_names:
            return False
        if not self.include_patterns:
            return True
        return any(p.match(dir_name) for p in self.include_patterns)


class ServerConfig:
    """服务端运行期配置"""

    def __init__(self, host, port, token, log_downloads, datasets):
        self.host = host
        self.port = port
        self.token = token
        self.log_downloads = log_downloads
        self.datasets = datasets


def load_config():
    """
    读取并校验配置文件。

    返回 ServerConfig 实例; 若配置缺失或无效则返回 None,
    由调用方负责终止启动流程。
    """
    config_path = os.path.join(BASE_DIR, CONFIG_FILE)

    if not os.path.exists(config_path):
        create_default_config(config_path)
        return None

    parser = configparser.ConfigParser()
    try:
        parser.read(config_path, encoding="utf-8")
    except configparser.Error as exc:
        plain(f"[!] 配置文件解析失败: {exc}")
        return None

    if not parser.has_section("server"):
        plain(f"[!] 配置文件缺少 [server] 段, 请参照注释补全: {config_path}")
        return None

    server_section = parser["server"]
    host = server_section.get("host", "127.0.0.1").strip() or "127.0.0.1"

    try:
        port = int(server_section.get("port", "8000").strip())
    except ValueError:
        plain("[!] [server] 段的 port 必须是数字。")
        return None
    if not 1 <= port <= 65535:
        plain("[!] [server] 段的 port 必须位于 1-65535 之间。")
        return None

    token = server_section.get("token", "").strip().strip('"')
    if not token:
        plain("[!] [server] 段的 token 不能为空, 请设置一个访问令牌。")
        return None
    if len(token) < 16:
        plain("[!] 为保证安全, token 长度至少需要 16 个字符。")
        return None

    log_downloads = server_section.getboolean("log_downloads", fallback=True)

    # 解析各数据集
    datasets = {}
    for section_name in parser.sections():
        if section_name == "server":
            continue

        if not DATASET_NAME_PATTERN.match(section_name):
            plain(
                f"[!] 数据集名称 '{section_name}' 含有非法字符, 已跳过。"
                " 仅支持字母、数字、点、下划线和连字符。"
            )
            continue

        section = parser[section_name]
        raw_location = section.get("location", "").strip().strip('"')
        if not raw_location:
            plain(f"[!] 数据集 '{section_name}' 缺少 location 配置项, 已跳过。")
            continue

        location = os.path.normpath(
            raw_location
            if os.path.isabs(raw_location)
            else os.path.join(BASE_DIR, raw_location)
        )

        if not os.path.isdir(location):
            plain(
                f"[!] 数据集 '{section_name}' 的目录不存在或不是文件夹, 已跳过:"
                f" {location}"
            )
            continue

        include_dirs = parse_patterns(
            section.get("include_dirs"), DEFAULT_INCLUDE_DIRS
        )
        exclude_dirs = parse_patterns(
            section.get("exclude_dirs"), DEFAULT_EXCLUDE_DIRS
        )

        try:
            datasets[section_name] = Dataset(
                section_name, location, include_dirs, exclude_dirs
            )
        except re.error as exc:
            plain(
                f"[!] 数据集 '{section_name}' 的 include_dirs 不是合法正则,"
                f" 已跳过: {exc}"
            )

    if not datasets:
        plain(f"[!] 配置文件中没有任何可用的数据集: {config_path}")
        plain("[*] 请至少配置一个数据集, 并确认其 location 目录确实存在。")
        return None

    return ServerConfig(host, port, token, log_downloads, datasets)


# --------------------------------------------------------------------------
# 快照生成
# --------------------------------------------------------------------------

def build_snapshot(dataset):
    """
    扫描数据集目录, 生成文件清单。

    清单结构为:
        { "相对路径": {"size": 字节数, "mtime": 修改时间, "hash": SHA256} }

    相对路径统一使用正斜杠, 以保证跨平台一致。
    """
    plain(f"[*] 正在扫描数据集 '{dataset.name}' -> {dataset.root_dir}")

    snapshot = {}
    total_bytes = 0
    skipped = 0

    try:
        entries = sorted(os.listdir(dataset.root_dir))
    except OSError as exc:
        plain(f"[!] 无法读取数据集目录: {dataset.root_dir} ({exc})")
        return False

    # 确定本次需要遍历的顶层范围
    if dataset.include_patterns or dataset.exclude_names:
        roots = []
        for name in entries:
            full = os.path.join(dataset.root_dir, name)
            if os.path.isdir(full) and dataset.should_include_dir(name):
                roots.append(full)
    else:
        roots = [dataset.root_dir]

    for root_path in roots:
        for current_dir, sub_dirs, file_names in os.walk(root_path):
            sub_dirs.sort()
            for file_name in sorted(file_names):
                if file_name in ALWAYS_SKIP_FILES:
                    continue

                full_path = os.path.join(current_dir, file_name)

                # 跳过指向数据集之外的符号链接, 避免泄露无关文件
                if not is_inside_directory(full_path, dataset.root_dir):
                    log(f"[!] 跳过指向目录外的文件: {full_path}")
                    skipped += 1
                    continue

                file_hash = compute_sha256(full_path)
                if file_hash is None:
                    skipped += 1
                    continue

                try:
                    stat_result = os.stat(full_path)
                except OSError:
                    skipped += 1
                    continue

                relative_path = os.path.relpath(
                    full_path, dataset.root_dir
                ).replace(os.sep, "/")

                snapshot[relative_path] = {
                    "size": stat_result.st_size,
                    "mtime": stat_result.st_mtime,
                    "hash": file_hash,
                }
                total_bytes += stat_result.st_size

    dataset.snapshot = snapshot
    dataset.total_bytes = total_bytes

    size_text = format_size(total_bytes)
    plain(f"    -> 共索引 {len(snapshot)} 个文件, 合计 {size_text}")
    if skipped:
        plain(f"    -> 有 {skipped} 个文件因读取失败或越界被跳过")
    return True


def format_size(num_bytes):
    """把字节数格式化成便于阅读的字符串"""
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(num_bytes)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.2f} {unit}"
        value /= 1024
    return f"{num_bytes} B"


# --------------------------------------------------------------------------
# HTTP 请求处理
# --------------------------------------------------------------------------

class SyncRequestHandler(BaseHTTPRequestHandler):
    """处理客户端的同步请求"""

    # 使用 HTTP/1.1 以支持连接复用, 加快大量小文件的下载速度
    protocol_version = "HTTP/1.1"
    server_version = "FileSyncServer/1.0"
    sys_version = ""

    # 由 run_server 在启动时注入
    config = None

    # ---------------- 通用辅助 ----------------

    def log_message(self, format, *args):
        """屏蔽标准库默认的访问日志, 统一由本模块的 log() 输出"""
        return

    def send_json(self, payload, status=HTTPStatus.OK):
        """以 JSON 形式返回响应"""
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json_error(self, status, message):
        """以 JSON 形式返回错误, 便于客户端解析提示文案"""
        self.send_json({"status": "error", "message": message}, status=status)

    def client_ip(self):
        """取得客户端 IP, 仅用于日志展示"""
        try:
            return self.client_address[0]
        except (AttributeError, IndexError):
            return "未知"

    def check_token(self, query_params):
        """
        校验访问令牌。

        支持两种传递方式:
            - 请求头 X-Auth-Token: <令牌>
            - 查询参数 ?token=<令牌>
        校验通过返回 True, 否则已自行返回 401 并返回 False。
        """
        provided = self.headers.get("X-Auth-Token")
        if not provided:
            provided = query_params.get("token", [None])[0]

        if provided and hmac.compare_digest(provided, self.config.token):
            return True

        log(f"[!] 令牌校验失败 - 来源 IP: {self.client_ip()}, 路径: {self.path}")
        self.send_json_error(
            HTTPStatus.UNAUTHORIZED,
            "访问令牌缺失或不正确, 请检查客户端配置中的 token 是否与服务端一致。",
        )
        return False

    # ---------------- POST ----------------

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed.query)

        if parsed.path != "/register":
            self.send_json_error(HTTPStatus.NOT_FOUND, "接口不存在。")
            return

        if not self.check_token(query_params):
            return

        # 读取并解析请求体
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json_error(
                HTTPStatus.BAD_REQUEST, "Content-Length 头不合法。"
            )
            return

        if content_length > MAX_POST_BODY:
            self.send_json_error(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "请求体过大。"
            )
            return

        raw_body = self.rfile.read(content_length) if content_length else b"{}"

        try:
            client_info = json.loads(raw_body.decode("utf-8") or "{}")
            if not isinstance(client_info, dict):
                raise ValueError("请求体必须是 JSON 对象")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            self.send_json_error(
                HTTPStatus.BAD_REQUEST, f"请求体不是合法的 JSON: {exc}"
            )
            return

        dataset_name = str(client_info.get("dataset", "未指定"))[:128]
        client_name = str(client_info.get("client", "未知"))[:128]

        log(
            f"客户端注册 - IP: {self.client_ip()}, "
            f"数据集: {dataset_name}, 标识: {client_name}"
        )

        self.send_json({"status": "ok", "message": "注册成功"})

    # ---------------- GET / HEAD ----------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed.query)
        path = parsed.path

        # 健康检查接口不需要令牌, 方便做存活探测
        if path == "/healthz":
            self.send_json({"status": "ok", "datasets": len(self.config.datasets)})
            return

        if not self.check_token(query_params):
            return

        if path == "/datasets":
            self.handle_list_datasets()
            return

        if path == "/snapshot":
            self.handle_snapshot(query_params)
            return

        if path.startswith("/files/"):
            self.handle_file_download(path)
            return

        self.send_json_error(HTTPStatus.NOT_FOUND, "接口不存在。")

    # ---------------- 各接口的具体实现 ----------------

    def handle_list_datasets(self):
        """返回可用数据集概要, 不暴露服务端的真实目录"""
        items = [
            {
                "name": dataset.name,
                "files": len(dataset.snapshot),
                "bytes": dataset.total_bytes,
            }
            for dataset in self.config.datasets.values()
        ]
        items.sort(key=lambda item: item["name"])
        self.send_json({"status": "ok", "datasets": items})

    def handle_snapshot(self, query_params):
        """返回指定数据集的文件清单"""
        dataset_name = query_params.get("dataset", [None])[0]

        if not dataset_name:
            self.send_json_error(
                HTTPStatus.BAD_REQUEST, "缺少查询参数 dataset。"
            )
            return

        dataset = self.config.datasets.get(dataset_name)
        if dataset is None:
            log(
                f"[!] 请求了未配置的数据集 - IP: {self.client_ip()}, "
                f"数据集: {dataset_name}"
            )
            self.send_json_error(
                HTTPStatus.NOT_FOUND,
                f"服务端没有配置名为 '{dataset_name}' 的数据集。",
            )
            return

        log(
            f"快照请求 - IP: {self.client_ip()}, 数据集: {dataset_name}, "
            f"文件数: {len(dataset.snapshot)}"
        )
        self.send_json(
            {
                "status": "ok",
                "dataset": dataset.name,
                "files": dataset.snapshot,
            }
        )

    def handle_file_download(self, path):
        """
        下载单个文件。

        URL 形如 /files/<数据集名>/<文件相对路径>, 其中相对路径需要
        做 URL 编码。服务端会先定位数据集, 再校验目标文件确实位于该
        数据集目录内部, 最后才读取并返回文件内容。
        """
        encoded = path[len("/files/"):]
        decoded = urllib.parse.unquote(encoded, encoding="utf-8")

        if "/" not in decoded:
            self.send_json_error(
                HTTPStatus.BAD_REQUEST,
                "路径格式应为 /files/<数据集名>/<文件相对路径>。",
            )
            return

        dataset_name, relative_path = decoded.split("/", 1)

        dataset = self.config.datasets.get(dataset_name)
        if dataset is None:
            self.send_json_error(
                HTTPStatus.NOT_FOUND,
                f"服务端没有配置名为 '{dataset_name}' 的数据集。",
            )
            return

        # 只允许下载快照中登记过的文件。这一步同时也杜绝了
        # 通过构造 ../ 之类的路径读取任意文件的可能。
        if relative_path not in dataset.snapshot:
            log(
                f"[!] 拒绝下载未登记的文件 - IP: {self.client_ip()}, "
                f"数据集: {dataset_name}, 路径: {relative_path}"
            )
            self.send_json_error(
                HTTPStatus.NOT_FOUND, "该文件不在服务端的同步清单内。"
            )
            return

        target_path = os.path.normpath(
            os.path.join(dataset.root_dir, relative_path.replace("/", os.sep))
        )

        # 双重保险: 再次确认最终路径位于数据集目录内部
        if not is_inside_directory(target_path, dataset.root_dir):
            log(
                f"[!] 阻止越界访问 - IP: {self.client_ip()}, "
                f"路径: {relative_path}"
            )
            self.send_json_error(HTTPStatus.FORBIDDEN, "请求的路径越界。")
            return

        if not os.path.isfile(target_path):
            self.send_json_error(
                HTTPStatus.NOT_FOUND,
                "文件在服务端已不存在, 可能需要重启服务端以刷新清单。",
            )
            return

        if self.config.log_downloads:
            log(
                f"下载请求 - IP: {self.client_ip()}, "
                f"数据集: {dataset_name}, 文件: {relative_path}"
            )

        try:
            with open(target_path, "rb") as handle:
                file_size = os.fstat(handle.fileno()).st_size

                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(file_size))
                self.send_header(
                    "X-Content-SHA256", dataset.snapshot[relative_path]["hash"]
                )
                self.end_headers()

                if self.command == "HEAD":
                    return

                while True:
                    block = handle.read(CHUNK_SIZE)
                    if not block:
                        break
                    self.wfile.write(block)
        except (BrokenPipeError, ConnectionResetError):
            # 客户端提前断开连接属于正常现象, 不作为错误处理
            log(f"[*] 客户端中断了下载: {relative_path}")
        except OSError as exc:
            log(f"[!] 读取文件失败: {target_path} ({exc})")
            # 响应头可能已经发出, 此时无法再改成错误状态码


# --------------------------------------------------------------------------
# 启动流程
# --------------------------------------------------------------------------

class SyncServer(ThreadingHTTPServer):
    """
    多线程 HTTP 服务。

    标准库的 TCPServer 为单线程, 一次只能服务一个客户端, 传输大文件
    时会阻塞其他请求; 这里改用 ThreadingHTTPServer 并开启地址复用。
    """

    daemon_threads = True
    allow_reuse_address = True


def print_banner(config):
    """打印启动信息"""
    display_host = "127.0.0.1" if config.host == "0.0.0.0" else config.host

    plain()
    plain("=" * 68)
    plain("[*] 通用增量文件同步工具 - 服务端已启动")
    plain(f"[*] 监听地址: http://{config.host}:{config.port}")
    plain(f"[*] 本机访问: http://{display_host}:{config.port}")
    plain(f"[*] 已加载 {len(config.datasets)} 个数据集:")
    for dataset in config.datasets.values():
        plain(
            f"      - {dataset.name}: {len(dataset.snapshot)} 个文件, "
            f"{format_size(dataset.total_bytes)}"
        )
    plain("[*] 所有接口均需携带访问令牌 (请求头 X-Auth-Token 或参数 token)")
    if config.host == "0.0.0.0":
        plain("[!] 当前监听 0.0.0.0, 局域网内其他设备可以访问本服务。")
        plain("[!] 本服务为 HTTP 明文传输, 暴露到公网时请套一层 HTTPS 反向代理。")
    plain("[*] 按 Ctrl+C 停止服务")
    plain("=" * 68)
    plain()


def run_server():
    """装载配置、生成快照并启动 HTTP 服务"""
    plain("[*] 正在读取服务端配置...")
    config = load_config()
    if config is None:
        plain("[!] 服务端启动失败, 请根据上面的提示检查配置文件。")
        return 1

    plain(f"[*] 共发现 {len(config.datasets)} 个数据集, 开始生成文件清单...")
    usable = {}
    for name, dataset in config.datasets.items():
        if build_snapshot(dataset):
            usable[name] = dataset
        else:
            plain(f"[!] 数据集 '{name}' 清单生成失败, 本次运行将不提供该数据集。")

    if not usable:
        plain("[!] 没有任何数据集可用, 服务端退出。")
        return 1

    config.datasets = usable
    SyncRequestHandler.config = config

    try:
        httpd = SyncServer((config.host, config.port), SyncRequestHandler)
    except OSError as exc:
        plain(f"[!] 无法绑定 {config.host}:{config.port} ({exc})")
        plain("[*] 请确认端口未被占用, 或在配置文件中换一个端口。")
        return 1

    print_banner(config)

    with httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            plain()
            plain("[*] 收到停止信号, 服务端正在关闭...")
        finally:
            httpd.shutdown()

    plain("[*] 服务端已退出。")
    return 0


if __name__ == "__main__":
    sys.exit(run_server())
