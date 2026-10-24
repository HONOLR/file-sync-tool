#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
通用增量文件同步工具 - 客户端

功能说明:
    从服务端取得数据集的文件清单(快照), 与本地目录逐一比对, 只下载
    缺失或内容不一致的文件, 从而实现增量同步。每个文件下载完成后都会
    重新计算 SHA-256 并与清单比对, 校验不通过则丢弃重试。

使用方式:
    python sync_client.py              正常执行同步
    python sync_client.py --check      只检查差异, 不实际下载
    python sync_client.py --list       列出服务端可用的数据集
    python sync_client.py --force      忽略本地文件, 重新下载全部内容

实现说明:
    仅使用 Python 标准库, 无需安装任何第三方依赖。
"""

import argparse
import configparser
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


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
CONFIG_FILE = "config.ini"

# 读写文件时使用的分块大小
CHUNK_SIZE = 256 * 1024

# 计算哈希时使用的分块大小
HASH_CHUNK_SIZE = 1024 * 1024

# 单个请求的默认超时(秒)
DEFAULT_TIMEOUT = 30

# 单个文件下载失败后的重试次数
DEFAULT_RETRIES = 3

# 重试之间的等待秒数
RETRY_BACKOFF = 2


# --------------------------------------------------------------------------
# 基础工具函数
# --------------------------------------------------------------------------

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
    except OSError:
        return None


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


def is_safe_relative_path(relative_path):
    """
    校验服务端返回的相对路径是否安全。

    这一步非常关键: 文件清单来自服务端, 如果不加校验就直接拼接成
    本地路径, 一个被篡改的服务端(或中间人)就能通过 `../../` 或者
    绝对路径把文件写到同步目录之外的任意位置。

    不满足以下全部条件的路径都会被拒绝:
        1. 非空, 且不含 NUL 字符;
        2. 不是绝对路径, 也不带 Windows 盘符(如 C:);
        3. 不以分隔符开头(避免被当作根路径);
        4. 任何一段都不是 `..`;
        5. 不含 Windows 保留字符。
    """
    if not relative_path or "\x00" in relative_path:
        return False

    # 统一成正斜杠后再做检查
    normalized = relative_path.replace("\\", "/")

    if normalized.startswith("/"):
        return False

    # 含盘符的写法, 例如 "C:/windows" 或 "C:windows"
    if len(normalized) >= 2 and normalized[1] == ":":
        return False

    if os.path.isabs(normalized):
        return False

    segments = normalized.split("/")
    for segment in segments:
        if segment in ("", ".", ".."):
            return False
        # Windows 下这些字符不允许出现在文件名中
        if os.name == "nt" and any(ch in segment for ch in '<>:"|?*'):
            return False

    return True


def resolve_target_path(download_dir, relative_path):
    """
    把服务端给出的相对路径转换成本地绝对路径, 并确认其位于
    download_dir 内部。校验失败返回 None。
    """
    if not is_safe_relative_path(relative_path):
        return None

    local_path = os.path.normpath(
        os.path.join(download_dir, relative_path.replace("/", os.sep))
    )

    try:
        real_root = os.path.realpath(download_dir)
        # 目标文件此时可能还不存在, 因此对其所在目录做解析
        real_parent = os.path.realpath(os.path.dirname(local_path))
        if os.path.commonpath([real_parent, real_root]) != real_root:
            return None
    except ValueError:
        # 跨驱动器的情况
        return None

    return local_path


# --------------------------------------------------------------------------
# 配置文件处理
# --------------------------------------------------------------------------

DEFAULT_CONFIG_TEMPLATE = """\
; ==========================================================================
; 通用增量文件同步工具 - 客户端配置文件
; ==========================================================================
; 说明:
;   路径既可以写成相对于本配置文件所在目录的相对路径,
;   也可以写成完整的绝对路径。
; ==========================================================================

[server]
; 服务端地址, 需要包含协议和端口。
;   示例: http://127.0.0.1:8000
;   示例: https://sync.example.com
url = http://127.0.0.1:8000

; 访问令牌, 必须与服务端 server_config.ini 中的 token 完全一致。
token = 请在此填写服务端生成的访问令牌

; 要同步的数据集名称, 对应服务端配置文件里的段名。
; 不确定可用名称时, 可执行 `python sync_client.py --list` 查询。
dataset = example-dataset

; 单个请求的超时时间(秒)。
timeout = 30

; 单个文件下载失败后的重试次数。
retries = 3

[local]
; 本地同步目录: 服务端的文件会按相对路径还原到该目录下。
; 目录不存在时会自动创建。
;   相对路径示例: download_dir = data
;   绝对路径示例: download_dir = D:\\data\\example-dataset
download_dir = data

; 客户端标识, 会随注册请求一起上报, 方便在服务端日志里区分来源。
; 留空则自动使用本机计算机名。
client_name =
"""


def create_default_config(config_path):
    """当配置文件不存在时, 生成一份中文模板"""
    with open(config_path, "w", encoding="utf-8") as handle:
        handle.write(DEFAULT_CONFIG_TEMPLATE)

    print()
    print("=" * 68)
    print(f"[!] 未找到配置文件 {CONFIG_FILE}, 已为你生成一份模板。")
    print(f"[*] 文件位置: {config_path}")
    print("[*] 请按以下步骤操作:")
    print("      1. 打开该文件, 填写服务端地址 url;")
    print("      2. 填写 token, 需与服务端配置中的令牌完全一致;")
    print("      3. 填写 dataset, 即要同步的数据集名称;")
    print("      4. 确认 download_dir 指向正确的本地目录;")
    print("      5. 保存后重新运行本程序。")
    print("=" * 68)
    print()


class ClientConfig:
    """客户端运行期配置"""

    def __init__(self, url, token, dataset, download_dir, timeout, retries,
                 client_name):
        self.url = url
        self.token = token
        self.dataset = dataset
        self.download_dir = download_dir
        self.timeout = timeout
        self.retries = retries
        self.client_name = client_name


def load_config():
    """
    读取并校验配置文件。

    返回 ClientConfig 实例; 若配置缺失或无效则返回 None,
    由调用方负责终止流程。
    """
    config_path = os.path.join(BASE_DIR, CONFIG_FILE)

    if not os.path.exists(config_path):
        create_default_config(config_path)
        return None

    parser = configparser.ConfigParser()
    try:
        parser.read(config_path, encoding="utf-8")
    except configparser.Error as exc:
        print(f"[!] 配置文件解析失败: {exc}")
        return None

    if not parser.has_section("server"):
        print(f"[!] 配置文件缺少 [server] 段: {config_path}")
        return None

    server_section = parser["server"]

    url = server_section.get("url", "").strip().strip('"').rstrip("/")
    if not url:
        print("[!] [server] 段的 url 不能为空。")
        return None

    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        print(f"[!] 服务端地址格式不正确: {url}")
        print("[*] 正确的写法形如 http://127.0.0.1:8000")
        return None

    token = server_section.get("token", "").strip().strip('"')
    if not token or token.startswith("请在此填写"):
        print("[!] 请先在配置文件中填写访问令牌 token。")
        print(f"[*] 配置文件位置: {config_path}")
        print("[*] 令牌可在服务端的 server_config.ini 中查看。")
        return None

    dataset = server_section.get("dataset", "").strip().strip('"')
    if not dataset:
        print("[!] [server] 段的 dataset 不能为空。")
        print("[*] 可执行 `--list` 参数查询服务端有哪些可用数据集。")
        return None

    try:
        timeout = float(server_section.get("timeout", DEFAULT_TIMEOUT))
        if timeout <= 0:
            raise ValueError
    except ValueError:
        print(f"[!] timeout 配置不合法, 已回退为默认值 {DEFAULT_TIMEOUT} 秒。")
        timeout = DEFAULT_TIMEOUT

    try:
        retries = int(server_section.get("retries", DEFAULT_RETRIES))
        if retries < 0:
            raise ValueError
    except ValueError:
        print(f"[!] retries 配置不合法, 已回退为默认值 {DEFAULT_RETRIES} 次。")
        retries = DEFAULT_RETRIES

    local_section = parser["local"] if parser.has_section("local") else {}
    raw_download_dir = ""
    client_name = ""
    if local_section:
        raw_download_dir = local_section.get("download_dir", "").strip().strip('"')
        client_name = local_section.get("client_name", "").strip().strip('"')

    if not raw_download_dir:
        print("[!] [local] 段的 download_dir 不能为空。")
        return None

    download_dir = os.path.normpath(
        raw_download_dir
        if os.path.isabs(raw_download_dir)
        else os.path.join(BASE_DIR, raw_download_dir)
    )

    if not client_name:
        client_name = os.environ.get("COMPUTERNAME") or os.environ.get(
            "HOSTNAME"
        ) or "未命名客户端"

    return ClientConfig(
        url, token, dataset, download_dir, timeout, retries, client_name
    )


# --------------------------------------------------------------------------
# 与服务端通信
# --------------------------------------------------------------------------

class SyncError(Exception):
    """与服务端交互过程中出现的可预期错误"""


class ServerClient:
    """封装对服务端各接口的调用"""

    def __init__(self, config):
        self.config = config
        # 使用带连接池的 opener, 并禁用代理, 避免本地代理干扰内网访问
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({})
        )

    def _build_request(self, path, query=None, data=None):
        """构造一个带令牌的请求对象"""
        url = f"{self.config.url}{path}"
        if query:
            url = f"{url}?{urllib.parse.urlencode(query)}"

        headers = {
            "X-Auth-Token": self.config.token,
            "User-Agent": "FileSyncClient/1.0",
            "Accept-Encoding": "identity",
        }
        if data is not None:
            headers["Content-Type"] = "application/json; charset=utf-8"

        return urllib.request.Request(url, data=data, headers=headers)

    def _describe_http_error(self, exc):
        """把 HTTP 错误翻译成便于理解的中文提示"""
        detail = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
            payload = json.loads(body)
            if isinstance(payload, dict):
                detail = payload.get("message", "")
        except (OSError, ValueError, json.JSONDecodeError):
            pass

        if exc.code == 401:
            return detail or "访问令牌不正确, 请检查客户端与服务端的 token 是否一致。"
        if exc.code == 403:
            return detail or "服务端拒绝了本次请求。"
        if exc.code == 404:
            return detail or "服务端上不存在该资源。"
        return detail or f"服务端返回 HTTP {exc.code} {exc.reason}"

    def request_json(self, path, query=None, payload=None):
        """调用一个返回 JSON 的接口"""
        data = None
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        request = self._build_request(path, query=query, data=data)

        try:
            with self.opener.open(request, timeout=self.config.timeout) as resp:
                body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise SyncError(self._describe_http_error(exc)) from exc
        except urllib.error.URLError as exc:
            raise SyncError(
                f"无法连接到服务端 {self.config.url} ({exc.reason})"
            ) from exc
        except TimeoutError as exc:
            raise SyncError(
                f"连接服务端超时(超过 {self.config.timeout:.0f} 秒)"
            ) from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise SyncError(f"服务端返回的内容不是合法 JSON: {exc}") from exc

    def register(self):
        """向服务端上报客户端信息"""
        return self.request_json(
            "/register",
            payload={
                "dataset": self.config.dataset,
                "client": self.config.client_name,
            },
        )

    def list_datasets(self):
        """取得服务端可用数据集列表"""
        result = self.request_json("/datasets")
        return result.get("datasets", [])

    def fetch_snapshot(self):
        """取得当前数据集的文件清单"""
        result = self.request_json(
            "/snapshot", query={"dataset": self.config.dataset}
        )
        files = result.get("files")
        if not isinstance(files, dict):
            raise SyncError("服务端返回的文件清单格式不正确。")
        return files

    def download_to(self, relative_path, destination, expected_hash,
                    expected_size):
        """
        下载单个文件。

        为避免中断导致目标文件残缺, 先写入同目录下的临时文件, 校验
        SHA-256 通过后再原子性地替换到目标位置。
        """
        quoted_dataset = urllib.parse.quote(self.config.dataset, safe="")
        quoted_path = urllib.parse.quote(relative_path, safe="/")
        path = f"/files/{quoted_dataset}/{quoted_path}"

        request = self._build_request(path)

        parent_dir = os.path.dirname(destination)
        os.makedirs(parent_dir, exist_ok=True)

        temp_fd, temp_path = tempfile.mkstemp(
            prefix=".sync-", suffix=".part", dir=parent_dir
        )
        os.close(temp_fd)

        try:
            digest = hashlib.sha256()
            written = 0

            try:
                with self.opener.open(
                    request, timeout=self.config.timeout
                ) as resp, open(temp_path, "wb") as out:
                    while True:
                        block = resp.read(CHUNK_SIZE)
                        if not block:
                            break
                        out.write(block)
                        digest.update(block)
                        written += len(block)
            except urllib.error.HTTPError as exc:
                raise SyncError(self._describe_http_error(exc)) from exc
            except urllib.error.URLError as exc:
                raise SyncError(f"下载失败 ({exc.reason})") from exc
            except TimeoutError as exc:
                raise SyncError("下载超时") from exc

            if expected_size is not None and written != expected_size:
                raise SyncError(
                    f"文件大小不符(期望 {expected_size} 字节, "
                    f"实际 {written} 字节)"
                )

            actual_hash = digest.hexdigest()
            if actual_hash != expected_hash:
                raise SyncError(
                    "内容校验失败: 下载到的文件与服务端清单不一致"
                )

            # 校验通过, 替换到目标位置
            os.replace(temp_path, destination)
            temp_path = None
            return written
        finally:
            if temp_path and os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except OSError:
                    pass


# --------------------------------------------------------------------------
# 同步主流程
# --------------------------------------------------------------------------

def validate_snapshot(snapshot, download_dir):
    """
    校验服务端清单的合法性。

    返回 (有效条目字典, 被拒绝的路径列表)。任何路径不安全或字段
    缺失的条目都会被剔除, 不参与后续下载。
    """
    valid = {}
    rejected = []

    for relative_path, info in snapshot.items():
        if not isinstance(info, dict):
            rejected.append(relative_path)
            continue

        file_hash = info.get("hash")
        if not isinstance(file_hash, str) or len(file_hash) != 64:
            rejected.append(relative_path)
            continue

        try:
            int(file_hash, 16)
        except ValueError:
            rejected.append(relative_path)
            continue

        local_path = resolve_target_path(download_dir, relative_path)
        if local_path is None:
            rejected.append(relative_path)
            continue

        size = info.get("size")
        valid[relative_path] = {
            "hash": file_hash.lower(),
            "size": size if isinstance(size, int) and size >= 0 else None,
            "local_path": local_path,
        }

    return valid, rejected


def find_differences(entries, force=False):
    """
    比对本地文件与清单, 找出需要下载的条目。

    返回 (待下载列表, 已是最新的数量)。
    """
    pending = []
    up_to_date = 0

    total = len(entries)
    for index, (relative_path, info) in enumerate(sorted(entries.items()), 1):
        if total >= 200 and index % 100 == 0:
            print(f"    - 校验进度: {index}/{total}")

        local_path = info["local_path"]

        if force:
            pending.append((relative_path, info, "强制重新下载"))
            continue

        if not os.path.exists(local_path):
            pending.append((relative_path, info, "本地缺失"))
            continue

        # 先用文件大小做快速筛查, 大小不符时无需再计算哈希
        if info["size"] is not None:
            try:
                if os.path.getsize(local_path) != info["size"]:
                    pending.append((relative_path, info, "大小不符"))
                    continue
            except OSError:
                pending.append((relative_path, info, "无法读取"))
                continue

        local_hash = compute_sha256(local_path)
        if local_hash is None:
            pending.append((relative_path, info, "无法读取"))
        elif local_hash != info["hash"]:
            pending.append((relative_path, info, "内容不符"))
        else:
            up_to_date += 1

    return pending, up_to_date


def download_pending(client, pending):
    """
    逐个下载待同步文件, 失败时按配置重试。

    返回 (成功数, 失败列表, 累计字节数)。
    """
    total = len(pending)
    succeeded = 0
    failed = []
    total_bytes = 0
    max_attempts = client.config.retries + 1

    for index, (relative_path, info, reason) in enumerate(pending, 1):
        size_text = (
            f", {format_size(info['size'])}" if info["size"] is not None else ""
        )
        print(f"    ({index}/{total}) {relative_path} [{reason}{size_text}]")

        last_error = None
        for attempt in range(1, max_attempts + 1):
            try:
                written = client.download_to(
                    relative_path,
                    info["local_path"],
                    info["hash"],
                    info["size"],
                )
                total_bytes += written
                succeeded += 1
                last_error = None
                break
            except SyncError as exc:
                last_error = str(exc)
                if attempt < max_attempts:
                    wait = RETRY_BACKOFF * attempt
                    print(
                        f"          第 {attempt} 次尝试失败: {last_error}; "
                        f"{wait} 秒后重试"
                    )
                    time.sleep(wait)
            except OSError as exc:
                last_error = f"写入本地文件失败: {exc}"
                break

        if last_error is not None:
            print(f"          下载失败: {last_error}")
            failed.append((relative_path, last_error))

    return succeeded, failed, total_bytes


def check_free_space(download_dir, required_bytes):
    """粗略检查磁盘剩余空间是否够用, 不足时给出提示"""
    try:
        probe_dir = download_dir
        while probe_dir and not os.path.isdir(probe_dir):
            parent = os.path.dirname(probe_dir)
            if parent == probe_dir:
                break
            probe_dir = parent
        usage = shutil.disk_usage(probe_dir)
    except OSError:
        return True

    if usage.free < required_bytes:
        print()
        print(
            f"[!] 磁盘剩余空间不足: 需要约 {format_size(required_bytes)}, "
            f"当前可用 {format_size(usage.free)}"
        )
        return False
    return True


def command_list(client):
    """--list: 列出服务端可用的数据集"""
    print("[*] 正在查询服务端可用的数据集...")
    datasets = client.list_datasets()

    if not datasets:
        print("[!] 服务端当前没有可用的数据集。")
        return 1

    print()
    print(f"[*] 服务端共有 {len(datasets)} 个数据集:")
    for item in datasets:
        print(
            f"      - {item.get('name')}: {item.get('files', 0)} 个文件, "
            f"{format_size(item.get('bytes', 0))}"
        )
    print()
    print("[*] 把需要同步的名称填入 config.ini 的 dataset 配置项即可。")
    return 0


def command_sync(client, check_only=False, force=False):
    """执行同步(或只做差异检查)"""
    config = client.config

    print()
    print("=" * 68)
    print("[*] 通用增量文件同步工具 - 客户端")
    print("=" * 68)
    print(f"[*] 服务端地址: {config.url}")
    print(f"[*] 数据集名称: {config.dataset}")
    print(f"[*] 本地目录  : {config.download_dir}")
    if check_only:
        print("[*] 当前模式  : 仅检查差异, 不会下载任何文件")
    elif force:
        print("[*] 当前模式  : 强制重新下载全部文件")
    print()

    # 步骤 1: 向服务端注册
    print("[1/4] 正在连接服务端并校验访问令牌...")
    response = client.register()
    print(f"      服务端响应: {response.get('message', '连接正常')}")

    # 步骤 2: 取得文件清单
    print()
    print("[2/4] 正在获取文件清单...")
    raw_snapshot = client.fetch_snapshot()
    print(f"      服务端清单包含 {len(raw_snapshot)} 个文件")

    entries, rejected = validate_snapshot(raw_snapshot, config.download_dir)

    if rejected:
        print()
        print(f"[!] 有 {len(rejected)} 个条目因路径不安全或字段异常被忽略:")
        for item in rejected[:10]:
            print(f"      - {item}")
        if len(rejected) > 10:
            print(f"      ... 其余 {len(rejected) - 10} 条略")
        print("[!] 这通常意味着服务端清单异常, 建议核实服务端是否可信。")

    if not entries:
        print()
        print("[!] 没有任何可同步的文件, 流程结束。")
        return 1

    # 步骤 3: 比对本地文件
    print()
    print("[3/4] 正在校验本地文件...")
    if not check_only:
        os.makedirs(config.download_dir, exist_ok=True)
    pending, up_to_date = find_differences(entries, force=force)

    print(f"      已是最新: {up_to_date} 个")
    print(f"      需要同步: {len(pending)} 个")

    if not pending:
        print()
        print("[4/4] 本地文件已全部是最新版本, 无需下载。")
        print("=" * 68)
        return 0

    required_bytes = sum(
        info["size"] for _, info, _ in pending if info["size"] is not None
    )

    # 步骤 4: 下载
    print()
    if check_only:
        print("[4/4] 以下文件存在差异(仅检查模式, 不会下载):")
        for relative_path, info, reason in pending[:50]:
            print(f"      - {relative_path} [{reason}]")
        if len(pending) > 50:
            print(f"      ... 其余 {len(pending) - 50} 个略")
        print()
        print(f"[*] 合计需要下载约 {format_size(required_bytes)}")
        print("[*] 去掉 --check 参数即可开始实际下载。")
        print("=" * 68)
        return 0

    if required_bytes and not check_free_space(
        config.download_dir, required_bytes
    ):
        print("[!] 请清理磁盘空间后重试。")
        return 1

    print(
        f"[4/4] 开始下载 {len(pending)} 个文件"
        f"(合计约 {format_size(required_bytes)})..."
    )
    started_at = time.time()
    succeeded, failed, downloaded_bytes = download_pending(client, pending)
    elapsed = max(time.time() - started_at, 0.001)

    print()
    print("=" * 68)
    print(f"[*] 同步完成: 成功 {succeeded} 个, 失败 {len(failed)} 个")
    print(
        f"[*] 实际传输 {format_size(downloaded_bytes)}, "
        f"耗时 {elapsed:.1f} 秒, "
        f"平均 {format_size(downloaded_bytes / elapsed)}/秒"
    )

    if failed:
        print()
        print("[!] 以下文件未能成功同步:")
        for relative_path, error in failed[:20]:
            print(f"      - {relative_path}: {error}")
        if len(failed) > 20:
            print(f"      ... 其余 {len(failed) - 20} 个略")
        print()
        print("[*] 可以重新运行本程序, 已完成的文件不会重复下载。")
        print("=" * 68)
        return 1

    print("[*] 所有文件均已通过 SHA-256 校验。")
    print("=" * 68)
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="通用增量文件同步工具 - 客户端",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="只检查本地与服务端的差异, 不实际下载文件",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="列出服务端所有可用的数据集",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="忽略本地已有文件, 重新下载全部内容",
    )
    args = parser.parse_args()

    config = load_config()
    if config is None:
        return 1

    client = ServerClient(config)

    try:
        if args.list:
            return command_list(client)
        return command_sync(client, check_only=args.check, force=args.force)
    except SyncError as exc:
        print()
        print(f"[!] {exc}")
        print("[*] 请检查:")
        print("      1. 服务端程序是否已经启动;")
        print("      2. config.ini 中的 url 是否填写正确;")
        print("      3. config.ini 中的 token 是否与服务端一致;")
        print("      4. 防火墙或安全软件是否拦截了连接。")
        return 1
    except KeyboardInterrupt:
        print()
        print("[*] 已取消。下次运行会自动跳过已完成的文件。")
        return 130


if __name__ == "__main__":
    sys.exit(main())
