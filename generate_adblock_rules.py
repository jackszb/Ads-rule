#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
【项目标题】AdBlock_Rule_For_Sing-box (Python 版本)
【核心功能】从多个上游广告过滤源抓取规则，经精确解析后转换为 Sing-box 兼容的
           DOMAIN-SUFFIX 与 DOMAIN 格式，最终生成 Sing-box 规则集 JSON 源文件。
【项目主页】https://github.com/REIJI007/AdBlock_Rule_For_Sing-box
【开源协议1】GPL-3.0
【开源协议2】CC-BY-NC-SA 4.0

本脚本是原 PowerShell 版本 (adblock_rule_generator_json.ps1) 的严格 1:1 Python 移植，
除下列必要修正外，完整保留原脚本的判定矩阵与冗余剪枝逻辑：
  - 输出文件名由 adblock_reject.json 改为 adblock.json（按需求变更）
  - 使用 requests + ThreadPoolExecutor 并发下载，替代 .NET HttpClient
  - 使用 Python re 模块替代 PowerShell -match，正则语法保持一致
"""

import concurrent.futures
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from url_list import URL_LIST

# ── 输出路径配置 ──────────────────────────────────────────────────────────────
SCRIPT_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = SCRIPT_DIR / "rules"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_JSON_PATH = OUTPUT_DIR / "adblock.json"
LOG_FILE_PATH = OUTPUT_DIR / "adblock_log.txt"

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
REQUEST_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
REQUEST_TIMEOUT = 30
MAX_WORKERS = 20


def log(message: str) -> None:
    """同时输出到控制台与日志文件（等价于 Write-Host + Add-Content）"""
    print(message)
    with open(LOG_FILE_PATH, "a", encoding="utf-8") as f:
        f.write(message + "\n")


# ── 凡携带以下修饰符的规则均在 HTTP/浏览器/应用层生效，DNS 层无法实施，直接跳过整条规则 ──
MOD_SKIP_SET = {
    # 变换 / 重定向 / 安全策略
    "redirect", "redirect-rule", "csp", "replace",
    # 参数与请求剪裁、Cookie、Header、权限
    "removeparam", "queryprune", "cookie", "header", "permissions",
    # 内联资源 / 媒体 / 内容
    "inline-script", "inline-font", "empty", "mp4", "urltransform",
    "jsonprune", "hls", "referrerpolicy", "content",
    # 屏蔽/隐藏/过滤（通用或特定选择器）
    "genericblock", "generichide", "specifichide", "elemhide", "badfilter", "urlblock",
    # 应用/客户端/标签/方向/来源 标识
    "app", "client", "ctag", "to", "from",
    # 第三方/第一方 标识（及其变体）
    "third-party", "3p", "first-party", "1p", "~third-party", "~3p",
    # 严格一方/三方 模式及其反向标记
    "strict1p", "~strict1p", "strict3p", "~strict3p", "extension",
    # 弹窗/网络/方法/协议/隐私功能 等行为或信号
    "popup", "popunder", "ping", "webrtc", "network", "method",
    "dnstype", "protectedaudience", "privacysandbox",
}

WHITELIST_SUBRESOURCE_TYPES = {
    "document", "script", "image", "stylesheet", "css", "object",
    "xmlhttprequest", "xhr", "media", "font", "subdocument", "ping",
    "websocket", "webrtc", "other", "object-subrequest",
}

LOCALHOST_NAMES = {"localhost", "localhost.localdomain", "local", "broadcasthost"}

IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# ── 工具函数 ──────────────────────────────────────────────────────────────────
def normalize_domain(domain):
    """等价于 Normalize-Domain：IDN -> ASCII(Punycode)，全部转小写"""
    if domain is None or domain.strip() == "":
        return None
    d = domain.strip()
    try:
        ascii_form = d.encode("idna").decode("ascii")
        return ascii_form.lower()
    except Exception:
        return d.lower()


_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_INVALID_CHARS_RE = re.compile(r"[\s\(\)\[\]/\\:;@,+]")


def is_valid_dns_domain(domain):
    """等价于 Is-ValidDNSDomain"""
    if domain is None or domain.strip() == "":
        return False
    domain = normalize_domain(domain)
    if domain is None:
        return False
    if len(domain) > 253:
        return False
    if _INVALID_CHARS_RE.search(domain) or "_" in domain:
        return False
    labels = domain.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if not _LABEL_RE.match(label):
            return False
    if len(labels[-1]) < 2:
        return False
    return True


def is_public_suffix(domain, psl_set):
    return domain in psl_set


_WILDCARD_RE = re.compile(r"^\*+\.(.+)$")


def resolve_wildcard_domain(raw):
    """等价于 Resolve-WildcardDomain"""
    if raw is None or raw.strip() == "":
        return None
    m = _WILDCARD_RE.match(raw)
    if m:
        candidate = normalize_domain(m.group(1))
        if candidate and is_valid_dns_domain(candidate):
            return candidate
    return None


_parent_cache = {}


def get_parent_domains(domain):
    """等价于 Get-ParentDomains（带缓存），返回严格父域列表（不含自身与末级 TLD）"""
    cached = _parent_cache.get(domain)
    if cached is not None:
        return cached
    labels = domain.split(".")
    parents = []
    for i in range(1, len(labels) - 1):
        parents.append(".".join(labels[i:]))
    _parent_cache[domain] = parents
    return parents


class ModifierResult:
    __slots__ = ("decision", "skip_reason", "is_important")

    def __init__(self):
        self.decision = "CONTINUE"
        self.skip_reason = None
        self.is_important = False


_DNSREWRITE_BLOCK_RE = re.compile(r"^noerror;a;[\d.]+$|^noerror;aaaa;[0:]*$|^noerror;aaaa;::1$")


def resolve_modifiers(mod_str):
    """等价于 Resolve-Modifiers"""
    ret = ModifierResult()
    if mod_str is None or mod_str.strip() == "":
        return ret
    for mod in [m.strip().lower() for m in mod_str.split(",")]:
        mod_name = mod.split("=")[0]
        if mod_name in MOD_SKIP_SET:
            ret.decision = "SKIP"
            ret.skip_reason = f"non-dns-modifier:{mod_name}"
            return ret
        if mod_name == "dnsrewrite":
            eq_match = re.search(r"=(.+)$", mod)
            rv = eq_match.group(1) if eq_match else ""
            if rv == "nxdomain" or _DNSREWRITE_BLOCK_RE.match(rv) or rv == "noerror;aaaa;::1":
                continue
            ret.decision = "SKIP"
            ret.skip_reason = f"dnsrewrite-non-block:{rv}"
            return ret
        if mod_name == "domain":
            eq_match = re.search(r"=(.+)$", mod)
            dv = eq_match.group(1) if eq_match else ""
            if dv == "*" or dv == "~*":
                continue
            ret.decision = "SKIP"
            ret.skip_reason = f"context-dependent:domain={dv}"
            return ret
        if mod_name == "important":
            ret.is_important = True
            continue
    if ret.is_important:
        ret.decision = "IMPORTANT_CONTINUE"
    return ret


def is_context_constrained_whitelist(mod_str):
    """等价于 Is-ContextConstrainedWhitelist"""
    if mod_str is None or mod_str.strip() == "":
        return False
    for mod in mod_str.split(","):
        name = mod.split("=")[0].strip().lower()
        if name in WHITELIST_SUBRESOURCE_TYPES or name in MOD_SKIP_SET:
            return True
    return False


def get_whitelist_important_flag(mod_str):
    """等价于 Get-WhitelistImportantFlag"""
    if mod_str is None or mod_str.strip() == "":
        return False
    for mod in [m.strip().lower() for m in mod_str.split(",")]:
        if mod == "important":
            return True
    return False


_WHITELIST_SOURCE_RE = re.compile(r"allowlist|exclusions|exceptions|whitelist", re.IGNORECASE)


def is_whitelist_source(url):
    return bool(_WHITELIST_SOURCE_RE.search(url))


# ── 集中式规则解析函数（等价于 Parse-Rule） ──────────────────────────────────
_RE_COMMENT_HASH = ("##", "#?#", "#@#", "#$#")
_RE_REGEX_RULE = re.compile(r"^/.+/(\$.*)?$")
_RE_EXACT_URL = re.compile(r"^\|https?://")
_RE_WHITELIST_PIPE = re.compile(
    r"^@@\|\|([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+)(.*)$"
)
_RE_WHITELIST_PLAIN = re.compile(r"^@@([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")
_RE_AFTER_DOMAIN_PATH = re.compile(r"^[\^]?[/?]")
_RE_AFTER_DOMAIN_MOD = re.compile(r"^\^?\$(.+)$")
_RE_EXACT_PIPE = re.compile(r"^\|([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\|(\$(.+))?$")
_RE_SUFFIX = re.compile(r"^\|\|([a-zA-Z0-9*][a-zA-Z0-9*.-]*)(.*)")
_RE_REST_BEFORE_DOLLAR = re.compile(r"^([^$]*)")
_RE_PATH_OR_QUERY = re.compile(r"[/?]")
_RE_HOSTS = re.compile(
    r"^(0\.0\.0\.0|127\.0\.0\.1|::1|::0|::)\s+"
    r"([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(\s.*)?$"
)
_RE_DNSMASQ_ADDRESS = re.compile(r"^address=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/([^/]*)$")
_RE_DNSMASQ_SERVER = re.compile(r"^server=/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/")
_RE_DNSMASQ_LOCAL = re.compile(r"^local=/([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/$")
_RE_PLAIN_DOMAIN = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$")


class ParsedRule:
    __slots__ = ("action", "domain", "skip_reason", "source_format", "is_important", "is_wildcard")

    def __init__(self):
        self.action = "SKIP"
        self.domain = None
        self.skip_reason = "unmatched"
        self.source_format = "unknown"
        self.is_important = False
        self.is_wildcard = False


def parse_rule(line, is_whitelist_source_flag=False):
    """等价于 Parse-Rule"""
    result = ParsedRule()

    if (not line) or line.startswith("!") or line.startswith("#") or line.startswith("[") \
            or any(tok in line for tok in _RE_COMMENT_HASH):
        result.skip_reason = "comment-or-cosmetic"
        return result

    if _RE_REGEX_RULE.match(line):
        result.skip_reason = "regex-rule"
        return result

    if _RE_EXACT_URL.match(line):
        result.skip_reason = "exact-url-rule"
        return result

    if line.startswith("@@"):
        extract_domain = None
        mod_part_raw = None
        m = _RE_WHITELIST_PIPE.match(line)
        if m:
            extract_domain = m.group(1).lower()
            after_domain = m.group(5)
            if _RE_AFTER_DOMAIN_PATH.match(after_domain):
                result.skip_reason = "whitelist-path-or-query-specific"
                return result
            m2 = _RE_AFTER_DOMAIN_MOD.match(after_domain)
            if m2:
                mod_part_raw = m2.group(1)
        else:
            m3 = _RE_WHITELIST_PLAIN.match(line)
            if m3:
                extract_domain = m3.group(1).lower()

        if extract_domain is not None:
            if is_context_constrained_whitelist(mod_part_raw):
                result.skip_reason = "whitelist-context-constrained"
            else:
                result.action = "EXCLUDE"
                result.domain = extract_domain
                result.source_format = "adblock-whitelist"
                result.is_important = get_whitelist_important_flag(mod_part_raw)
        else:
            result.skip_reason = "whitelist-unparseable"
        return result

    m = _RE_EXACT_PIPE.match(line)
    if m:
        candidate = m.group(1).lower()
        mod_str = m.group(3)
        mod_result = resolve_modifiers(mod_str)
        if mod_result.decision == "SKIP":
            result.skip_reason = mod_result.skip_reason
            return result
        if is_whitelist_source_flag:
            result.action = "EXCLUDE"
            result.source_format = "whitelist-exact"
        else:
            result.action = "EXACT"
            result.source_format = "adguard-exact"
        result.domain = candidate
        result.is_important = mod_result.is_important
        return result

    m = _RE_SUFFIX.match(line)
    if m:
        raw = m.group(1).lower()
        rest = m.group(2)
        rbd_match = _RE_REST_BEFORE_DOLLAR.match(rest)
        rest_before_dollar = rbd_match.group(1) if rbd_match else ""
        if _RE_PATH_OR_QUERY.search(raw) or _RE_PATH_OR_QUERY.search(rest_before_dollar):
            result.skip_reason = "path-or-query-specific-rule"
            return result
        mod_mod = _RE_AFTER_DOMAIN_MOD.match(rest)
        if mod_mod:
            mod_result = resolve_modifiers(mod_mod.group(1))
            if mod_result.decision == "SKIP":
                result.skip_reason = mod_result.skip_reason
                return result
            result.is_important = mod_result.is_important
        domain = None
        if "*" in raw:
            domain = resolve_wildcard_domain(raw)
            if domain is None:
                result.skip_reason = "unresolvable-wildcard"
                return result
            result.is_wildcard = True
        else:
            domain = raw
        if IP_RE.match(domain):
            result.skip_reason = "ip-address"
            return result
        if is_whitelist_source_flag:
            result.action = "EXCLUDE"
            result.source_format = "whitelist-suffix"
        else:
            result.action = "SUFFIX"
            result.source_format = "adblock-suffix"
        result.domain = domain
        return result

    m = _RE_HOSTS.match(line)
    if m:
        domain = m.group(2).lower()
        if domain in LOCALHOST_NAMES:
            result.skip_reason = "localhost-entry"
            return result
        if is_whitelist_source_flag:
            result.action = "EXCLUDE"
            result.source_format = "whitelist-hosts"
        else:
            result.action = "EXACT"
            result.source_format = "hosts"
        result.domain = domain
        return result

    m = _RE_DNSMASQ_ADDRESS.match(line)
    if m:
        domain = m.group(1).lower()
        target = m.group(2).strip()
        is_block = target in ("", "0.0.0.0", "127.0.0.1", "::",
                               "::1", "::0", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1")
        if not is_block:
            result.skip_reason = f"dnsmasq-dns-forward:{target}"
            return result
        if is_whitelist_source_flag:
            result.action = "EXCLUDE"
            result.source_format = "whitelist-dnsmasq"
        else:
            result.action = "SUFFIX"
            result.source_format = "dnsmasq-address"
        result.domain = domain
        return result

    if _RE_DNSMASQ_SERVER.match(line):
        result.skip_reason = "dnsmasq-server-routing"
        return result

    m = _RE_DNSMASQ_LOCAL.match(line)
    if m:
        if is_whitelist_source_flag:
            result.action = "EXCLUDE"
            result.source_format = "whitelist-dnsmasq-local"
        else:
            result.action = "SUFFIX"
            result.source_format = "dnsmasq-local"
        result.domain = m.group(1).lower()
        return result

    m = _RE_PLAIN_DOMAIN.match(line)
    if m:
        if is_whitelist_source_flag:
            result.action = "EXCLUDE"
            result.source_format = "whitelist-plain"
        else:
            result.action = "EXACT"
            result.source_format = "plain-domain"
        result.domain = m.group(1).lower()
        return result

    result.skip_reason = "no-pattern-match"
    return result


# ── 网络下载 ──────────────────────────────────────────────────────────────────
def fetch_all(urls):
    """并行下载阶段：等价于 PS 中的 HttpClient 并发下载"""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(_safe_get, u): u for u in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            content, err = future.result()
            results[url] = (content, err)
    return results


def _safe_get(url):
    try:
        resp = requests.get(url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.text, None
    except Exception as exc:
        return None, str(exc)


def load_psl(psl_set):
    log("正在加载 PSL 公共后缀列表...")
    try:
        resp = requests.get(PSL_URL, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        psl_content = resp.text
    except Exception as exc:
        log(f"加载 PSL 时出错: {exc}")
        psl_content = ""
    for raw_line in psl_content.split("\n"):
        psl_line = raw_line.strip()
        if psl_line.startswith("//") or psl_line == "":
            continue
        if psl_line.startswith("!") or psl_line.startswith("*"):
            continue
        psl_set.add(psl_line)
    log(f"PSL 加载完成，共 {len(psl_set)} 条")


# ── 五级优先级判定矩阵与最近邻原则（等价于 Get-EffectiveStatus） ────────────
def make_effective_status_fn(important_whitelist_domains, important_domains,
                              valid_excluded_domains, valid_exact_rules, valid_suffix_rules):
    def get_effective_status(domain):
        labels = domain.split(".")
        n = len(labels)

        # P0（最高）：$important 白名单（跨级覆盖一切）
        for i in range(0, n - 1):
            current = ".".join(labels[i:])
            if current in important_whitelist_domains:
                return "WHITELIST_P0"

        # P1：$important 黑名单（覆盖所有普通白名单）
        for i in range(0, n - 1):
            current = ".".join(labels[i:])
            if current in important_domains:
                return "BLACKLIST_P1"

        # 结构解析层：自底向上遍历，最具体的子域优先级高于宽泛的父域
        for i in range(0, n - 1):
            current = ".".join(labels[i:])
            # P2：精确匹配白名单（赦免特定子域）
            if current in valid_excluded_domains:
                return "WHITELIST_P2"
            # P3：精确匹配黑名单（仅在当层匹配时生效，不沿继承链向上扩散）
            if i == 0 and current in valid_exact_rules:
                return "BLACKLIST_P3"
            # P4（最低）：广义后缀/父域黑名单
            if current in valid_suffix_rules:
                return "BLACKLIST_P4"
        return "UNKNOWN"

    return get_effective_status


def main():
    # 清空/初始化日志文件
    with open(LOG_FILE_PATH, "w", encoding="utf-8"):
        pass

    psl_set = set()
    load_psl(psl_set)

    unique_suffix_rules = set()
    unique_exact_rules = set()
    excluded_domains = set()
    important_domains = set()
    important_whitelist_domains = set()
    wildcard_source_doms = set()
    skip_stats = {}
    format_stats = {}

    log(f"开始并发下载 {len(URL_LIST)} 个上游规则源...")
    download_results = fetch_all(URL_LIST)

    for url in URL_LIST:
        log(f"正在处理: {url}")
        is_ws = is_whitelist_source(url)
        content, err = download_results.get(url, (None, "未找到下载结果"))
        if content is None:
            log(f"下载 {url} 时出错: {err}")
            continue
        try:
            for raw_line in content.split("\n"):
                line = raw_line.strip()
                parsed = parse_rule(line, is_ws)
                if parsed.action == "EXCLUDE":
                    if is_valid_dns_domain(parsed.domain):
                        excluded_domains.add(normalize_domain(parsed.domain))
                        if parsed.is_important:
                            important_whitelist_domains.add(normalize_domain(parsed.domain))
                    format_stats[parsed.source_format] = format_stats.get(parsed.source_format, 0) + 1
                elif parsed.action == "SUFFIX":
                    if is_valid_dns_domain(parsed.domain) and not IP_RE.match(parsed.domain):
                        norm = normalize_domain(parsed.domain)
                        unique_suffix_rules.add(norm)
                        if parsed.is_important:
                            important_domains.add(norm)
                        if parsed.is_wildcard:
                            wildcard_source_doms.add(norm)
                    format_stats[parsed.source_format] = format_stats.get(parsed.source_format, 0) + 1
                elif parsed.action == "EXACT":
                    if is_valid_dns_domain(parsed.domain):
                        norm = normalize_domain(parsed.domain)
                        unique_exact_rules.add(norm)
                        if parsed.is_important:
                            important_domains.add(norm)
                    format_stats[parsed.source_format] = format_stats.get(parsed.source_format, 0) + 1
                else:  # SKIP
                    skip_stats[parsed.skip_reason] = skip_stats.get(parsed.skip_reason, 0) + 1
        except Exception as exc:
            log(f"处理 {url} 时出错: {exc}")

    # ── 过滤阶段 + 白名单抑制 + 冲突索引 + 父域剪枝 ──────────────────────────
    valid_suffix_rules = set()
    valid_exact_rules = set()
    valid_excluded_domains = set()
    valid_psl_rules = set()

    for d in unique_suffix_rules:
        if is_valid_dns_domain(d) and not IP_RE.match(d):
            if is_public_suffix(d, psl_set):
                valid_psl_rules.add(d)
            else:
                valid_suffix_rules.add(d)

    for d in unique_exact_rules:
        if is_valid_dns_domain(d):
            if is_public_suffix(d, psl_set):
                valid_psl_rules.add(d)
            else:
                valid_exact_rules.add(d)

    # 强化：PSL whitelist（普通+important）移除过滤限制（修复潜在误杀/漏杀）
    for d in excluded_domains:
        if is_valid_dns_domain(d):
            valid_excluded_domains.add(d)

    filtered_important_whitelist = set()
    for d in important_whitelist_domains:
        if is_valid_dns_domain(d):
            filtered_important_whitelist.add(d)
    important_whitelist_domains = filtered_important_whitelist

    valid_exact_rules |= valid_psl_rules

    # ── 核心逻辑：五级优先级判定矩阵与最近邻原则 ────────────────────────────
    get_effective_status = make_effective_status_fn(
        important_whitelist_domains, important_domains,
        valid_excluded_domains, valid_exact_rules, valid_suffix_rules
    )

    log("正在执行自动降级机制与冲突检测...")
    suffix_conflict_exact_domains = set()
    all_whitelists = set()
    all_whitelists |= important_whitelist_domains
    all_whitelists |= valid_excluded_domains

    for w in all_whitelists:
        if get_effective_status(w).startswith("WHITELIST"):
            for parent in get_parent_domains(w):
                if parent in valid_suffix_rules:
                    suffix_conflict_exact_domains.add(parent)

    log(f"冲突检测完成，共有 {len(suffix_conflict_exact_domains)} 个 SUFFIX 规则需降级为 DOMAIN")

    raw_suffix_set = set()
    raw_exact_set = set()

    all_blacklists = set()
    all_blacklists |= valid_suffix_rules
    all_blacklists |= valid_exact_rules
    all_blacklists |= important_domains

    for d in all_blacklists:
        if not get_effective_status(d).startswith("BLACKLIST"):
            continue
        is_suffix = False
        if d in valid_suffix_rules and d not in suffix_conflict_exact_domains:
            is_suffix = True
        if is_suffix:
            raw_suffix_set.add(d)
        else:
            raw_exact_set.add(d)

    # ── 三类域名分类与冗余剪枝 ────────────────────────────────────────────────
    log("正在构建三类域名集合与执行冗余剪枝...")
    class_suffix_blocks = set()
    for d in raw_suffix_set:
        covered = False
        for parent in get_parent_domains(d):
            if parent in raw_suffix_set:
                covered = True
                break
        if not covered:
            class_suffix_blocks.add(d)

    class_exact_blocks = set()
    for d in raw_exact_set:
        covered = False
        for parent in get_parent_domains(d):
            if parent in class_suffix_blocks:
                covered = True
                break
        if not covered:
            class_exact_blocks.add(d)

    class_whitelist = set()
    for w in all_whitelists:
        if get_effective_status(w).startswith("WHITELIST"):
            class_whitelist.add(w)

    log(f"三类集合构建完成：Whitelist {len(class_whitelist)} | "
        f"DOMAIN {len(class_exact_blocks)} | DOMAIN-SUFFIX {len(class_suffix_blocks)}")

    log("正在执行冲突父域子域精确补全（封堵降级导致的漏网之鱼）...")
    extra_exact_blocks = set()
    for black in all_blacklists:
        if black in class_whitelist:
            continue
        for parent in get_parent_domains(black):
            if parent in suffix_conflict_exact_domains:
                extra_exact_blocks.add(black)
                break

    class_exact_blocks |= extra_exact_blocks
    log(f"冲突补全完成：新增 {len(extra_exact_blocks)} 条精确规则（封堵漏杀）")

    # ── 输出 JSON 规则集 ─────────────────────────────────────────────────────
    rule_count = len(class_exact_blocks) + len(class_suffix_blocks)
    generate_time = (datetime.now(timezone.utc) + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")

    json_object = {
        "version": 1,
        "rules": [
            {
                "domain_suffix": sorted(class_suffix_blocks),
                "domain": sorted(class_exact_blocks),
            }
        ],
    }

    with open(OUTPUT_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(json_object, f, indent=2, ensure_ascii=False)
        f.write("\n")

    # ── 控制台诊断输出 ────────────────────────────────────────────────────────
    log("")
    log("===== 生成完成 =====")
    log(f"生成时间: {generate_time}")
    log(f"总规则数: {rule_count} (DOMAIN: {len(class_exact_blocks)} | "
        f"DOMAIN-SUFFIX: {len(class_suffix_blocks)})")
    log(f"白名单放行: {len(class_whitelist)}")
    log(f"PSL Apex DOMAIN (黑): {len(valid_psl_rules)}")
    log("PSL Apex Whitelist (白) 已全支持")
    log(f"文件路径: {OUTPUT_JSON_PATH}")

    total_skipped = sum(skip_stats.values())
    log(f"Generated at {generate_time} | Total: {rule_count} | "
        f"DOMAIN: {len(class_exact_blocks)} | SUFFIX: {len(class_suffix_blocks)} | "
        f"Whitelist: {len(class_whitelist)} | Skipped: {total_skipped}")


if __name__ == "__main__":
    main()
