#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""proxifly free-proxy-list 全量健康探测。

流程
----
1. 解析最新数据版本（GitHub API 取 commit SHA，避免 CDN 缓存旧副本）
2. 下载 data.json，按 (ip, port, protocol) 去重
3. 可选抽样（--sample N，固定 seed 可复现）
4. 批量查询入口 IP 归属（ip-api batch）
5. 并发探测：经前置建立隧道 -> 协议握手 -> 访问回显服务取出口
6. 汇总统计并导出 JSON（含运行元数据、逐条明细、分国家/协议聚合）

用法
----
  # 全量、经前置、用自建回显
  python probe.py --upstream 192.168.1.231:7890 \
      --echo whatsmyip.125478.xyz --output-dir data

  # 抽样 1000 且不走前置
  python probe.py --sample 1000 --output-dir out
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import random
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional, Sequence, Tuple

LOG = logging.getLogger('proxy-health')

LIST_REPO = 'proxifly/free-proxy-list'
LIST_PATH = 'proxies/all/data.json'
GITHUB_API = f'https://api.github.com/repos/{LIST_REPO}'
RAW_URL = f'https://raw.githubusercontent.com/{LIST_REPO}/{{sha}}/{LIST_PATH}'

GEO_HOST = 'ip-api.com'
GEO_FIELDS = 'query,countryCode,regionName,city,isp,as,hosting,proxy'

PROTOCOLS = ('http', 'https', 'socks4', 'socks5')


# ----------------------------------------------------------------------------
# 工具
# ----------------------------------------------------------------------------

def utcnow() -> str:
    """毫秒精度 UTC 时间戳，统一格式便于排序。"""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def utcstamp() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_json(path: str, obj) -> None:
    """原子写出 JSON（先写临时文件再 rename）。"""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=1)
        f.write('\n')
    os.replace(tmp, path)


def parse_host_port(s: str, default_port: int = 80) -> Tuple[str, int]:
    s = s.strip()
    if s.startswith('['):
        end = s.index(']')
        host, rest = s[1:end], s[end + 1:]
        if rest.startswith(':') and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if s.count(':') == 1:
        host, ps = s.rsplit(':', 1)
        if ps.isdigit():
            return host, int(ps)
    return s, default_port


def _http_get(url: str, timeout: float = 30.0, headers: Optional[dict] = None,
              retries: int = 3) -> bytes:
    req = urllib.request.Request(url, headers=headers or {
        'User-Agent': 'proxy-health/1.0',
        'Accept': 'application/vnd.github+json',
    })
    last: Optional[Exception] = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as e:                      # noqa: BLE001 - 网络异常统一重试
            last = e
            LOG.warning('GET %s 失败（第 %d/%d 次）: %s', url, attempt, retries, e)
            if attempt < retries:
                time.sleep(min(2 ** attempt, 8))
    raise RuntimeError(f'GET {url} 失败: {last}')


# ----------------------------------------------------------------------------
# 1. 获取最新列表
# ----------------------------------------------------------------------------

def resolve_latest_sha(timeout: float = 30.0) -> Tuple[str, str]:
    """返回 (sha, 该文件的提交时间)。用 commit 列表而非 branch，避免 CDN 缓存。"""
    url = f'{GITHUB_API}/commits?path={LIST_PATH}&per_page=1'
    raw = _http_get(url, timeout=timeout)
    commits = json.loads(raw)
    if not commits:
        raise RuntimeError('GitHub 未返回 commit 信息')
    c = commits[0]
    return c['sha'], c['commit']['committer']['date']


def fetch_list(sha: Optional[str] = None, timeout: float = 90.0) -> Tuple[bytes, dict]:
    """下载列表，返回 (原始字节, 版本信息)。"""
    meta: dict = {'fetched_at': utcnow()}
    if sha is None:
        sha, committed = resolve_latest_sha()
    else:
        committed = None
    url = RAW_URL.format(sha=sha)
    raw = _http_get(url, timeout=timeout)
    meta.update({'sha': sha, 'committed_at': committed, 'url': url,
                 'bytes': len(raw), 'sha256': sha256_of(raw)})
    LOG.info('列表版本 %s（提交于 %s），%d 字节', sha[:12], committed, len(raw))
    return raw, meta


def load_entries(raw: bytes) -> Tuple[List[dict], dict]:
    """解析并去重，返回 (entries, 统计)。"""
    data = json.loads(raw)
    seen = set()
    entries: List[dict] = []
    dup = 0
    for e in data:
        ip = str(e.get('ip') or '').strip()
        port = e.get('port')
        proto = str(e.get('protocol') or '').strip().lower()
        if not ip or port is None:
            continue
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if proto not in PROTOCOLS:
            continue
        key = (ip, port, proto)
        if key in seen:
            dup += 1
            continue
        seen.add(key)
        entries.append({
            'ip': ip, 'port': port, 'protocol': proto,
            'declared_cc': (e.get('geolocation') or {}).get('country'),
            'declared_city': (e.get('geolocation') or {}).get('city'),
            'anonymity': e.get('anonymity'),
            'score': e.get('score'),
        })
    stats = {
        'raw_entries': len(data),
        'unique_entries': len(entries),
        'duplicates_removed': dup,
        'unique_ips': len({e['ip'] for e in entries}),
        'by_protocol': dict(Counter(e['protocol'] for e in entries)),
        'by_declared_country': dict(Counter(e['declared_cc'] for e in entries).most_common()),
    }
    LOG.info('解析 %d 条（去重后 %d，移除重复 %d）',
             stats['raw_entries'], stats['unique_entries'], dup)
    return entries, stats


# ----------------------------------------------------------------------------
# 2. 入口归属
# ----------------------------------------------------------------------------

def lookup_entry_geo(ips: Sequence[str], batch_size: int = 100,
                     timeout: float = 40.0, per_minute: int = 40,
                     cache_path: Optional[str] = None) -> dict:
    """ip-api 批量查询，返回 {ip: geo}。

    免费额度 45 请求/分钟：按 per_minute 限速；遇到 429 指数退避并降低速率。
    结果可缓存到 cache_path，重复运行时直接复用，避免反复消耗额度。
    """
    out: dict = {}
    if cache_path and os.path.exists(cache_path):
        try:
            with open(cache_path, encoding='utf-8') as f:
                cached = json.load(f)
            out.update({k: v for k, v in cached.items() if v})
            LOG.info('入口归属缓存命中 %d 条', len(out))
        except (json.JSONDecodeError, OSError) as e:
            LOG.warning('缓存读取失败，忽略: %s', e)

    pending = [ip for ip in dict.fromkeys(ips) if ip not in out]
    if not pending:
        LOG.info('入口归属全部命中缓存 %d/%d', len(out), len(ips))
        return out

    interval = 60.0 / per_minute if per_minute > 0 else 0.0
    last_call = 0.0
    for start in range(0, len(pending), batch_size):
        chunk = pending[start:start + batch_size]
        if interval:
            wait = interval - (time.monotonic() - last_call)
            if wait > 0:
                time.sleep(wait)
        last_call = time.monotonic()

        payload = json.dumps([
            {'query': ip, 'fields': GEO_FIELDS} for ip in chunk
        ]).encode()
        req = urllib.request.Request(
            f'http://{GEO_HOST}/batch', data=payload,
            headers={'Content-Type': 'application/json'})

        rows = None
        for attempt in range(1, 6):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    rows = json.load(r)
                break
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    interval = min(interval * 2, 5.0) if interval else 1.5
                    backoff = min(2 ** attempt, 30)
                    LOG.warning('ip-api 限流，退避 %ds 后重试（%d/5）', backoff, attempt)
                    time.sleep(backoff)
                else:
                    LOG.warning('入口归属批次 %d 失败（%d/5）: %s',
                                start // batch_size, attempt, e)
                    time.sleep(2 * attempt)
            except Exception as e:                  # noqa: BLE001
                LOG.warning('入口归属批次 %d 失败（%d/5）: %s',
                            start // batch_size, attempt, e)
                time.sleep(2 * attempt)

        if rows:
            for row in rows:
                ip = row.get('query')
                if ip and row.get('countryCode'):
                    out[ip] = row

        done = min(start + batch_size, len(pending))
        if done % 1000 == 0 or done == len(pending):
            LOG.info('入口归属 %d/%d', done, len(pending))
            if cache_path:
                _write_json(cache_path, out)

    if cache_path:
        _write_json(cache_path, out)
    LOG.info('入口归属完成 %d/%d', len(out), len(ips))
    return out


# ----------------------------------------------------------------------------
# 3. 探测
# ----------------------------------------------------------------------------

@dataclass
class ProbeConfig:
    upstream: Optional[Tuple[str, int]] = None
    echo_host: str = 'whatsmyip.125478.xyz'
    echo_port: int = 80
    echo_path: str = '/'
    connect_timeout: float = 7.0
    io_timeout: float = 15.0
    concurrency: int = 120
    proxy_auth: Optional[Tuple[str, str]] = None

    @property
    def upstream_label(self) -> str:
        return f'{self.upstream[0]}:{self.upstream[1]}' if self.upstream else 'direct'


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError('closed')
        buf += chunk
    return buf


def _open_tunnel(cfg: ProbeConfig, ip: str, port: int) -> socket.socket:
    """建立到 ip:port 的连接；配置了前置则先经前置 CONNECT。"""
    if not cfg.upstream:
        s = socket.create_connection((ip, port), timeout=cfg.connect_timeout)
        s.settimeout(cfg.io_timeout)
        return s

    s = socket.create_connection(cfg.upstream, timeout=cfg.connect_timeout)
    s.settimeout(cfg.io_timeout)
    headers = f'CONNECT {ip}:{port} HTTP/1.1\r\nHost: {ip}:{port}\r\n'
    if cfg.proxy_auth:
        import base64
        token = base64.b64encode(
            f'{cfg.proxy_auth[0]}:{cfg.proxy_auth[1]}'.encode()).decode()
        headers += f'Proxy-Authorization: Basic {token}\r\n'
    s.sendall((headers + '\r\n').encode())

    data = b''
    while b'\r\n\r\n' not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 16384:
            break
    m = re.match(rb'HTTP/\d\.\d\s+(\d+)', data)
    if not m:
        s.close()
        raise RuntimeError('upstream-no-status')
    code = int(m.group(1))
    if code != 200:
        s.close()
        raise RuntimeError(f'upstream-{code}')
    return s


def _socks5_handshake(sock: socket.socket, host: str, port: int) -> None:
    sock.sendall(b'\x05\x01\x00')
    ver, method = _recv_exact(sock, 2)
    if ver != 5:
        raise RuntimeError(f'socks5-ver{ver}')
    if method == 0x02:
        raise RuntimeError('socks5-auth-required')
    if method != 0x00:
        raise RuntimeError(f'socks5-method{method:#x}')
    hb = host.encode()
    sock.sendall(b'\x05\x01\x00\x03' + bytes([len(hb)]) + hb
                 + struct.pack('>H', port))
    head = _recv_exact(sock, 4)
    if head[1] != 0:
        raise RuntimeError(f'socks5-rep{head[1]}')
    atyp = head[3]
    if atyp == 1:
        _recv_exact(sock, 6)
    elif atyp == 3:
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
    elif atyp == 4:
        _recv_exact(sock, 18)


def _socks4_handshake(sock: socket.socket, host: str, port: int) -> None:
    sock.sendall(b'\x04\x01' + struct.pack('>H', port)
                 + b'\x00\x00\x00\x01\x00' + host.encode() + b'\x00')
    resp = _recv_exact(sock, 8)
    if resp[1] != 0x5A:
        raise RuntimeError(f'socks4-rep{resp[1]}')


def _http_connect_handshake(sock: socket.socket, host: str, port: int) -> None:
    sock.sendall(f'CONNECT {host}:{port} HTTP/1.1\r\n'
                 f'Host: {host}:{port}\r\n\r\n'.encode())
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > 16384:
            break
    m = re.match(rb'HTTP/\d\.\d\s+(\d+)', data)
    if not m:
        raise RuntimeError('handshake-no-status')
    code = int(m.group(1))
    if code != 200:
        raise RuntimeError(f'handshake-{code}')


def _read_http_response(sock: socket.socket, limit: int = 262144) -> Tuple[Optional[int], bytes]:
    data = b''
    while b'\r\n\r\n' not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            break
    head, _, body = data.partition(b'\r\n\r\n')
    m = re.match(rb'HTTP/\d\.\d\s+(\d+)', head)
    status = int(m.group(1)) if m else None

    clen = re.search(rb'content-length:\s*(\d+)', head, re.I)
    if clen:
        need = int(clen.group(1))
        while len(body) < need:
            chunk = sock.recv(min(8192, need - len(body)))
            if not chunk:
                break
            body += chunk
    elif b'chunked' in head.lower():
        while True:
            line = b''
            while b'\r\n' not in line:
                c = sock.recv(1)
                if not c:
                    return status, body
                line += c
            try:
                size = int(line.split(b';')[0].strip(), 16)
            except ValueError:
                break
            if size == 0:
                break
            body += _recv_exact(sock, size)
            _recv_exact(sock, 2)
    else:
        while True:
            try:
                chunk = sock.recv(8192)
            except socket.timeout:
                break
            if not chunk:
                break
            body += chunk
            if len(body) > limit:
                break
    return status, body


def probe_one(entry: dict, cfg: ProbeConfig) -> dict:
    """探测单个节点，返回详细记录（含时间戳、延迟、出口）。"""
    rec = {
        'ip': entry['ip'],
        'port': entry['port'],
        'protocol': entry['protocol'],
        'declared_cc': entry.get('declared_cc'),
        'declared_city': entry.get('declared_city'),
        'anonymity': entry.get('anonymity'),
        't_start': utcnow(),
        'ok': False,
        'stage': 'connect',
        'error': None,
    }
    t0 = time.monotonic()
    sock: Optional[socket.socket] = None
    try:
        sock = _open_tunnel(cfg, entry['ip'], entry['port'])

        rec['stage'] = 'handshake'
        if entry['protocol'] == 'https':
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=entry['ip'])
            sock.settimeout(cfg.io_timeout)

        if entry['protocol'] == 'socks5':
            _socks5_handshake(sock, cfg.echo_host, cfg.echo_port)
        elif entry['protocol'] == 'socks4':
            _socks4_handshake(sock, cfg.echo_host, cfg.echo_port)
        else:
            _http_connect_handshake(sock, cfg.echo_host, cfg.echo_port)

        rec['stage'] = 'request'
        sock.sendall(f'GET {cfg.echo_path} HTTP/1.1\r\n'
                     f'Host: {cfg.echo_host}\r\n'
                     f'User-Agent: Mozilla/5.0 (proxy-health)\r\n'
                     f'Connection: close\r\n\r\n'.encode())
        status, body = _read_http_response(sock)
        rec['http_status'] = status
        if status != 200:
            raise RuntimeError(f'http-{status}')

        try:
            payload = json.loads(body.decode('utf-8', 'replace'))
        except json.JSONDecodeError as e:
            raise RuntimeError('echo-not-json') from e
        if not payload.get('ip'):
            raise RuntimeError('echo-no-ip')

        rec.update({
            'ok': True,
            'stage': 'done',
            'latency_ms': round((time.monotonic() - t0) * 1000),
            'exit_ip': payload.get('ip'),
            'exit_cc': payload.get('country'),
            'exit_region': payload.get('region'),
            'exit_city': payload.get('city'),
            'exit_isp': payload.get('isp'),
            'exit_colo': payload.get('colo'),
            'echo_extra': {
                'timezone': payload.get('timezone'),
                'tlsVersion': payload.get('tlsVersion'),
                'httpProtocol': payload.get('httpProtocol'),
            },
        })
    except Exception as e:                          # noqa: BLE001 - 逐条隔离
        rec['error'] = f'{type(e).__name__}: {str(e)[:120]}'
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
        rec['t_end'] = utcnow()
        rec['dur_ms'] = round((time.monotonic() - t0) * 1000)
    return rec


def probe_all(entries: Sequence[dict], cfg: ProbeConfig,
              progress_every: int = 500) -> List[dict]:
    results: List[dict] = []
    t0 = time.monotonic()
    LOG.info('开始探测 %d 个节点（前置=%s，回显=%s，并发=%d）',
             len(entries), cfg.upstream_label, cfg.echo_host, cfg.concurrency)
    with ThreadPoolExecutor(cfg.concurrency) as ex:
        futs = [ex.submit(probe_one, e, cfg) for e in entries]
        for i, fut in enumerate(as_completed(futs), 1):
            results.append(fut.result())
            if i % progress_every == 0:
                ok = sum(1 for r in results if r['ok'])
                LOG.info('进度 %d/%d 可用=%d 用时=%.0fs',
                         i, len(entries), ok, time.monotonic() - t0)
    results.sort(key=lambda r: (not r['ok'], r.get('latency_ms') or 9e9))
    LOG.info('探测完成 %d/%d 可用，用时 %.0fs',
             sum(1 for r in results if r['ok']), len(results),
             time.monotonic() - t0)
    return results


# ----------------------------------------------------------------------------
# 4. 汇总
# ----------------------------------------------------------------------------

def _pct(num: int, den: int) -> float:
    return round(num / den * 100, 2) if den else 0.0


def _percentile(values: List[float], q: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(int(len(ordered) * q), len(ordered) - 1)
    return ordered[idx]


def summarize(results: Sequence[dict], entry_geo: dict,
              list_stats: dict, meta: dict) -> dict:
    ok = [r for r in results if r['ok']]
    bad = [r for r in results if not r['ok']]
    total = len(results)

    def geo_of(ip: str) -> dict:
        return entry_geo.get(ip) or {}

    # 协议维度
    by_proto = {}
    for proto in PROTOCOLS:
        t = [r for r in results if r['protocol'] == proto]
        o = [r for r in t if r['ok']]
        by_proto[proto] = {
            'total': len(t), 'ok': len(o), 'ok_pct': _pct(len(o), len(t)),
        }

    # 国家维度（入口真实归属 / 出口）
    entry_country_total = Counter()
    entry_country_ok = Counter()
    for r in results:
        cc = geo_of(r['ip']).get('countryCode') or r.get('declared_cc') or 'UNKNOWN'
        entry_country_total[cc] += 1
        if r['ok']:
            entry_country_ok[cc] += 1
    exit_country_ok = Counter(r.get('exit_cc') for r in ok)

    by_entry_country = {
        cc: {
            'total': n,
            'ok': entry_country_ok.get(cc, 0),
            'ok_pct': _pct(entry_country_ok.get(cc, 0), n),
        }
        for cc, n in entry_country_total.most_common()
    }

    # 出口聚合：同一出口被多少入口共用（识别上游聚合）
    exit_usage: Counter = Counter(r.get('exit_ip') for r in ok)
    shared_exits = [
        {'exit_ip': ip, 'entries': n,
         'exit_cc': next((r.get('exit_cc') for r in ok if r.get('exit_ip') == ip), None),
         'exit_city': next((r.get('exit_city') for r in ok if r.get('exit_ip') == ip), None),
         'entry_ips': sorted({r['ip'] for r in ok if r.get('exit_ip') == ip})[:20]}
        for ip, n in exit_usage.most_common(50) if n > 1
    ]

    # 异常标记
    tor_like = [r for r in ok
                if r.get('exit_cc') == 'T1' or 'Tor' in (r.get('exit_isp') or '')]
    ipv6_exit = [r for r in ok if ':' in str(r.get('exit_ip'))]
    exit_ne_entry = [r for r in ok if r.get('exit_ip') != r['ip']]
    exit_country_ne_entry = [
        r for r in ok
        if r.get('exit_cc') and geo_of(r['ip']).get('countryCode')
        and r['exit_cc'] != geo_of(r['ip'])['countryCode']
    ]
    exit_ne_declared = [r for r in ok
                        if r.get('exit_cc') and r['exit_cc'] != r.get('declared_cc')]

    # 失败原因
    failures = Counter()
    for r in bad:
        err = r.get('error') or 'unknown'
        kind, _, detail = err.partition(': ')
        key = f'{kind}:{detail[:32]}' if detail else kind
        failures[key] += 1

    latencies = [r['latency_ms'] for r in ok if r.get('latency_ms')]

    # 入口网络类型
    hosting_known = [r for r in results if geo_of(r['ip']).get('hosting') is not None]
    hosting_ok = [r for r in ok if geo_of(r['ip']).get('hosting')]

    return {
        'meta': meta,
        'list': list_stats,
        'totals': {
            'probed': total,
            'ok': len(ok),
            'failed': len(bad),
            'ok_pct': _pct(len(ok), total),
        },
        'by_protocol': by_proto,
        'by_entry_country': by_entry_country,
        'exit_country': dict(exit_country_ok.most_common()),
        'latency_ms': {
            'min': min(latencies) if latencies else None,
            'p50': _percentile(latencies, 0.50),
            'p90': _percentile(latencies, 0.90),
            'p99': _percentile(latencies, 0.99),
            'max': max(latencies) if latencies else None,
            'buckets': {
                'lt_1s': sum(1 for x in latencies if x < 1000),
                '1s_2s': sum(1 for x in latencies if 1000 <= x < 2000),
                '2s_5s': sum(1 for x in latencies if 2000 <= x < 5000),
                '5s_10s': sum(1 for x in latencies if 5000 <= x < 10000),
                'gte_10s': sum(1 for x in latencies if x >= 10000),
            },
        },
        'anomalies': {
            'tor_exit': {
                'count': len(tor_like),
                'nodes': [{'ip': r['ip'], 'port': r['port'],
                           'protocol': r['protocol'], 'exit_ip': r.get('exit_ip'),
                           'exit_isp': r.get('exit_isp')} for r in tor_like],
            },
            'ipv6_exit': {
                'count': len(ipv6_exit),
                'nodes': [{'ip': r['ip'], 'port': r['port'],
                           'exit_ip': r.get('exit_ip'),
                           'exit_cc': r.get('exit_cc')} for r in ipv6_exit],
            },
            'exit_ne_entry': {'count': len(exit_ne_entry)},
            'exit_country_ne_entry': {
                'count': len(exit_country_ne_entry),
                'nodes': [{'ip': r['ip'], 'port': r['port'],
                           'entry_cc': geo_of(r['ip']).get('countryCode'),
                           'exit_cc': r.get('exit_cc')}
                          for r in exit_country_ne_entry[:200]],
            },
            'exit_ne_declared': {'count': len(exit_ne_declared)},
            'shared_exits': shared_exits,
        },
        'entry_network': {
            'hosting_known': len(hosting_known),
            'hosting_ok': len(hosting_ok),
            'residential_ok': len(ok) - len(hosting_ok),
            'hosting_total': sum(1 for r in hosting_known
                                 if geo_of(r['ip']).get('hosting')),
        },
        'failures': dict(failures.most_common(40)),
    }


# ----------------------------------------------------------------------------
# 5. 导出
# ----------------------------------------------------------------------------



def export(results: Sequence[dict], entry_geo: dict, summary: dict,
           output_dir: str, run_id: str, split: int = 3000) -> List[str]:
    """写出 latest.json / history/<run>.json / 分片明细 / 可用节点清单。"""
    written: List[str] = []

    def out(*parts: str) -> str:
        return os.path.join(output_dir, *parts)

    # 分片明细，避免单文件过大
    chunks = [results[i:i + split] for i in range(0, len(results), split)]
    chunk_names = []
    for idx, chunk in enumerate(chunks, 1):
        name = out('history', f'{run_id}-details-{idx:02d}.json')
        _write_json(name, {
            'run_id': run_id,
            'part': idx,
            'parts': len(chunks),
            'records': len(chunk),
            'results': chunk,
        })
        written.append(name)
        chunk_names.append(os.path.relpath(name, output_dir))

    ok = [r for r in results if r['ok']]

    # 可用节点清单（ip:port#CC，可直接喂给 proxyip.py）
    txt = out('latest-ok.txt')
    os.makedirs(os.path.dirname(txt) or '.', exist_ok=True)
    with open(txt, 'w', encoding='utf-8') as f:
        for r in ok:
            cc = r.get('exit_cc') or r.get('declared_cc') or ''
            f.write(f"{r['ip']}:{r['port']}" + (f'#{cc}' if cc else '') + '\n')
    written.append(txt)

    # 最新汇总（含摘要 + 分片索引，明细在 history）
    latest = {
        'run_id': run_id,
        'generated_at': utcnow(),
        'summary': summary,
        'detail_files': chunk_names,
        'ok_entries': len(ok),
        'usable_nodes': [
            {'ip': r['ip'], 'port': r['port'], 'protocol': r['protocol'],
             'latency_ms': r.get('latency_ms'), 'exit_ip': r.get('exit_ip'),
             'exit_cc': r.get('exit_cc'), 'exit_city': r.get('exit_city'),
             'exit_isp': r.get('exit_isp')}
            for r in ok
        ],
    }
    latest_path = out('latest.json')
    _write_json(latest_path, latest)
    written.append(latest_path)

    # 历史快照（仅汇总，体积小，便于长期留存对比）
    hist_path = out('history', f'{run_id}.json')
    _write_json(hist_path, {
        'run_id': run_id,
        'generated_at': utcnow(),
        'summary': summary,
        'detail_files': chunk_names,
    })
    written.append(hist_path)

    # 索引：记录所有运行，方便趋势分析
    index_path = out('index.json')
    index = {'updated_at': utcnow(), 'runs': []}
    if os.path.exists(index_path):
        try:
            with open(index_path, encoding='utf-8') as f:
                index = json.load(f)
        except (json.JSONDecodeError, OSError):
            index = {'updated_at': utcnow(), 'runs': []}
    index.setdefault('runs', [])
    index['runs'] = [r for r in index['runs'] if r.get('run_id') != run_id]
    index['runs'].append({
        'run_id': run_id,
        'generated_at': utcnow(),
        'list_sha': summary['meta'].get('list_sha'),
        'list_committed_at': summary['meta'].get('list_committed_at'),
        'probed': summary['totals']['probed'],
        'ok': summary['totals']['ok'],
        'ok_pct': summary['totals']['ok_pct'],
        'upstream': summary['meta'].get('upstream'),
        'echo': summary['meta'].get('echo_host'),
        'summary_file': os.path.relpath(hist_path, output_dir),
        'detail_files': chunk_names,
    })
    index['runs'].sort(key=lambda r: r.get('generated_at') or '')
    _write_json(index_path, index)
    written.append(index_path)
    return written


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description='proxifly 代理列表健康探测（入口/出口/延迟/异常）')
    ap.add_argument('--sample', type=int, default=0,
                    help='随机抽样条数，0=全量（默认）')
    ap.add_argument('--seed', type=int, default=20260101,
                    help='抽样随机种子，保证可复现')
    ap.add_argument('--sha', default=None,
                    help='锁定列表 commit SHA；默认取最新')
    ap.add_argument('--list-file', default=None,
                    help='改用本地 data.json（跳过下载）')
    ap.add_argument('--upstream', default=None,
                    help='前置代理 host:port（HTTP CONNECT）')
    ap.add_argument('--upstream-auth', default=None,
                    help='前置认证 user:pass')
    ap.add_argument('--echo', default='whatsmyip.125478.xyz',
                    help='回显服务域名（返回 JSON 且含 ip 字段）')
    ap.add_argument('--echo-port', type=int, default=80)
    ap.add_argument('--echo-path', default='/')
    ap.add_argument('--concurrency', type=int, default=120)
    ap.add_argument('--connect-timeout', type=float, default=7.0)
    ap.add_argument('--io-timeout', type=float, default=15.0)
    ap.add_argument('--output-dir', default='data')
    ap.add_argument('--no-entry-geo', action='store_true',
                    help='跳过入口 IP 归属查询')
    ap.add_argument('--geo-per-minute', type=int, default=40,
                    help='ip-api 每分钟请求上限（免费额度 45）')
    ap.add_argument('--geo-cache', default=None,
                    help='入口归属缓存文件路径（默认 <output-dir>/entry-geo-cache.json）')
    ap.add_argument('--log-level', default='INFO')
    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format='%(asctime)s [%(levelname)s] %(message)s')

    started = utcnow()
    run_id = utcstamp()
    LOG.info('运行 %s 开始于 %s', run_id, started)

    # 1) 列表
    if args.list_file:
        with open(args.list_file, 'rb') as f:
            raw = f.read()
        meta = {'fetched_at': utcnow(), 'sha': None, 'committed_at': None,
                'url': args.list_file, 'bytes': len(raw),
                'sha256': sha256_of(raw)}
    else:
        raw, meta = fetch_list(args.sha)
    entries, list_stats = load_entries(raw)

    # 2) 抽样
    if args.sample and 0 < args.sample < len(entries):
        rng = random.Random(args.seed)
        entries = rng.sample(entries, args.sample)
        LOG.info('抽样 %d 条（seed=%d）', len(entries), args.seed)
    meta['sampled'] = args.sample if args.sample else 0
    meta['seed'] = args.seed if args.sample else None

    # 3) 入口归属
    entry_geo: dict = {}
    if not args.no_entry_geo:
        cache = args.geo_cache or os.path.join(args.output_dir, 'entry-geo-cache.json')
        entry_geo = lookup_entry_geo(
            sorted({e['ip'] for e in entries}),
            per_minute=args.geo_per_minute, cache_path=cache)
    meta['entry_geo_known'] = len(entry_geo)

    # 4) 探测
    cfg = ProbeConfig(
        upstream=parse_host_port(args.upstream, 7890) if args.upstream else None,
        echo_host=args.echo,
        echo_port=args.echo_port,
        echo_path=args.echo_path,
        connect_timeout=args.connect_timeout,
        io_timeout=args.io_timeout,
        concurrency=args.concurrency,
        proxy_auth=(tuple(args.upstream_auth.split(':', 1))
                    if args.upstream_auth else None),
    )
    meta.update({
        'run_id': run_id,
        'started_at': started,
        'finished_at': None,
        'upstream': cfg.upstream_label,
        'echo_host': cfg.echo_host,
        'echo_port': cfg.echo_port,
        'concurrency': cfg.concurrency,
        'list_sha': meta.get('sha'),
        'list_committed_at': meta.get('committed_at'),
    })
    results = probe_all(entries, cfg)

    # 5) 汇总 + 导出
    meta['finished_at'] = utcnow()
    summary = summarize(results, entry_geo, list_stats, meta)
    summary['meta'] = meta
    files = export(results, entry_geo, summary, args.output_dir, run_id)

    LOG.info('完成：可用 %d/%d（%.2f%%）',
             summary['totals']['ok'], summary['totals']['probed'],
             summary['totals']['ok_pct'])
    for path in files:
        LOG.info('  写入 %s', path)
    return 0


if __name__ == '__main__':
    sys.exit(main())
