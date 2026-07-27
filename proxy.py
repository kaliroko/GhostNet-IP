#!/usr/bin/env python3
"""
GhostNet 军事级IP隐匿框架 v1.0
功能：
  - 多级代理链自动配置（Proxychains）
  - 操作系统防火墙防泄露（iptables规则）
  - 高匿代理池（国家过滤、评分淘汰）
  - 全浏览器指纹伪装（curl_cffi）
  - 请求混淆、随机延迟
  - 浏览器 WebRTC 禁用模块
  - DNS/IPv6 安全建议

用法：
  1. 以 root 执行本脚本，生成防火墙规则并部署代理链。
  2. 然后通过 proxychains 运行任何工具（如 proxychains python3 ghostnet.py）。
  3. 对于浏览器，使用 proxychains firefox 并注入 WebRTC 禁用脚本。

⚠️ 警告：本工具仅限获得明确书面授权的红蓝对抗、安全研究。非法使用将承担全部法律责任。
"""

import requests
import threading
import time
import random
import queue
import json
import os
import sys
from typing import Optional, List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from curl_cffi import requests as curl_requests

# ================= 配置参数 =================
PROXY_FILE = "proxies.txt"                # 出口代理列表，格式：socks5://1.2.3.4:1080#US
CHAIN_PROXY_FILE = "chain_proxies.txt"    # 跳板代理列表，格式同上
COUNTRY_PROXY_APIS = {                    # 在线代理API（按国家）
    "US": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=500&country=US&ssl=all&anonymity=elite",
    "DE": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=500&country=DE&ssl=all&anonymity=elite",
}
DEFAULT_COUNTRY = "US"                   # 默认出口国家
VALIDATE_TIMEOUT = 5
REFRESH_INTERVAL = 300
MAX_WORKERS = 20
REQUEST_DELAY_BASE = 0.3

# 浏览器指纹库
ALL_IMPERSONATES = [
    "chrome99", "chrome100", "chrome101", "chrome104", "chrome107", "chrome110",
    "chrome116", "chrome119", "chrome120", "chrome123", "chrome124",
    "firefox102", "firefox110", "firefox117", "firefox120", "firefox124",
    "edge99", "edge101", "safari15_3", "safari15_5", "safari17_0",
    "opera91", "opera90",
]
UA_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# ================= 系统防泄漏模块 =================
class SystemHardening:
    """提供系统级防泄露规则（iptables/DNS/IPv6）"""
    @staticmethod
    def print_iptables_rules(proxy_ports=(1080, 9050), vpn_interface="tun0"):
        rules = [
            "iptables -F OUTPUT",
            "iptables -A OUTPUT -o lo -j ACCEPT",
            f"iptables -A OUTPUT -o {vpn_interface} -j ACCEPT",
        ]
        for port in proxy_ports:
            rules.append(f"iptables -A OUTPUT -p tcp --dport {port} -j ACCEPT")
            rules.append(f"iptables -A OUTPUT -p udp --dport {port} -j ACCEPT")
        rules += [
            "iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT",
            "iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT",
            "iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT",
            "iptables -A OUTPUT -j DROP",
        ]
        print("[*] 请以 root 执行以下 iptables 规则，防止非代理流量泄露：")
        for rule in rules:
            print(f"    {rule}")
        print("[*] 恢复规则：iptables -P OUTPUT ACCEPT; iptables -F OUTPUT\n")

    @staticmethod
    def print_dns_ipv6_advice():
        print("[*] DNS防泄露建议：")
        print("    1. 安装 dnscrypt-proxy 并确保其上游走代理。")
        print("    2. 修改 /etc/resolv.conf 为 nameserver 127.0.0.1")
        print("[*] 禁用 IPv6：")
        print("    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        print("    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1\n")

# ================= 多级代理链配置 =================
class ProxyChainManager:
    """自动生成 Proxychains 配置文件，串联多级跳板"""
    @staticmethod
    def generate_proxychains_conf(chain_proxies: List[str], out_proxy: str, filename="proxychains.conf"):
        config = """# Proxychains 配置文件（GhostNet 自动生成）
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
"""
        for proxy in chain_proxies:
            parts = proxy.replace('://', ' ').split()
            if len(parts) >= 2:
                config += f"{parts[0]} {parts[1]}\n"
        parts = out_proxy.replace('://', ' ').split()
        if len(parts) >= 2:
            config += f"{parts[0]} {parts[1]}\n"
        with open(filename, 'w') as f:
            f.write(config)
        print(f"[+] Proxychains 配置已生成：{filename}")
        print(f"    使用方式：proxychains python3 {sys.argv[0]}\n")

# ================= 代理节点与池 =================
class ProxyNode:
    def __init__(self, url: str, country: str = "unknown", is_chain: bool = False):
        self.url = url
        self.country = country
        self.is_chain = is_chain
        self.success = 0
        self.fail = 0
        self.avg_latency = 1.0
        self.anonymous = True

    @property
    def weight(self) -> float:
        total = self.success + self.fail
        if total == 0:
            return 1.0
        return (self.success / total) * (1.0 / (self.avg_latency + 0.5)) * (1.5 if self.anonymous else 0.5)

class ProxyPool:
    def __init__(self, target_country: str = DEFAULT_COUNTRY):
        self.target_country = target_country
        self.out_proxies: Dict[str, ProxyNode] = {}
        self.chain_proxies: Dict[str, ProxyNode] = {}
        self.lock = threading.Lock()
        self.last_refresh = 0

    def _load_local(self, file_path: str, is_chain=False) -> Dict[str, ProxyNode]:
        nodes = {}
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    country = "unknown"
                    if '#' in line:
                        url_part, tag = line.split('#', 1)
                        country = tag.strip().upper()
                    else:
                        url_part = line
                    if '://' not in url_part:
                        url_part = 'http://' + url_part
                    nodes[url_part] = ProxyNode(url_part, country, is_chain)
        except FileNotFoundError:
            pass
        return nodes

    def _fetch_country_online(self) -> Dict[str, ProxyNode]:
        online = {}
        for country, api_url in COUNTRY_PROXY_APIS.items():
            if country != self.target_country:
                continue
            try:
                resp = requests.get(api_url, timeout=10)
                for line in resp.text.strip().split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if '://' not in line:
                            line = 'http://' + line
                        online[line] = ProxyNode(line, country, False)
            except:
                continue
        return online

    def validate(self, node: ProxyNode) -> Tuple[bool, float, bool]:
        proxies = {"http": node.url, "https": node.url}
        start = time.time()
        anonymous = True
        try:
            r = requests.get("https://httpbin.org/ip", proxies=proxies, timeout=VALIDATE_TIMEOUT)
            latency = time.time() - start
            if r.status_code != 200:
                return False, latency, False
            data = r.json()
            origin = data.get("origin", "")
            if "X-Forwarded-For" in r.headers or "Via" in r.headers:
                anonymous = False
            if ',' in origin:
                anonymous = False
            return True, latency, anonymous
        except:
            return False, 999, False

    def refresh(self):
        now = time.time()
        if now - self.last_refresh < REFRESH_INTERVAL:
            return
        local_out = self._load_local(PROXY_FILE, False)
        online_out = self._fetch_country_online()
        all_out = {}
        for url, node in {**local_out, **online_out}.items():
            if node.country == self.target_country or node.country == "unknown":
                all_out[url] = node
        chain_nodes = self._load_local(CHAIN_PROXY_FILE, True)

        valid_out, valid_chain = {}, {}
        q = queue.Queue()
        for n in all_out.values():
            q.put(('out', n))
        for n in chain_nodes.values():
            q.put(('chain', n))

        def worker():
            while not q.empty():
                typ, node = q.get()
                ok, lat, anon = self.validate(node)
                if ok:
                    node.success += 1
                    node.avg_latency = (node.avg_latency * 0.7) + (lat * 0.3)
                    node.anonymous = anon
                    if typ == 'out':
                        valid_out[node.url] = node
                    else:
                        valid_chain[node.url] = node
                else:
                    node.fail += 1
                q.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(min(MAX_WORKERS, len(all_out)+len(chain_nodes)))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with self.lock:
            self.out_proxies = valid_out
            self.chain_proxies = valid_chain
            self.last_refresh = time.time()
        print(f"[*] 代理池刷新完成，出口代理: {len(self.out_proxies)}，跳板代理: {len(self.chain_proxies)}")

    def get_best_pair(self) -> Tuple[Optional[str], Optional[str]]:
        self.refresh()
        with self.lock:
            out_sorted = sorted(self.out_proxies.values(), key=lambda x: x.weight, reverse=True)
            if not out_sorted:
                return None, None
            out_proxy = out_sorted[0].url
            chain_proxy = None
            if self.chain_proxies:
                chain_sorted = sorted(self.chain_proxies.values(), key=lambda x: x.weight, reverse=True)
                chain_proxy = chain_sorted[0].url
            return chain_proxy, out_proxy

# ================= WebRTC 禁用 =================
class WebRTCBlocker:
    JS_DISABLE_WEBRTC = """
    (function() {
        var rtc = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
        if (rtc) {
            rtc.prototype.createDataChannel = function() { throw new Error('WebRTC disabled'); };
            rtc.prototype.createOffer = function() { throw new Error('WebRTC disabled'); };
            console.log('[Stealth] WebRTC disabled');
        }
    })();
    """
    @staticmethod
    def inject(driver):
        """适用于 Selenium/Playwright"""
        try:
            driver.execute_script(WebRTCBlocker.JS_DISABLE_WEBRTC)
            print("[+] WebRTC 禁用已注入浏览器")
        except Exception as e:
            print(f"[-] WebRTC 注入失败: {e}")

# ================= 隐蔽请求会话 =================
class StealthSession:
    def __init__(self, pool: ProxyPool):
        self.pool = pool
        self.ua = random.choice(UA_LIST)
        self.impersonate = random.choice(ALL_IMPERSONATES)
        self.client = curl_requests.Session(impersonate=self.impersonate)
        self.chain_proxy, self.out_proxy = pool.get_best_pair()
        self._build_headers()

    def _build_headers(self):
        ua = self.ua
        if "Chrome" in ua:
            version = ua.split("Chrome/")[1].split(" ")[0].split('.')[0]
            sec_ch_ua = f'"Chromium";v="{version}", "Not;A Brand";v="24", "Google Chrome";v="{version}"'
        else:
            sec_ch_ua = None
        self.headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": random.choice(["zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7", "zh-CN,zh;q=0.8,zh-TW;q=0.7,en;q=0.6"]),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        if sec_ch_ua:
            self.headers["Sec-CH-UA"] = sec_ch_ua
        self.headers["Sec-CH-UA-Mobile"] = "?0" if "Windows" in ua or "Macintosh" in ua else "?1"
        self.headers["Sec-CH-UA-Platform"] = random.choice(['"Windows"', '"macOS"', '"Linux"'])

    def request(self, method, url, **kwargs):
        time.sleep(REQUEST_DELAY_BASE + random.uniform(0, 0.5))
        if "?" in url:
            url += f"&_r={random.random()}"
        else:
            url += f"?_r={random.random()}"
        proxies = {}
        if self.out_proxy:
            proxies = {"http": self.out_proxy, "https": self.out_proxy}
        return self.client.request(method, url, headers=self.headers, proxies=proxies, timeout=15, **kwargs)

# ================= 主程序 =================
proxy_pool = ProxyPool(target_country=DEFAULT_COUNTRY)
system_hardening = SystemHardening()
chain_manager = ProxyChainManager()
webrtc_blocker = WebRTCBlocker()

def military_setup():
    """军事级环境初始化：打印所有配置与建议"""
    print(">>> GhostNet 军事级隐匿环境初始化 <<<\n")
    # 1. 系统防火墙
    system_hardening.print_iptables_rules()
    # 2. DNS/IPv6
    system_hardening.print_dns_ipv6_advice()
    # 3. 代理链配置
    chain, out = proxy_pool.get_best_pair()
    if chain and out:
        chain_manager.generate_proxychains_conf([chain], out)
    else:
        print("[!] 未找到足够的跳板/出口代理，请检查 proxies.txt 和 chain_proxies.txt")
    # 4. 浏览器 WebRTC
    print("[*] 浏览器 WebRTC 禁用：如使用 Selenium，调用 WebRTCBlocker.inject(driver) 即可。")
    print("[*] 纯HTTP模式下无需此步骤。")
    print("\n[*] 初始化完成。现在可以开始隐蔽请求。\n")

def stealth_get(url: str) -> Optional[requests.Response]:
    sess = StealthSession(proxy_pool)
    try:
        resp = sess.request("GET", url)
        return resp
    except Exception as e:
        print(f"[-] 请求失败: {e}")
        return None

if __name__ == "__main__":
    military_setup()
    print("=== 演示：使用代理池进行请求 ===")
    def test_task():
        resp = stealth_get("https://httpbin.org/ip")
        if resp and resp.status_code == 200:
            print(f"  [+] 出口IP: {resp.json()['origin']}")
        else:
            print("  [-] 请求失败")
    with ThreadPoolExecutor(max_workers=3) as executor:
        for _ in range(3):
            executor.submit(test_task)