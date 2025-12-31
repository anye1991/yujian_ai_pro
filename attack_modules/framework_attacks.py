# [file name]: attack_modules/framework_attacks.py

# !/usr/bin/env python3
"""
⚙️ 框架攻击模块 - 针对Laravel, Django, Spring, Express等框架的专项攻击
"""

import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class FrameworkAttacker:
    """框架攻击模块"""

    def __init__(self, config: Dict):
        self.config = config.get('modules', {}).get('framework_attacks', {})
        self.timeout = config.get('scan', {}).get('timeout', 15)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        self.framework_signatures = self.load_framework_signatures()

    def load_framework_signatures(self) -> Dict:
        """加载框架特征库"""
        return {
            'laravel': {
                'paths': ['/storage', '/bootstrap/cache', '/vendor'],
                'files': ['/.env', '/artisan', '/server.php'],
                'headers': ['X-Powered-By: Laravel'],
                'content_patterns': ['csrf-token', 'laravel', 'Laravel']
            },
            'django': {
                'paths': ['/static/admin', '/media', '/accounts'],
                'files': ['/manage.py', '/requirements.txt'],
                'headers': ['X-Frame-Options: DENY'],
                'content_patterns': ['csrfmiddlewaretoken', 'Django', 'django.js']
            },
            'spring': {
                'paths': ['/actuator', '/health', '/metrics'],
                'files': ['/application.properties', '/pom.xml'],
                'headers': ['X-Application-Context:'],
                'content_patterns': ['spring', 'Spring Boot']
            },
            'express': {
                'paths': ['/api', '/users', '/auth'],
                'files': ['/package.json', '/server.js'],
                'headers': ['X-Powered-By: Express'],
                'content_patterns': ['express', 'node.js', 'npm']
            },
            'ruby_on_rails': {
                'paths': ['/assets', '/javascripts', '/stylesheets'],
                'files': ['/Gemfile', '/config.ru'],
                'headers': ['X-Runtime:', 'X-Rack-Cache:'],
                'content_patterns': ['rails', 'Ruby on Rails']
            }
        }

    def detect_framework(self, target: str) -> Optional[str]:
        """检测目标使用的框架"""
        try:
            response = self.session.get(target, timeout=10, verify=False)
            content = response.text.lower()
            headers = str(response.headers).lower()

            for framework, signatures in self.framework_signatures.items():
                # 检查路径
                for path in signatures['paths']:
                    test_url = urljoin(target, path)
                    if self.check_url_exists(test_url):
                        return framework

                # 检查内容模式
                for pattern in signatures['content_patterns']:
                    if pattern.lower() in content:
                        return framework

                # 检查头部
                for header in signatures['headers']:
                    if header.lower() in headers:
                        return framework

            return None

        except Exception as e:
            logger.error(f"框架检测失败: {e}")
            return None

    def attack_laravel(self, target: str) -> List[Dict]:
        """攻击Laravel应用"""
        results = []

        print("    ⚙️ 开始Laravel专项攻击...")

        # 1. 检查.env文件泄露
        env_vulns = self.check_laravel_env(target)
        results.extend(env_vulns)

        # 2. 检查调试模式
        debug_vulns = self.check_laravel_debug(target)
        results.extend(debug_vulns)

        # 3. 检查存储目录访问
        storage_vulns = self.check_laravel_storage(target)
        results.extend(storage_vulns)

        # 4. CSRF token泄露检查
        csrf_vulns = self.check_laravel_csrf(target)
        results.extend(csrf_vulns)

        return results

    def check_laravel_env(self, target: str) -> List[Dict]:
        """检查Laravel .env文件泄露"""
        vulns = []

        env_urls = [
            urljoin(target, '/.env'),
            urljoin(target, '/.env.example'),
            urljoin(target, '/.env.local'),
            urljoin(target, '/.env.production')
        ]

        for env_url in env_urls:
            try:
                response = self.session.get(env_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否为.env文件
                    if 'APP_KEY=' in content or 'DB_' in content:
                        sensitive_info = []

                        # 提取敏感信息
                        patterns = [
                            ('APP_KEY=', '应用密钥'),
                            ('DB_PASSWORD=', '数据库密码'),
                            ('DB_USERNAME=', '数据库用户名'),
                            ('REDIS_PASSWORD=', 'Redis密码'),
                            ('MAIL_PASSWORD=', '邮件密码'),
                            ('AWS_ACCESS_KEY_ID=', 'AWS访问密钥')
                        ]

                        for pattern, description in patterns:
                            if pattern in content:
                                # 提取值
                                value_match = re.search(rf'{pattern}([^\n]+)', content)
                                if value_match:
                                    sensitive_info.append(f'{description}: {value_match.group(1)[:20]}...')

                        vulns.append({
                            'type': 'laravel_env_disclosure',
                            'severity': 'high',
                            'description': '.env配置文件泄露',
                            'url': env_url,
                            'sensitive_info': sensitive_info[:3]  # 只显示前3个
                        })
                        break  # 发现一个就停止

            except:
                continue

        return vulns

    def check_laravel_debug(self, target: str) -> List[Dict]:
        """检查Laravel调试模式"""
        vulns = []

        # Laravel调试模式特征
        debug_indicators = [
            ('/_ignition/execute-solution', 'Ignition调试接口'),
            ('/telescope', 'Telescope调试面板'),
            ('/horizon', 'Horizon队列面板'),
            ('/log-viewer', '日志查看器')
        ]

        for path, description in debug_indicators:
            debug_url = urljoin(target, path)

            try:
                response = self.session.get(debug_url, timeout=5, verify=False)

                if response.status_code == 200:
                    vulns.append({
                        'type': 'laravel_debug_enabled',
                        'severity': 'medium',
                        'description': f'Laravel调试工具启用: {description}',
                        'url': debug_url
                    })

            except:
                continue

        return vulns

    def check_laravel_storage(self, target: str) -> List[Dict]:
        """检查Laravel存储目录访问"""
        vulns = []

        storage_urls = [
            urljoin(target, '/storage'),
            urljoin(target, '/storage/logs'),
            urljoin(target, '/storage/framework'),
            urljoin(target, '/storage/app')
        ]

        for storage_url in storage_urls:
            try:
                response = self.session.get(storage_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # 检查是否为目录列表
                    if 'Index of' in response.text or 'Directory listing' in response.text:
                        vulns.append({
                            'type': 'laravel_storage_exposed',
                            'severity': 'medium',
                            'description': 'Laravel存储目录暴露',
                            'url': storage_url
                        })
                        break

            except:
                continue

        return vulns

    def check_laravel_csrf(self, target: str) -> List[Dict]:
        """检查Laravel CSRF token泄露"""
        vulns = []

        try:
            response = self.session.get(target, timeout=5, verify=False)
            content = response.text

            # 查找CSRF token
            csrf_patterns = [
                r'name="_token" value="([^"]+)"',
                r'name="csrf-token" content="([^"]+)"',
                r'X-CSRF-TOKEN.*?([a-f0-9]{40})'
            ]

            for pattern in csrf_patterns:
                matches = re.findall(pattern, content, re.I)
                if matches:
                    vulns.append({
                        'type': 'laravel_csrf_token_found',
                        'severity': 'info',
                        'description': f'发现CSRF token (数量: {len(matches)})',
                        'count': len(matches)
                    })
                    break

        except:
            pass

        return vulns

    def attack_django(self, target: str) -> List[Dict]:
        """攻击Django应用"""
        results = []

        print("    ⚙️ 开始Django专项攻击...")

        # 1. 检查Django调试模式
        debug_vulns = self.check_django_debug(target)
        results.extend(debug_vulns)

        # 2. 检查Django管理后台
        admin_vulns = self.check_django_admin(target)
        results.extend(admin_vulns)

        # 3. 检查敏感文件
        file_vulns = self.check_django_files(target)
        results.extend(file_vulns)

        # 4. 检查CSRF token
        csrf_vulns = self.check_django_csrf(target)
        results.extend(csrf_vulns)

        return results

    def check_django_debug(self, target: str) -> List[Dict]:
        """检查Django调试模式"""
        vulns = []

        # Django调试页面特征
        try:
            # 触发一个错误页面
            test_url = urljoin(target, '/test-non-existent-page-12345/')
            response = self.session.get(test_url, timeout=5, verify=False)

            if response.status_code == 404:
                content = response.text

                # 检查是否为Django调试页面
                debug_indicators = [
                    'You\'re seeing this error because you have',
                    'DEBUG = True',
                    'Django settings',
                    'Traceback (most recent call last)'
                ]

                if any(indicator in content for indicator in debug_indicators):
                    vulns.append({
                        'type': 'django_debug_enabled',
                        'severity': 'high',
                        'description': 'Django调试模式启用，暴露敏感信息',
                        'url': test_url
                    })

        except:
            pass

        return vulns

    def check_django_admin(self, target: str) -> List[Dict]:
        """检查Django管理后台"""
        vulns = []

        admin_urls = [
            urljoin(target, '/admin'),
            urljoin(target, '/admin/login'),
            urljoin(target, '/admin/login/')
        ]

        for admin_url in admin_urls:
            try:
                response = self.session.get(admin_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # 确认是Django管理后台
                    if 'Django administration' in response.text or 'id_username' in response.text:
                        vulns.append({
                            'type': 'django_admin_exposed',
                            'severity': 'medium',
                            'description': 'Django管理后台暴露',
                            'url': admin_url
                        })

                        # 尝试默认凭证
                        default_auth = self.test_django_admin_auth(admin_url)
                        if default_auth:
                            vulns.append(default_auth)

                        break

            except:
                continue

        return vulns

    def test_django_admin_auth(self, admin_url: str) -> Optional[Dict]:
        """测试Django管理后台默认凭证"""
        django_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', 'admin123'),
            ('administrator', 'admin')
        ]

        for username, password in django_credentials:
            try:
                session = requests.Session()

                # 先获取登录页面
                response = session.get(admin_url, timeout=5, verify=False)

                # 提取CSRF token
                csrf_match = re.search(r'name="csrfmiddlewaretoken" value="([^"]+)"', response.text)

                if not csrf_match:
                    continue

                csrf_token = csrf_match.group(1)

                # 准备登录数据
                login_data = {
                    'username': username,
                    'password': password,
                    'csrfmiddlewaretoken': csrf_token,
                    'next': '/admin/'
                }

                # 提交登录
                login_response = session.post(
                    admin_url,
                    data=login_data,
                    headers={'Referer': admin_url},
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )

                # 检查是否登录成功
                if 'Site administration' in login_response.text or 'Welcome' in login_response.text:
                    return {
                        'type': 'django_admin_auth_success',
                        'severity': 'high',
                        'description': f'Django管理后台登录成功: {username}:{password}',
                        'username': username,
                        'password': password,
                        'url': admin_url
                    }

            except:
                continue

        return None

    def check_django_files(self, target: str) -> List[Dict]:
        """检查Django敏感文件"""
        vulns = []

        sensitive_files = [
            ('/manage.py', 'Django管理脚本'),
            ('/requirements.txt', 'Python依赖文件'),
            ('/settings.py', 'Django设置文件'),
            ('/urls.py', 'Django路由文件'),
            ('/wsgi.py', 'WSGI配置文件')
        ]

        for path, description in sensitive_files:
            file_url = urljoin(target, path)

            try:
                response = self.session.get(file_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否为Python文件
                    if 'import ' in content or 'from ' in content or 'def ' in content:
                        vulns.append({
                            'type': 'django_file_exposed',
                            'severity': 'medium',
                            'description': f'Django源代码泄露: {description}',
                            'url': file_url,
                            'content_preview': content[:100]
                        })

            except:
                continue

        return vulns

    def check_django_csrf(self, target: str) -> List[Dict]:
        """检查Django CSRF token"""
        vulns = []

        try:
            response = self.session.get(target, timeout=5, verify=False)
            content = response.text

            # 查找CSRF token
            csrf_matches = re.findall(r'csrfmiddlewaretoken.*?value="([^"]+)"', content, re.I)

            if csrf_matches:
                vulns.append({
                    'type': 'django_csrf_token_found',
                    'severity': 'info',
                    'description': f'发现Django CSRF token (数量: {len(csrf_matches)})',
                    'count': len(csrf_matches)
                })

        except:
            pass

        return vulns

    def attack_spring(self, target: str) -> List[Dict]:
        """攻击Spring应用"""
        results = []

        print("    ⚙️ 开始Spring专项攻击...")

        # 1. 检查Actuator端点
        actuator_vulns = self.check_spring_actuator(target)
        results.extend(actuator_vulns)

        # 2. 检查配置信息
        config_vulns = self.check_spring_config(target)
        results.extend(config_vulns)

        # 3. 检查Swagger文档
        swagger_vulns = self.check_spring_swagger(target)
        results.extend(swagger_vulns)

        return results

    def check_spring_actuator(self, target: str) -> List[Dict]:
        """检查Spring Actuator端点"""
        vulns = []

        actuator_endpoints = [
            '/actuator',
            '/actuator/health',
            '/actuator/info',
            '/actuator/metrics',
            '/actuator/env',
            '/actuator/configprops',
            '/actuator/beans',
            '/actuator/mappings',
            '/actuator/heapdump',
            '/actuator/threaddump'
        ]

        for endpoint in actuator_endpoints:
            actuator_url = urljoin(target, endpoint)

            try:
                response = self.session.get(actuator_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否为Spring Actuator
                    if 'status' in content or 'beans' in content or 'health' in content:

                        severity = 'medium'
                        if endpoint in ['/actuator/env', '/actuator/configprops', '/actuator/heapdump']:
                            severity = 'high'

                        vulns.append({
                            'type': 'spring_actuator_exposed',
                            'severity': severity,
                            'description': f'Spring Actuator端点暴露: {endpoint}',
                            'url': actuator_url
                        })

            except:
                continue

        return vulns

    def check_spring_config(self, target: str) -> List[Dict]:
        """检查Spring配置文件"""
        vulns = []

        config_files = [
            '/application.properties',
            '/application.yml',
            '/application.yaml',
            '/bootstrap.properties',
            '/bootstrap.yml'
        ]

        for config_file in config_files:
            config_url = urljoin(target, config_file)

            try:
                response = self.session.get(config_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否为配置文件
                    if 'spring.' in content or 'server.' in content or 'database' in content.lower():

                        sensitive_info = []
                        patterns = [
                            (r'password\s*=\s*([^\n]+)', '密码'),
                            (r'username\s*=\s*([^\n]+)', '用户名'),
                            (r'secret\s*=\s*([^\n]+)', '密钥'),
                            (r'key\s*=\s*([^\n]+)', '密钥')
                        ]

                        for pattern, desc in patterns:
                            matches = re.findall(pattern, content, re.I)
                            if matches:
                                sensitive_info.append(f'{desc}: {matches[0][:20]}...')

                        vulns.append({
                            'type': 'spring_config_exposed',
                            'severity': 'high',
                            'description': 'Spring配置文件泄露',
                            'url': config_url,
                            'sensitive_info': sensitive_info[:3]
                        })
                        break

            except:
                continue

        return vulns

    def check_spring_swagger(self, target: str) -> List[Dict]:
        """检查Swagger API文档"""
        vulns = []

        swagger_paths = [
            '/swagger-ui.html',
            '/swagger-ui/',
            '/v2/api-docs',
            '/v3/api-docs',
            '/swagger-resources',
            '/webjars/swagger-ui'
        ]

        for path in swagger_paths:
            swagger_url = urljoin(target, path)

            try:
                response = self.session.get(swagger_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # 检查是否为Swagger页面
                    if 'swagger' in response.text.lower() or 'api-docs' in response.text:
                        vulns.append({
                            'type': 'swagger_ui_exposed',
                            'severity': 'low',
                            'description': 'Swagger API文档暴露',
                            'url': swagger_url
                        })
                        break

            except:
                continue

        return vulns

    def attack_express(self, target: str) -> List[Dict]:
        """攻击Express应用"""
        results = []

        print("    ⚙️ 开始Express专项攻击...")

        # 1. 检查package.json泄露
        package_vulns = self.check_express_package(target)
        results.extend(package_vulns)

        # 2. 检查源代码泄露
        source_vulns = self.check_express_source(target)
        results.extend(source_vulns)

        # 3. 检查调试端点
        debug_vulns = self.check_express_debug(target)
        results.extend(debug_vulns)

        return results

    def check_express_package(self, target: str) -> List[Dict]:
        """检查package.json泄露"""
        vulns = []

        package_url = urljoin(target, '/package.json')

        try:
            response = self.session.get(package_url, timeout=5, verify=False)

            if response.status_code == 200:
                try:
                    package_data = json.loads(response.text)

                    if 'name' in package_data or 'dependencies' in package_data:
                        vulns.append({
                            'type': 'package_json_exposed',
                            'severity': 'low',
                            'description': 'package.json配置文件泄露',
                            'url': package_url,
                            'name': package_data.get('name', '未知'),
                            'version': package_data.get('version', '未知')
                        })

                except json.JSONDecodeError:
                    # 如果不是JSON，检查是否为Node.js文件
                    if 'express' in response.text.lower():
                        vulns.append({
                            'type': 'package_json_exposed',
                            'severity': 'low',
                            'description': 'package.json配置文件泄露',
                            'url': package_url
                        })

        except:
            pass

        return vulns

    def check_express_source(self, target: str) -> List[Dict]:
        """检查Express源代码泄露"""
        vulns = []

        source_files = [
            '/server.js',
            '/app.js',
            '/index.js',
            '/main.js',
            '/routes/index.js',
            '/controllers'
        ]

        for file in source_files:
            source_url = urljoin(target, file)

            try:
                response = self.session.get(source_url, timeout=5, verify=False)

                if response.status_code == 200:
                    content = response.text

                    # 检查是否为JavaScript文件
                    if 'require(' in content or 'exports' in content or 'module.exports' in content:
                        vulns.append({
                            'type': 'express_source_exposed',
                            'severity': 'medium',
                            'description': f'Node.js源代码泄露: {file}',
                            'url': source_url,
                            'content_preview': content[:100]
                        })
                        break

            except:
                continue

        return vulns

    def check_express_debug(self, target: str) -> List[Dict]:
        """检查Express调试端点"""
        vulns = []

        debug_endpoints = [
            '/debug',
            '/debug/',
            '/dev',
            '/dev/',
            '/test',
            '/test/',
            '/status',
            '/status/'
        ]

        for endpoint in debug_endpoints:
            debug_url = urljoin(target, endpoint)

            try:
                response = self.session.get(debug_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # 检查是否为调试信息
                    content = response.text.lower()
                    if 'debug' in content or 'status' in content or 'environment' in content:
                        vulns.append({
                            'type': 'express_debug_exposed',
                            'severity': 'medium',
                            'description': 'Express调试端点暴露',
                            'url': debug_url
                        })
                        break

            except:
                continue

        return vulns

    def execute_attack(self, target: str, framework_type: str = None) -> List[Dict]:
        """执行框架攻击"""
        results = []

        # 如果没有指定框架，先检测
        if not framework_type:
            framework_type = self.detect_framework(target)

        if not framework_type:
            print("    ⚠️  未检测到支持的框架")
            return results

        print(f"    🎯 检测到 {framework_type.upper()}，开始专项攻击...")

        # 根据框架类型执行相应的攻击
        if framework_type == 'laravel':
            results = self.attack_laravel(target)
        elif framework_type == 'django':
            results = self.attack_django(target)
        elif framework_type == 'spring':
            results = self.attack_spring(target)
        elif framework_type == 'express':
            results = self.attack_express(target)
        elif framework_type == 'ruby_on_rails':
            results.append({
                'type': 'framework_detected',
                'severity': 'info',
                'description': f'检测到{framework_type}，当前版本暂不支持深度攻击',
                'framework': framework_type
            })
        else:
            results.append({
                'type': 'framework_detected',
                'severity': 'info',
                'description': f'检测到{framework_type}，当前版本暂不支持攻击',
                'framework': framework_type
            })

        return results

    def check_url_exists(self, url: str) -> bool:
        """检查URL是否存在"""
        try:
            response = self.session.head(url, timeout=5, verify=False, allow_redirects=True)
            return response.status_code in [200, 301, 302, 403]
        except:
            return False


# 测试函数
def test_framework_attacker():
    """测试框架攻击模块"""
    print("=" * 60)
    print("🧪 框架攻击模块测试")
    print("=" * 60)

    config = {
        'modules': {
            'framework_attacks': {
                'laravel': {'enabled': True},
                'django': {'enabled': True},
                'spring': {'enabled': True},
                'express': {'enabled': True}
            }
        },
        'scan': {'timeout': 10}
    }

    attacker = FrameworkAttacker(config)

    # 测试框架检测
    test_url = "http://example.com"
    framework_type = attacker.detect_framework(test_url)

    if framework_type:
        print(f"检测到框架: {framework_type}")
    else:
        print("未检测到框架")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_framework_attacker()
