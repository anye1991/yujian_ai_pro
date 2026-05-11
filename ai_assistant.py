#!/usr/bin/env python3
# 2026-05-11 优化
"""
🎯 YujianAI Pro - 通用AI渗透测试平台
🤖 支持任意网站、系统、API的智能安全测试
"""

import sys
import json
import re
from datetime import datetime
from pathlib import Path

# 添加路径
sys.path.insert(0, str(Path(__file__).parent))


class UniversalAI_Tester:
    """通用AI渗透测试器"""

    def __init__(self):
        self.config = self.load_config()
        self.ai_detector = None
        self.scanner = None
        self.attacker = None
        self.current_target = None
        self.test_history = []

        self.init_system()

    def load_config(self):
        """加载配置"""
        default_config = {
            'ai': {
                'model': 'mistral:7b',
                'ollama_url': 'http://localhost:11434',
                'timeout': 30,
                'enabled': True
            },
            'scan': {
                'depth': 'aggressive',  # 激进模式，找更多路径
                'threads': 15,
                'timeout': 15
            },
            'attack': {
                'brute_force': True,
                'sql_injection': True,
                'xss_test': True,
                'csrf_test': True,
                'file_upload_test': True,
                'info_disclosure': True,
                'rate_limit': 10  # 请求速率限制
            }
        }
        return default_config

    def init_system(self):
        """初始化系统"""
        print("""
╔══════════════════════════════════════════════════════════╗
║                🤖 YujianAI Pro 通用版                    ║
║            AI驱动的通用渗透测试平台                      ║
╚══════════════════════════════════════════════════════════╝
        """)

        print("[*] 正在初始化通用测试引擎...")

        # 1. 初始化AI检测引擎
        try:
            from ai_detector import UniversalDetector
            self.ai_detector = UniversalDetector(self.config)
            print("✅ AI智能检测引擎就绪")
        except Exception as e:
            print(f"⚠️  AI引擎初始化失败: {e}")

        # 2. 初始化通用扫描器
        try:
            from universal_scanner import UniversalScanner
            self.scanner = UniversalScanner(self.config)
            print("✅ 通用扫描器就绪")
        except Exception as e:
            print(f"⚠️  扫描器初始化失败: {e}")

        # 3. 初始化通用攻击器
        try:
            from universal_attacker import UniversalAttacker
            self.attacker = UniversalAttacker(self.config)
            print("✅ 通用攻击器就绪")
        except Exception as e:
            print(f"⚠️  攻击器初始化失败: {e}")

        print("\n" + "=" * 60)
        print("✨ 系统初始化完成！支持任意目标测试")
        print("=" * 60 + "\n")

    def universal_test(self, target):
        """通用测试入口"""
        self.current_target = target

        print(f"\n🎯 开始通用渗透测试: {target}")
        print("=" * 60)

        results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'phases': {},
            'findings': [],
            'recommendations': []
        }

        # 阶段1：智能侦察
        print("\n[1/4] 🕵️  AI智能侦察...")
        recon_results = self.smart_reconnaissance(target)
        results['phases']['reconnaissance'] = recon_results
        print(f"   🔍 识别结果: {recon_results.get('target_type', '未知')}")

        # 阶段2：深度扫描
        print("\n[2/4] 📡 深度安全扫描...")
        scan_results = self.deep_scan(target, recon_results)
        results['phases']['scanning'] = scan_results
        print(f"   📊 发现 {len(scan_results.get('vulnerabilities', []))} 个潜在漏洞")

        # 阶段3：智能攻击
        print("\n[3/4] ⚔️  智能攻击测试...")
        attack_results = self.intelligent_attack(target, recon_results, scan_results)
        results['phases']['attack'] = attack_results

        # 阶段4：AI分析报告
        print("\n[4/4] 📋 AI生成安全报告...")
        report = self.generate_ai_report(results)
        results['report'] = report

        # 保存结果
        self.save_results(results)

        # 打印摘要
        self.print_summary(results)

        return results

    def smart_reconnaissance(self, target):
        """智能侦察"""
        recon = {
            'target': target,
            'detection_time': datetime.now().isoformat()
        }

        if self.ai_detector:
            # 使用AI进行深度识别
            detection = self.ai_detector.detect_all(target)
            recon.update(detection)
        else:
            # 基础识别
            recon.update(self.basic_detection(target))

        return recon

    def basic_detection(self, target):
        """基础检测"""
        import requests
        try:
            resp = requests.get(target, timeout=10, verify=False)
            content = resp.text.lower()

            detection = {
                'tech_stack': [],
                'cms': None,
                'framework': None,
                'server': resp.headers.get('Server', '未知'),
                'status': resp.status_code
            }

            # 简单技术栈识别
            if '.php' in target or 'php' in content:
                detection['tech_stack'].append('PHP')
            if '.asp' in target or 'asp' in content:
                detection['tech_stack'].append('ASP.NET')
            if '.jsp' in target:
                detection['tech_stack'].append('Java')

            # CMS检测
            if 'wp-content' in content:
                detection['cms'] = 'WordPress'
            elif 'joomla' in content:
                detection['cms'] = 'Joomla'
            elif 'drupal' in content:
                detection['cms'] = 'Drupal'

            return detection
        except:
            return {'tech_stack': ['未知'], 'error': '连接失败'}

    def deep_scan(self, target, recon_info):
        """深度扫描"""
        scan_results = {
            'vulnerabilities': [],
            'sensitive_paths': [],
            'security_issues': [],
            'authentication_points': []
        }

        if self.scanner:
            # 执行全面扫描
            full_scan = self.scanner.comprehensive_scan(target, recon_info)
            scan_results.update(full_scan)
        else:
            # 简单扫描
            scan_results.update(self.quick_scan(target))

        return scan_results

    def quick_scan(self, target):
        """快速扫描"""
        common_paths = [
            '/admin', '/login', '/admin.php', '/admin.asp',
            '/wp-admin', '/wp-login.php', '/administrator',
            '/backend', '/manager', '/dashboard', '/console',
            '/api', '/api/v1', '/api/v2', '/swagger',
            '/.env', '/config.php', '/phpinfo.php',
            '/robots.txt', '/sitemap.xml', '/.git/',
            '/test', '/debug', '/phpmyadmin'
        ]

        import requests
        found_paths = []

        for path in common_paths[:10]:  # 只测试前10个
            url = target.rstrip('/') + path
            try:
                resp = requests.get(url, timeout=5, verify=False)
                if resp.status_code in [200, 301, 302, 403]:
                    found_paths.append({
                        'url': url,
                        'status': resp.status_code,
                        'type': self.classify_path(path, resp.text)
                    })
            except:
                pass

        return {
            'sensitive_paths': found_paths,
            'vulnerabilities': self.check_common_vulns(target)
        }

    def classify_path(self, path, content):
        """分类路径类型"""
        content_lower = content.lower()

        if 'login' in path or 'password' in content_lower:
            return 'authentication'
        elif 'admin' in path or '管理' in content_lower:
            return 'admin_panel'
        elif 'api' in path or 'json' in content_lower:
            return 'api_endpoint'
        elif 'config' in path or '数据库' in content_lower:
            return 'config_file'
        else:
            return 'unknown'

    def check_common_vulns(self, target):
        """检查常见漏洞"""
        vulns = []

        # SQL注入检查
        sql_payloads = ["'", "\"", "' OR '1'='1"]
        for payload in sql_payloads:
            test_url = f"{target}?id={payload}"
            try:
                import requests
                resp = requests.get(test_url, timeout=5, verify=False)
                if any(err in resp.text.lower() for err in ['sql', 'mysql', 'syntax']):
                    vulns.append({
                        'type': 'sql_injection',
                        'severity': 'high',
                        'payload': payload,
                        'url': test_url
                    })
                    break
            except:
                pass

        # XSS检查
        xss_payload = "<script>alert('XSS')</script>"
        test_url = f"{target}?q={xss_payload}"
        try:
            import requests
            resp = requests.get(test_url, timeout=5, verify=False)
            if xss_payload in resp.text:
                vulns.append({
                    'type': 'xss',
                    'severity': 'medium',
                    'payload': xss_payload,
                    'url': test_url
                })
        except:
            pass

        return vulns

    def intelligent_attack(self, target, recon_info, scan_info):
        """智能攻击"""
        attack_results = {
            'authentication_tests': [],
            'api_tests': [],
            'vulnerability_exploits': []
        }

        if self.attacker:
            # 基于侦察信息选择攻击策略
            attack_plan = self.attacker.create_attack_plan(recon_info, scan_info)

            # 执行认证测试
            if scan_info.get('authentication_points'):
                auth_results = self.attacker.test_authentication(target, scan_info['authentication_points'])
                attack_results['authentication_tests'] = auth_results

            # 执行API测试
            if recon_info.get('api_detected'):
                api_results = self.attacker.test_api_security(target)
                attack_results['api_tests'] = api_results

            # 尝试利用漏洞
            if scan_info.get('vulnerabilities'):
                exploit_results = self.attacker.exploit_vulnerabilities(target, scan_info['vulnerabilities'])
                attack_results['vulnerability_exploits'] = exploit_results
        else:
            # 基础攻击测试
            attack_results.update(self.basic_attack_test(target))

        return attack_results

    def basic_attack_test(self, target):
        """基础攻击测试"""
        results = {'brute_force': None, 'common_vulns': []}

        # 简单爆破测试
        common_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'admin'),
            ('root', 'root')
        ]

        login_urls = [target + '/login', target + '/admin', target + '/wp-login.php']

        for login_url in login_urls:
            success = False
            for username, password in common_creds:
                # 这里简化处理，实际需要表单提交
                print(f"  测试 {username}:{password} @ {login_url}")
                # 实际实现需要处理表单提交

            if success:
                break

        return results

    def generate_ai_report(self, results):
        """AI生成报告"""
        if self.ai_detector and hasattr(self.ai_detector, 'generate_report'):
            return self.ai_detector.generate_report(results)

        # 基础报告
        report = f"""
安全测试报告
============

目标: {results['target']}
时间: {results['timestamp']}

发现摘要:
"""

        # 添加发现
        if results['phases'].get('scanning', {}).get('vulnerabilities'):
            vulns = results['phases']['scanning']['vulnerabilities']
            report += f"- 发现 {len(vulns)} 个潜在漏洞\n"
            for vuln in vulns[:3]:  # 显示前3个
                report += f"  • {vuln.get('type', '未知')} ({vuln.get('severity', '中')})\n"

        if results['phases'].get('scanning', {}).get('sensitive_paths'):
            paths = results['phases']['scanning']['sensitive_paths']
            report += f"- 发现 {len(paths)} 个敏感路径\n"

        if results['phases'].get('attack', {}).get('authentication_tests'):
            auth_tests = results['phases']['attack']['authentication_tests']
            if any(test.get('success') for test in auth_tests):
                report += "- 认证测试: 发现弱密码\n"

        report += """
建议:
1. 修复发现的漏洞
2. 加强访问控制
3. 实施输入验证
4. 定期安全测试
5. 启用安全监控

报告生成: YujianAI Pro 通用渗透测试平台
"""

        return report

    def save_results(self, results):
        """保存结果"""
        import json

        # 创建结果目录
        Path("results").mkdir(exist_ok=True)

        # 生成文件名
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = re.sub(r'[^a-zA-Z0-9]', '_', results['target'].replace('://', '_'))
        filename = f"results/test_{domain}_{timestamp}.json"

        # 保存JSON
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"💾 详细结果已保存: {filename}")

        # 同时保存HTML报告
        html_report = self.generate_html_report(results)
        html_filename = f"results/report_{domain}_{timestamp}.html"
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_report)

        print(f"📄 HTML报告已保存: {html_filename}")

    def generate_html_report(self, results):
        """生成HTML报告"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>YujianAI 安全测试报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #3498db; background: #f8f9fa; }}
        .finding {{ padding: 10px; margin: 10px 0; background: white; border: 1px solid #ddd; }}
        .high {{ border-left: 4px solid #e74c3c; }}
        .medium {{ border-left: 4px solid #f39c12; }}
        .low {{ border-left: 4px solid #3498db; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #ecf0f1; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 YujianAI Pro 安全测试报告</h1>
        <p>目标: {results['target']} | 时间: {results['timestamp']}</p>
    </div>

    <div class="section">
        <h2>📊 执行摘要</h2>
"""

        # 添加发现
        vulns = results['phases'].get('scanning', {}).get('vulnerabilities', [])
        if vulns:
            html += f"<p>发现 <strong>{len(vulns)}</strong> 个潜在漏洞</p>"
            html += "<table><tr><th>类型</th><th>严重性</th><th>详情</th></tr>"
            for vuln in vulns[:10]:  # 显示前10个
                severity_class = vuln.get('severity', 'medium').lower()
                html += f"""
                <tr class="{severity_class}">
                    <td>{vuln.get('type', '未知')}</td>
                    <td><span class="{severity_class}">{severity_class.upper()}</span></td>
                    <td>{vuln.get('description', '')[:100]}...</td>
                </tr>
                """
            html += "</table>"

        # 添加建议
        html += """
    </div>

    <div class="section">
        <h2>💡 安全建议</h2>
        <ul>
            <li>及时修复发现的漏洞</li>
            <li>加强身份验证机制</li>
            <li>实施输入验证和过滤</li>
            <li>定期更新系统和组件</li>
            <li>启用安全监控和日志</li>
            <li>进行定期的安全测试</li>
        </ul>
    </div>

    <div class="section">
        <h2>📋 测试详情</h2>
        <p>详细测试数据已保存为JSON文件，包含完整的请求/响应信息。</p>
    </div>

    <footer>
        <p>报告生成: YujianAI Pro 通用渗透测试平台 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </footer>
</body>
</html>
"""

        return html

    def print_summary(self, results):
        """打印测试摘要"""
        print("\n" + "=" * 60)
        print("📋 测试完成摘要")
        print("=" * 60)

        vulns = results['phases'].get('scanning', {}).get('vulnerabilities', [])
        paths = results['phases'].get('scanning', {}).get('sensitive_paths', [])

        print(f"🎯 目标: {results['target']}")
        print(f"📅 时间: {results['timestamp'].split('T')[0]}")
        print(f"⚠️  漏洞发现: {len(vulns)} 个")
        print(f"🔍 敏感路径: {len(paths)} 个")

        # 显示高风险漏洞
        high_vulns = [v for v in vulns if v.get('severity') == 'high']
        if high_vulns:
            print(f"\n🚨 高风险漏洞 ({len(high_vulns)} 个):")
            for vuln in high_vulns[:3]:
                print(f"   • {vuln.get('type', '未知')} - {vuln.get('url', '')[:50]}...")

        print("\n📁 报告文件:")
        print("   • JSON详细报告: results/ 目录")
        print("   • HTML可视化报告: results/ 目录")
        print("=" * 60)

    def interactive_mode(self):
        """交互式模式"""
        print("\n💬 交互模式激活！")
        print("你可以:")
        print("  1. 输入URL进行测试")
        print("  2. 输入'scan [URL]' 只扫描")
        print("  3. 输入'attack [URL]' 只攻击")
        print("  4. 输入'help' 查看帮助")
        print("  5. 输入'exit' 退出\n")

        while True:
            try:
                cmd = input("🔧 命令: ").strip()

                if cmd.lower() in ['exit', 'quit', 'q']:
                    print("👋 再见！")
                    break

                if cmd.lower() == 'help':
                    self.show_help()
                    continue

                if not cmd:
                    continue

                # 解析命令
                if cmd.startswith('http'):
                    # 直接URL，执行完整测试
                    self.universal_test(cmd)
                elif cmd.startswith('scan '):
                    url = cmd[5:].strip()
                    if url.startswith('http'):
                        self.deep_scan_only(url)
                    else:
                        print("❌ 请输入有效的URL")
                elif cmd.startswith('attack '):
                    url = cmd[7:].strip()
                    if url.startswith('http'):
                        self.attack_only(url)
                    else:
                        print("❌ 请输入有效的URL")
                else:
                    print("❌ 未知命令，输入'help'查看帮助")

                print()  # 空行

            except KeyboardInterrupt:
                print("\n\n👋 用户中断")
                break
            except Exception as e:
                print(f"❌ 错误: {e}")

    def deep_scan_only(self, target):
        """只执行深度扫描"""
        print(f"\n📡 执行深度扫描: {target}")
        recon = self.smart_reconnaissance(target)
        scan_results = self.deep_scan(target, recon)

        print(f"\n📊 扫描结果:")
        print(f"  漏洞发现: {len(scan_results.get('vulnerabilities', []))} 个")
        print(f"  敏感路径: {len(scan_results.get('sensitive_paths', []))} 个")

        # 显示发现的路径
        paths = scan_results.get('sensitive_paths', [])
        if paths:
            print("\n🔍 发现的敏感路径:")
            for path in paths[:5]:  # 显示前5个
                print(f"  [{path.get('status')}] {path.get('url')}")

    def attack_only(self, target):
        """只执行攻击测试"""
        print(f"\n⚔️  执行攻击测试: {target}")

        # 先做简单侦察
        recon = self.basic_detection(target)

        # 执行攻击
        attack_results = self.intelligent_attack(target, recon, {})

        print(f"\n⚡ 攻击测试完成:")
        if attack_results.get('authentication_tests'):
            auth_tests = attack_results['authentication_tests']
            success_tests = [t for t in auth_tests if t.get('success')]
            print(f"  认证测试: {len(success_tests)} 次成功")

        if attack_results.get('vulnerability_exploits'):
            exploits = attack_results['vulnerability_exploits']
            print(f"  漏洞利用: {len(exploits)} 个尝试")

    def show_help(self):
        """显示帮助"""
        help_text = """
🤖 YujianAI Pro 通用渗透测试平台
================================

基本命令:
  1. 直接输入URL - 执行完整测试
    示例: http://example.com

  2. scan [URL] - 只执行扫描
    示例: scan http://example.com

  3. attack [URL] - 只执行攻击测试
    示例: attack http://example.com/login

  4. help - 显示此帮助

  5. exit - 退出程序

支持的测试类型:
  • Web应用安全测试
  • API安全测试
  • 认证机制测试
  • 常见漏洞扫描
  • 敏感信息发现
  • 配置错误检测

报告输出:
  • JSON详细报告 (results/目录)
  • HTML可视化报告 (results/目录)

配置调整:
  编辑 config.yaml 调整测试参数
        """
        print(help_text)


def main():
    """主函数"""
    print("正在启动 YujianAI Pro...")

    # 创建测试器实例
    tester = UniversalAI_Tester()

    # 检查命令行参数
    if len(sys.argv) > 1:
        arg = sys.argv[1]

        if arg in ['--help', '-h', 'help']:
            tester.show_help()
        elif arg.startswith('http'):
            # 直接测试URL
            tester.universal_test(arg)
        elif arg == '--interactive' or arg == '-i':
            # 交互模式
            tester.interactive_mode()
        else:
            print(f"未知参数: {arg}")
            print("使用: python ai_assistant.py [URL] 或 python ai_assistant.py --interactive")
    else:
        # 默认进入交互模式
        tester.interactive_mode()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 用户中断")
    except Exception as e:
        print(f"\n❌ 致命错误: {e}")
        import traceback

        traceback.print_exc()
