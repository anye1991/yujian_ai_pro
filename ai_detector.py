#!/usr/bin/env python3
"""
🧠 AI智能检测引擎 - 使用Ollama进行智能分析
"""

import requests
import re
import json
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class UniversalDetector:
    """通用AI检测器"""

    def __init__(self, config: Dict):
        self.config = config.get('ai', {})
        self.model = self.config.get('model', 'mistral:7b')
        self.ollama_url = self.config.get('ollama_url', 'http://localhost:11434')
        self.timeout = self.config.get('timeout', 30)

        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

        print(f"🧠 AI检测引擎: 使用模型 {self.model}")

        # 测试连接
        self.test_connection()

    def test_connection(self):
        """测试Ollama连接"""
        try:
            response = self.session.get(
                f"{self.ollama_url}/api/tags",
                timeout=5
            )

            if response.status_code == 200:
                models = response.json().get('models', [])
                available_models = [m['name'] for m in models]

                if self.model in available_models:
                    print(f"✅ AI引擎连接成功")
                    return True
                else:
                    print(f"⚠️  模型 {self.model} 不可用")
                    if available_models:
                        self.model = available_models[0]
                        print(f"🔄 自动切换到: {self.model}")
                        return True
            return False
        except Exception as e:
            print(f"❌ AI引擎连接失败: {e}")
            return False

    def detect_all(self, target: str) -> Dict:
        """执行全面检测"""
        print(f"  开始AI智能分析...")

        detection = {
            'target': target,
            'detection_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'ai_model': self.model
        }

        try:
            # 获取页面内容
            response = requests.get(target, timeout=10, verify=False)
            content = response.text[:5000]  # 限制内容长度

            # 1. 技术栈识别
            tech_stack = self.detect_tech_stack(content, response.headers)
            detection['tech_stack'] = tech_stack

            # 2. CMS识别
            cms = self.detect_cms(content, response.headers)
            if cms:
                detection['cms'] = cms

            # 3. 安全风险分析
            risk_analysis = self.analyze_security_risk(content, response.headers)
            detection['risk_analysis'] = risk_analysis

            # 4. AI深度分析
            ai_analysis = self.ai_deep_analysis(target, content[:2000])
            detection['ai_analysis'] = ai_analysis

            # 5. 目标类型分类
            target_type = self.classify_target(target, content, tech_stack, cms)
            detection['target_type'] = target_type

            print(f"  ✅ AI分析完成: {target_type}")

        except Exception as e:
            detection['error'] = str(e)
            print(f"  ❌ AI分析失败: {e}")

        return detection

    def detect_tech_stack(self, content: str, headers) -> List[str]:
        """检测技术栈"""
        tech_stack = []
        content_lower = content.lower()
        headers_str = str(headers).lower()

        # 服务器技术
        if 'x-powered-by: php' in headers_str or '.php' in content_lower:
            tech_stack.append('PHP')
        if 'x-powered-by: asp.net' in headers_str or '.aspx' in content_lower:
            tech_stack.append('ASP.NET')
        if '.jsp' in content_lower:
            tech_stack.append('Java')
        if 'python' in headers_str or 'django' in content_lower:
            tech_stack.append('Python')
        if 'node.js' in headers_str or 'express' in content_lower:
            tech_stack.append('Node.js')
        if 'ruby' in headers_str or 'rails' in content_lower:
            tech_stack.append('Ruby')

        # 前端框架
        if 'react' in content_lower:
            tech_stack.append('React')
        if 'vue' in content_lower:
            tech_stack.append('Vue')
        if 'angular' in content_lower:
            tech_stack.append('Angular')

        # 数据库
        if 'mysql' in content_lower:
            tech_stack.append('MySQL')
        if 'postgresql' in content_lower:
            tech_stack.append('PostgreSQL')
        if 'mongodb' in content_lower:
            tech_stack.append('MongoDB')

        # Web服务器
        if 'apache' in headers_str:
            tech_stack.append('Apache')
        if 'nginx' in headers_str:
            tech_stack.append('Nginx')
        if 'iis' in headers_str:
            tech_stack.append('IIS')

        return list(set(tech_stack))  # 去重

    def detect_cms(self, content: str, headers) -> Optional[str]:
        """检测CMS"""
        content_lower = content.lower()
        headers_str = str(headers).lower()

        # WordPress
        if 'wp-content' in content_lower or 'wp-includes' in content_lower:
            return 'WordPress'

        # Joomla
        if 'joomla' in content_lower or 'media/jui' in content_lower:
            return 'Joomla'

        # Drupal
        if 'drupal' in content_lower or 'sites/all' in content_lower:
            return 'Drupal'

        # Magento
        if 'magento' in content_lower:
            return 'Magento'

        # Shopify
        if 'shopify' in content_lower:
            return 'Shopify'

        # Laravel
        if 'laravel' in content_lower:
            return 'Laravel'

        # Django
        if 'django' in content_lower or 'csrfmiddlewaretoken' in content_lower:
            return 'Django'

        return None

    def analyze_security_risk(self, content: str, headers) -> Dict:
        """分析安全风险"""
        risk_score = 0
        issues = []

        content_lower = content.lower()
        headers_dict = dict(headers)

        # 1. 检查安全头
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options',
                            'X-XSS-Protection', 'Content-Security-Policy']

        missing_headers = []
        for header in security_headers:
            if header not in headers_dict:
                missing_headers.append(header)
                risk_score += 10

        if missing_headers:
            issues.append(f"缺少安全头: {', '.join(missing_headers)}")

        # 2. 检查敏感信息泄露
        sensitive_patterns = [
            (r'password\s*[:=]\s*["\']?[^"\'\s]+', '密码泄露'),
            (r'api[_-]?key\s*[:=]\s*["\']?[^"\'\s]+', 'API密钥泄露'),
            (r'secret\s*[:=]\s*["\']?[^"\'\s]+', '密钥泄露'),
            (r'database\s*[:=]\s*["\']?[^"\'\s]+', '数据库信息泄露')
        ]

        for pattern, description in sensitive_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                issues.append(description)
                risk_score += 20

        # 3. 检查调试信息
        if 'debug' in content_lower or 'test' in content_lower:
            issues.append('调试信息泄露')
            risk_score += 15

        # 确定风险等级
        if risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 20:
            risk_level = 'medium'
        else:
            risk_level = 'low'

        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'issues': issues,
            'recommendation': self.get_risk_recommendation(risk_level)
        }

    def get_risk_recommendation(self, risk_level: str) -> str:
        """获取风险建议"""
        recommendations = {
            'high': '立即修复安全问题',
            'medium': '建议尽快修复安全问题',
            'low': '建议进行安全加固'
        }
        return recommendations.get(risk_level, '进行安全评估')

    def ai_deep_analysis(self, target: str, content: str) -> Dict:
        """AI深度分析"""
        try:
            prompt = f"""作为网络安全专家，请分析这个网站：

URL: {target}

页面内容摘要:
{content[:1000]}

请分析:
1. 网站的主要功能是什么？
2. 可能存在的安全风险有哪些？
3. 建议的测试重点是什么？

请用JSON格式回复，包含以下字段:
- website_function: 字符串
- potential_risks: 字符串列表
- testing_focus: 字符串列表
- confidence_level: 数字 (0-1)
            """

            response = self.ask_ai(prompt, max_tokens=500)

            # 尝试解析JSON
            try:
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    return json.loads(json_match.group())
            except:
                pass

            # 解析失败，返回基础分析
            return {
                'website_function': '未知',
                'potential_risks': ['需要进一步分析'],
                'testing_focus': ['认证安全', '输入验证'],
                'confidence_level': 0.5
            }

        except Exception as e:
            return {
                'error': str(e),
                'website_function': '分析失败',
                'potential_risks': [],
                'testing_focus': ['基础安全测试'],
                'confidence_level': 0.0
            }

    def ask_ai(self, prompt: str, max_tokens: int = 300) -> str:
        """向AI提问"""
        try:
            data = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.3,
                    "top_p": 0.9,
                    "num_predict": max_tokens
                }
            }

            response = self.session.post(
                f"{self.ollama_url}/api/generate",
                json=data,
                timeout=self.timeout
            )

            if response.status_code == 200:
                result = response.json()
                return result.get('response', '').strip()
            else:
                return ""

        except Exception as e:
            logger.error(f"AI请求失败: {e}")
            return ""

    def classify_target(self, target: str, content: str,
                        tech_stack: List[str], cms: Optional[str]) -> str:
        """分类目标类型"""
        content_lower = content.lower()
        url_lower = target.lower()

        # 电子商务
        if any(keyword in content_lower for keyword in ['shop', 'cart', 'product', 'price', 'buy']):
            return 'ecommerce'

        # 企业官网
        if any(keyword in content_lower for keyword in ['company', 'about us', 'contact', 'service']):
            return 'corporate_website'

        # 博客
        if any(keyword in content_lower for keyword in ['blog', 'article', 'post', 'comment']):
            return 'blog'

        # 论坛
        if any(keyword in content_lower for keyword in ['forum', 'discussion', 'thread', 'topic']):
            return 'forum'

        # 管理系统
        if any(keyword in url_lower or keyword in content_lower
               for keyword in ['admin', 'manage', 'dashboard', 'control']):
            return 'management_system'

        # API服务
        if any(keyword in url_lower for keyword in ['api', 'rest', 'graphql']):
            return 'api_service'

        # CMS网站
        if cms:
            return f'cms_{cms.lower()}'

        # 根据技术栈判断
        if 'PHP' in tech_stack and 'MySQL' in tech_stack:
            return 'php_web_application'

        return 'general_website'

    def generate_report(self, test_results: Dict) -> str:
        """生成AI报告"""
        try:
            prompt = f"""根据渗透测试结果生成专业安全报告:

测试结果摘要:
{json.dumps(test_results, indent=2, ensure_ascii=False)}

请生成包含以下内容的专业报告:
1. 执行摘要 (Executive Summary)
2. 测试范围和方法 (Scope and Methodology)
3. 发现的安全问题 (Findings)
4. 风险评级 (Risk Rating)
5. 修复建议 (Recommendations)
6. 总结 (Conclusion)

请用中文生成，保持专业、简洁、实用。"""

            report = self.ask_ai(prompt, max_tokens=800)

            if not report:
                report = self.generate_basic_report(test_results)

            return report

        except Exception as e:
            return f"报告生成失败: {str(e)}"

    def generate_basic_report(self, test_results: Dict) -> str:
        """生成基础报告"""
        target = test_results.get('target', '未知目标')

        report = f"""
安全测试报告
============

目标: {target}
时间: {test_results.get('timestamp', '未知')}

发现摘要:
"""

        # 添加漏洞信息
        if 'phases' in test_results:
            scan_phase = test_results['phases'].get('scanning', {})
            vulnerabilities = scan_phase.get('vulnerabilities', [])

            if vulnerabilities:
                report += f"- 发现 {len(vulnerabilities)} 个潜在漏洞\n"
                for vuln in vulnerabilities[:5]:
                    report += f"  • {vuln.get('type', '未知')} ({vuln.get('severity', '中')})\n"

        report += """
建议:
1. 及时修复发现的漏洞
2. 加强访问控制和认证机制
3. 实施输入验证和输出编码
4. 配置适当的安全HTTP头
5. 定期进行安全测试和代码审计

报告生成: YujianAI Pro 通用渗透测试平台
"""

        return report


# 测试函数
def test_detector():
    """测试检测器"""
    print("=" * 60)
    print("🧪 AI检测引擎测试")
    print("=" * 60)

    config = {
        'ai': {
            'model': 'mistral:7b',
            'ollama_url': 'http://localhost:11434',
            'timeout': 30
        }
    }

    detector = UniversalDetector(config)

    # 测试检测功能
    test_url = "http://example.com"

    print(f"测试目标: {test_url}")
    detection = detector.detect_all(test_url)

    print(f"\n检测结果:")
    print(f"  技术栈: {detection.get('tech_stack', [])}")
    print(f"  CMS: {detection.get('cms', '无')}")
    print(f"  目标类型: {detection.get('target_type', '未知')}")

    risk_analysis = detection.get('risk_analysis', {})
    print(f"  风险等级: {risk_analysis.get('risk_level', '未知')}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_detector()