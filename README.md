 **YujianAI Pro - 通用AI渗透测试平台 使用说明书** 

📖 目录
工具简介

核心特性

系统架构

安装配置

使用方法

模块详解

输出报告

注意事项

故障排除

更新计划

🎯 工具简介
YujianAI Pro 是一个基于AI驱动的通用渗透测试平台，支持对任意网站、系统和API进行智能化安全测试。工具集成了先进的AI分析引擎、全面的漏洞扫描模块和智能攻击策略，为安全研究人员、渗透测试工程师和企业安全团队提供一站式安全评估解决方案。

🎯 设计理念
智能化：利用AI技术进行目标识别、风险分析和攻击决策

通用性：支持任意Web目标，无需预先了解目标技术栈

自动化：全流程自动化测试，从侦察到报告生成

模块化：灵活的模块架构，支持功能扩展和定制

🌟 核心特性
1. AI智能侦察引擎
自动识别目标技术栈（PHP、Java、Python、Node.js等）

CMS检测（WordPress、Joomla、Drupal、Laravel等）

框架识别（Spring、Django、Express、Ruby on Rails等）

安全风险智能分析

目标类型自动分类

2. 全面漏洞扫描
注入漏洞：SQL注入、命令注入、LDAP注入

跨站脚本：反射型XSS、存储型XSS、DOM XSS

文件安全：文件包含、路径遍历、文件上传绕过

配置错误：目录遍历、敏感文件泄露、配置不当

服务器安全：SSL/TLS配置、HTTP方法、信息泄露

API安全：认证绕过、输入验证、速率限制

3. 智能攻击模块
认证攻击：暴力破解、默认凭证、会话攻击

CMS专项攻击：WordPress、Joomla、Drupal漏洞利用

框架攻击：Laravel、Django、Spring安全测试

API攻击：REST、GraphQL、SOAP安全评估

社会工程：钓鱼页面检测、敏感信息收集

4. 报告生成系统
多种格式报告（JSON、HTML、Markdown）

详细漏洞描述和修复建议

风险等级评估

执行摘要和测试详情

🏗️ 系统架构

项目结构

yujian_ai_pro/
├── ai_assistant.py          # 主程序入口
├── ai_detector.py          # AI智能检测引擎
├── universal_scanner.py     # 通用安全扫描器
├── universal_attacker.py    # 通用攻击器
├── config.yaml             # 配置文件
├── attack_modules/         # 攻击模块库
│   ├── cms_attacks.py      # CMS专项攻击
│   ├── framework_attacks.py # 框架攻击
│   ├── api_attacks.py      # API安全测试
│   ├── auth_attacks.py     # 认证攻击
│   └── vuln_scanner.py     # 漏洞扫描
├── wordlists/             # 字典目录（可选）
├── results/               # 结果输出目录
├── logs/                  # 日志目录
└── README.md             # 说明文档


工作流程

1. 目标输入 → 2. AI侦察 → 3. 深度扫描 → 4. 智能攻击 → 5. 报告生成
   ↓           ↓           ↓           ↓           ↓
用户URL     技术识别     漏洞发现     漏洞验证     安全报告


⚙️ 安装配置
环境要求
Python: 3.8+

操作系统: Windows/Linux/macOS

内存: 2GB+ (推荐4GB)

磁盘空间: 500MB+

网络: 稳定的互联网连接

安装步骤

1. 克隆项目


git clone https://gitee.com/yujian_ai_pro.git
cd yujian_ai_pro

2. 安装依赖

pip install -r requirements.txt

主要依赖包：

requests: HTTP请求库

beautifulsoup4: HTML解析

colorama: 彩色输出

pyyaml: YAML配置文件解析

urllib3: URL处理

cryptography: 加密库

3. AI引擎配置（可选）

如需使用AI分析功能，需要安装Ollama：

# 安装Ollama（Linux/macOS）
curl -fsSL https://ollama.ai/install.sh | sh

# 下载模型
ollama pull mistral:7b
ollama pull llama3.1:latest

4. 配置调整
编辑 config.yaml 文件：

# 基本配置
ai:
  enabled: true
  model: "mistral:7b"
  ollama_url: "http://localhost:11434"

# 扫描配置
scan:
  mode: "aggressive"  # quick/normal/aggressive
  threads: 15
  timeout: 15

# 攻击配置
attack:
  brute_force: true
  sql_injection: true
  xss_test: true

🚀 使用方法
基本命令
1. 交互模式（推荐）

python ai_assistant.py


交互模式支持以下命令：


直接输入URL       # 执行完整测试
scan [URL]       # 只执行扫描
attack [URL]     # 只执行攻击
help             # 显示帮助
exit             # 退出

2. 命令行模式

# 完整测试
python ai_assistant.py http://example.com

# 只扫描
python ai_assistant.py scan http://example.com

# 只攻击
python ai_assistant.py attack http://example.com

# 交互模式
python ai_assistant.py --interactive

# 帮助信息
python ai_assistant.py --help

3. 模块独立使用


# 单独使用扫描器
python -c "
from universal_scanner import UniversalScanner
scanner = UniversalScanner({'scan': {'threads': 10}})
results = scanner.comprehensive_scan('http://example.com', {})
print(results)
"

# 单独使用AI检测
python ai_detector.py

# 测试特定模块
python attack_modules/cms_attacks.py

使用示例
示例1：完整测试WordPress网站

python ai_assistant.py http://wordpress-site.com

测试流程：

AI识别WordPress CMS

扫描插件和主题漏洞

测试默认登录凭证

检查XML-RPC安全

生成详细报告

示例2：API安全测试


```
python ai_assistant.py attack https://api.example.com/v1
```

测试内容：

API端点发现

认证机制测试

输入验证检查

速率限制测试

信息泄露检测

示例3：深度扫描模式

# 编辑config.yaml
scan:
  mode: "aggressive"
  threads: 20
  timeout: 20

# 执行扫描
python ai_assistant.py scan http://target.com

🔧 模块详解

1. AI智能检测引擎 (ai_detector.py)
功能：
技术栈识别：自动识别PHP、Java、Python、Node.js等技术

CMS检测：WordPress、Joomla、Drupal、Magento等识别

风险分析：安全头检查、敏感信息泄露检测

目标分类：电商网站、企业官网、博客、管理系统等

配置参数：


```
ai:
  model: "mistral:7b"      # AI模型
  ollama_url: "http://localhost:11434"
  timeout: 30              # 请求超时
  temperature: 0.3         # AI创造性
  max_tokens: 500          # 最大输出长度
```

2. 通用安全扫描器 (universal_scanner.py)
扫描类型：
目录爆破：300+常见路径和文件

参数测试：GET/POST参数漏洞

头部安全：安全HTTP头检查

服务器检查：HTTP方法、SSL配置

扫描模式：
quick：快速扫描（50个路径）

normal：正常扫描（100个路径）

aggressive：激进扫描（全部路径）

配置示例：


```
scan:
  mode: "aggressive"
  threads: 15
  timeout: 15
  user_agent: "Mozilla/5.0..."
  
wordlists:
  directories: "wordlists/directories.txt"
  parameters: "wordlists/parameters.txt"
```
3. 通用攻击器 (universal_attacker.py)
攻击模块：
认证攻击：表单分析、凭证爆破、会话测试

漏洞利用：SQL注入、XSS、文件包含利用

API测试：端点发现、认证绕过、方法测试

凭证库：
默认凭证：100+常见用户名密码组合

区域特定：中文环境常见凭证

CMS特定：WordPress、Joomla默认凭证

4. CMS攻击模块 (attack_modules/cms_attacks.py)
支持的CMS：
WordPress：版本探测、插件扫描、XML-RPC攻击

Joomla：组件检测、管理员爆破

Drupal：模块扫描、用户登录测试

Laravel：.env文件检测、调试模式检查

攻击策略：


```
1. 检测CMS类型
2. 识别版本信息
3. 扫描已知漏洞
4. 尝试登录爆破
5. 专项功能测试
```

5. 框架攻击模块 (attack_modules/framework_attacks.py)
支持的框架：
Laravel：.env泄露、调试模式、存储目录

Django：调试信息、管理后台、配置文件

Spring：Actuator端点、配置泄露、Swagger

Express：源码泄露、调试端点、package.json

检测方法：
特征路径访问

响应头分析

页面内容匹配

文件指纹识别

6. API攻击模块 (attack_modules/api_attacks.py)
API类型支持：
REST API：JSON/XML接口安全测试

GraphQL：内省查询、批量攻击、复杂度测试

SOAP：WSDL分析、XML注入、XXE测试

测试内容：


```
1. 端点发现 → 2. 认证测试 → 3. 输入验证 → 4. 速率限制 → 5. 信息泄露
```

7. 认证攻击模块 (attack_modules/auth_attacks.py)
攻击类型：
暴力破解：智能表单分析、凭证库管理

会话攻击：会话固定、会话劫持、Cookie安全

OAuth安全：配置错误、开放重定向、Token泄露

智能特性：
自动识别登录表单字段

动态提取CSRF令牌

智能判断登录成功

多线程并发测试

8. 漏洞扫描模块 (attack_modules/vuln_scanner.py)
漏洞类型：
SQL注入：错误型、布尔型、时间盲注

XSS攻击：反射型、存储型、DOM型

命令注入：系统命令、代码执行

文件操作：包含、读取、上传

服务器漏洞：配置错误、信息泄露

扫描策略：


```
输入点发现 → 载荷测试 → 响应分析 → 漏洞确认
```
📊 输出报告
报告格式
1. JSON详细报告
位置：results/test_[target]_[timestamp].json

内容包含：


```
{
  "target": "http://example.com",
  "timestamp": "2024-01-15T10:30:00",
  "phases": {
    "reconnaissance": {...},
    "scanning": {...},
    "attack": {...}
  },
  "findings": [...],
  "recommendations": [...],
  "report": "完整报告文本"
}
```
2. HTML可视化报告
位置：results/report_[target]_[timestamp].html

特性：

响应式设计

漏洞分类展示

风险等级颜色标识

修复建议清单

测试详情摘要

3. 控制台输出


```
╔══════════════════════════════════════════════════════════╗
║                🤖 YujianAI Pro 通用版                    ║
║            AI驱动的通用渗透测试平台                      ║
╚══════════════════════════════════════════════════════════╝

🎯 开始通用渗透测试: http://example.com
============================================================

[1/4] 🕵️  AI智能侦察...
   ✅ AI分析完成: corporate_website

[2/4] 📡 深度安全扫描...
   📊 发现 5 个潜在漏洞

[3/4] ⚔️  智能攻击测试...
   🔐 测试 2 个认证入口...

[4/4] 📋 AI生成安全报告...
💾 详细结果已保存: results/test_example_com_20240115_103000.json
📄 HTML报告已保存: results/report_example_com_20240115_103000.html
```

报告内容详解
执行摘要


```
📋 测试完成摘要
============================================================
🎯 目标: http://example.com
📅 时间: 2024-01-15
⚠️  漏洞发现: 8 个
🔍 敏感路径: 12 个
🚨 高风险漏洞 (2 个):
   • SQL注入 - http://example.com?id=1'
   • 文件包含 - http://example.com?file=../../../etc/passwd
📁 报告文件:
   • JSON详细报告: results/ 目录
   • HTML可视化报告: results/ 目录
============================================================


```

漏洞详情


```
<div class="finding high">
  <h3>🔴 高风险 - SQL注入漏洞</h3>
  <p><strong>URL:</strong> http://example.com?id=1'</p>
  <p><strong>参数:</strong> id</p>
  <p><strong>载荷:</strong> ' OR '1'='1</p>
  <p><strong>证据:</strong> 发现MySQL语法错误信息</p>
  <p><strong>修复建议:</strong> 使用参数化查询或预编译语句</p>
</div>
```
⚠️ 注意事项
法律与道德
仅限授权测试：仅在拥有明确书面授权的目标上使用

遵守法律法规：遵循当地和国际网络安全法律法规

最小影响原则：避免对目标系统造成不必要的影响

数据保护：妥善处理测试中获取的敏感信息

技术注意事项
速率控制：配置适当的请求速率，避免触发WAF或封锁

超时设置：根据网络状况调整超时时间

线程数量：合理配置线程数，避免资源耗尽

错误处理：关注错误日志，及时调整配置

使用建议
测试环境：先在测试环境中验证功能

备份配置：修改配置前备份原始文件

日志监控：定期检查日志文件

更新维护：定期更新工具和字典

🔧 故障排除
常见问题
1. 连接失败


```
❌ 连接目标失败: Connection refused
```
解决方案：

检查网络连接

确认目标可访问

调整超时时间

检查代理设置

2. AI引擎不可用


```
⚠️ AI引擎初始化失败: ConnectionError
```

解决方案：

确认Ollama服务运行：ollama serve

检查模型是否下载：ollama list

验证API端口：curl http://localhost:11434/api/tags

3. 扫描速度慢


```
进度: 50/300 完成 (耗时: 120秒)
```
解决方案：

调整线程数：scan.threads: 20

减少超时时间：scan.timeout: 10

使用快速模式：scan.mode: "quick"

4. 报告生成失败


```
❌ 报告生成失败: Permission denied
```

解决方案：

检查目录权限：chmod 755 results/

确认磁盘空间：df -h

检查文件锁：lsof | grep results

性能优化
配置优化


```
advanced:
  rate_limit: 10          # 每秒请求数
  connection_pool: 50     # 连接池大小
  retry_attempts: 2       # 重试次数
  cache_enabled: true     # 启用缓存
  cache_ttl: 3600         # 缓存时间(秒)
```
字典优化
创建自定义字典：wordlists/custom.txt

按目标类型选择字典

定期更新字典库

🚀 更新计划
短期计划（v2.1）
增加更多CMS支持（Shopify、Magento等）

增强API测试覆盖率

添加更多漏洞检测规则

优化AI分析准确性

中期计划（v2.5）
集成外部工具（nmap、sqlmap等）

添加被动信息收集

支持多目标批量测试

增强报告定制化

长期计划（v3.0）
机器学习漏洞预测

自动化漏洞利用链

云环境安全测试

移动应用安全测试

📞 支持与贡献

获取帮助

微信公众号：

黑帽渗透技术：hkjs6986

网址：https://duduziy.com

GitHub Issues：报告问题或请求功能

文档更新：查看最新使用说明

社区讨论：加入安全社区交流

贡献指南
Fork项目仓库

创建功能分支

提交代码变更

创建Pull Request

代码规范
遵循PEP 8 Python代码规范

添加适当的注释和文档

编写单元测试

更新相关文档

📄 许可证
本项目采用 MIT 许可证 - 查看 LICENSE 文件了解详情。

免责声明


```
本工具仅用于合法的安全测试和教育目的。
使用者应对自己的行为负责。
作者不对任何滥用行为承担责任。
```
🎉 开始使用

现在你已经了解了YujianAI Pro的所有功能，可以开始你的安全测试之旅了！


```
# 快速开始
python ai_assistant.py --help

# 测试示例网站
python ai_assistant.py http://testphp.vulnweb.com

# 探索更多功能
python ai_assistant.py --interactive
```
记住：能力越大，责任越大。请负责任地使用安全工具。
































































































































































































































































































































































































