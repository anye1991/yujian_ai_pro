# YujianAI Pro - 通用AI渗透测试平台

**YujianAI Pro** 是一个基于AI驱动的通用渗透测试平台，支持对任意网站、系统和API进行智能化安全测试。平台集成了AI分析引擎、漏洞扫描模块和智能攻击策略，为安全研究人员、渗透测试工程师和企业安全团队提供一站式安全评估解决方案。

---

## 🎯 工具简介

YujianAI Pro 是一个智能化、通用性、自动化、模块化的渗透测试平台，支持从侦察到报告生成的全流程自动化测试。

---

## 🌟 核心特性

- **AI智能侦察引擎**：自动识别目标技术栈、CMS、框架等。
- **全面漏洞扫描**：支持SQL注入、XSS、文件包含、敏感文件泄露等常见漏洞检测。
- **智能攻击模块**：支持认证攻击、CMS专项攻击、API攻击等。
- **报告生成系统**：支持JSON、HTML、Markdown格式，提供详细漏洞描述和修复建议。

---

## 🏗️ 系统架构

项目结构如下：

```
yujian_ai_pro/
├── ai_assistant.py          # 主程序入口
├── ai_detector.py           # AI智能检测引擎
├── universal_scanner.py     # 通用安全扫描器
├── universal_attacker.py    # 通用攻击器
├── config.yaml              # 配置文件
├── attack_modules/          # 攻击模块库
│   ├── cms_attacks.py       # CMS专项攻击
│   ├── framework_attacks.py # 框架攻击
│   ├── api_attacks.py       # API安全测试
│   ├── auth_attacks.py      # 认证攻击
│   └── vuln_scanner.py      # 漏洞扫描
├── wordlists/               # 字典目录
├── results/                 # 结果输出目录
├── logs/                    # 日志目录
└── README.md                # 说明文档
```

---

## ⚙️ 安装配置

### 环境要求

- Python: 3.8+
- 操作系统: Windows/Linux/macOS
- 内存: 2GB+ (推荐4GB)
- 磁盘空间: 500MB+
- 网络: 稳定的互联网连接

### 安装步骤

1. 克隆项目

```bash
git clone https://github.com/anye1991/yujian_ai_pro.git
cd yujian_ai_pro
```

2. 安装依赖

```bash
pip install -r requirements.txt
```

3. 安装Ollama（可选，用于AI功能）

```bash
# 安装Ollama（Linux/macOS）
curl -fsSL https://ollama.ai/install.sh | sh

# 下载模型
ollama pull mistral:7b
ollama pull llama3.1:latest
```

4. 配置调整

编辑 `config.yaml` 文件，根据需求调整AI、扫描和攻击配置。

---

## 🚀 使用方法

### 基本命令

1. **交互模式（推荐）**

```bash
python ai_assistant.py
```

2. **命令行模式**

```bash
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
```

3. **模块独立使用**

```bash
# 单独使用扫描器
python -c "from universal_scanner import UniversalScanner; scanner = UniversalScanner({'scan': {'threads': 10}}); results = scanner.comprehensive_scan('http://example.com', {}); print(results)"

# 单独使用AI检测
python ai_detector.py

# 测试特定模块
python attack_modules/cms_attacks.py
```

---

## 📊 输出报告

支持以下报告格式：

- **JSON**：`results/test_[target]_[timestamp].json`
- **HTML**：`results/report_[target]_[timestamp].html`
- **控制台输出**：实时显示测试进度和结果

---

## ⚠️ 注意事项

- **法律与道德**：仅在授权测试目标上使用，遵守法律法规。
- **技术注意事项**：合理配置速率、超时、线程数，避免触发WAF或封锁。
- **使用建议**：先在测试环境中验证功能，定期更新工具和字典。

---

## 🔧 故障排除

常见问题及解决方案详见原 README.md 文件。

---

## 📦 更新计划

- **短期计划（v2.1）**：增加更多CMS支持、增强API测试覆盖率、优化AI分析。
- **中期计划（v2.5）**：集成外部工具、支持多目标批量测试。
- **长期计划（v3.0）**：机器学习漏洞预测、自动化漏洞利用链、云环境安全测试。

---

## 📞 支持与贡献

- **微信公众号**：黑帽渗透技术（hkjs6986）
- **网址**：https://duduziy.com
- **GitHub Issues**：报告问题或请求功能
- **社区讨论**：加入安全社区交流

---

## 📄 许可证

本项目采用 MIT 许可证。详见 `LICENSE` 文件。

---

## 🎉 快速开始

```bash
# 快速开始
python ai_assistant.py --help

# 测试示例网站
python ai_assistant.py http://testphp.vulnweb.com

# 探索更多功能
python ai_assistant.py --interactive
```

> **免责声明**：本工具仅用于合法的安全测试和教育目的。使用者应对自己的行为负责。作者不对任何滥用行为承担责任。
