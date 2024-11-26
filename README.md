# gatherBurp

![License](https://img.shields.io/github/license/kN6jq/gatherBurp)
![Stars](https://img.shields.io/github/stars/kN6jq/gatherBurp)
![Issues](https://img.shields.io/github/issues/kN6jq/gatherBurp)

一款强大的 Web 安全测试套件，集成多种安全测试功能，支持自动化扫描和手动测试。

## 使用视频

相关功能使用视频已更新到哔哩哔哩
https://www.bilibili.com/video/BV1UtScY7EyT/?spm_id_from=333.999.0.0

## ✨ 核心功能

### 🔍 漏洞扫描
- Fastjson 漏洞扫描（支持 DNS、JNDI、回显等多种检测方式）
- SQL 注入检测（支持 GET、POST、Cookie、多层级 JSON）
- Log4j 漏洞检测
- 未授权访问检测

### 🛡️ 权限测试
- URI 特殊字符绕过
- Header 字段绕过
- Accept 头绕过

### 🌐 信息收集
- 子域名收集
- 多层级路由扫描

### 🔧 辅助工具
- 一键生成 Nuclei 模板
- 代理池功能
- 复杂数据提交（解决序列化数据编码问题）
- 工具快速调用

## 🚀 快速开始

### 安装

```bash
mvn clean package
```
> ⚠️ 请注意：编译后的 jar 包位于 target/ 目录下

### 基本使用
所有功能均可通过右键菜单快速调用：

![操作界面](images/img.png)

## 📚 详细功能说明

### 1. Fastjson 扫描
![Fastjson扫描](images/img_1.png)

**前置配置**：
- 在配置面板设置 DNS 和 IP
- DNS 扫描：配置类型为 dns，使用 FUZZ 占位符
- JNDI 扫描：配置类型为 jndi，支持 DNS/IP 选择
- 回显扫描：支持 Tomcat、Spring 等多种环境

### 2. 权限绕过
![权限绕过](images/img_2.png)

- URI 绕过
- Header 绕过
- Accept 绕过


## 🔍 多层级路由扫描解析表达式说明

支持以下格式的表达式：
```text
code=200
body="hello"
title="druid"
headers="Content-Type: application/json"

# 复杂条件
code=200 && body="hello"
code!=200 && (body="hello" || title="druid")
```

## 🤝 参与贡献

我们非常欢迎各种形式的贡献：
- 🎨 提交新功能建议
- 🐛 报告 Bug
- 📝 改进文档
- 🔧 提交代码优化

> 如果您有好的想法，请提交 Issue，我们会认真考虑并尽力实现！

## 👥 交流群

加入微信讨论群：

请移步issus查看群聊

## 📋 待办事项

- [ ] 功能优化和 Bug 修复
- [ ] 新功能开发
- [ ] 性能优化
- [ ] 文档完善

## ⚠️ 免责声明

本工具仅用于授权的安全测试，请勿用于非法用途。使用本工具造成的任何后果由使用者承担。

## 📄 License

[MIT License](LICENSE)

---
如果觉得这个项目对您有帮助，请给个 Star ⭐️ 支持一下！
