# Certdx 文档

欢迎使用 Certdx 文档！Certdx 是一个集中式 SSL 证书管理系统，让证书的获取、更新和分发变得简单高效。

## 📖 文档目录

### 🚀 快速开始

- **[快速开始指南](01-quick-start.md)** - 5分钟快速体验 Certdx

### 📋 详细指南

- **[安装指南](02-installation.md)** - 完整的安装步骤和系统要求
- **[配置指南](03-configuration.md)** - 详细的配置参数说明
- **[部署示例](04-deployment-examples.md)** - 各种场景的部署示例
- **[运维指南](05-operations.md)** - 日常运维和监控
- **[API参考](06-api-reference.md)** - HTTP 和 gRPC API 文档
- **[故障排除](07-troubleshooting.md)** - 常见问题和解决方案

## 🎯 根据你的需求选择

### 我想快速试用

👉 直接查看 [快速开始指南](01-quick-start.md)

### 我要生产部署

1. [安装指南](02-installation.md) → 了解系统要求和安装方法
2. [配置指南](03-configuration.md) → 配置服务器和客户端
3. [部署示例](04-deployment-examples.md) → 选择适合的部署方案
4. [运维指南](05-operations.md) → 了解监控和维护

### 我要集成开发

1. [API参考](06-api-reference.md) → 了解接口规范
2. [配置指南](03-configuration.md) → 了解配置选项
3. [故障排除](07-troubleshooting.md) → 解决常见问题

### 我遇到了问题

👉 查看 [故障排除](07-troubleshooting.md)

## 💡 核心概念

- **服务器 (Server)**: 中央证书管理节点，负责与 ACME 服务器通信
- **客户端 (Client)**: 从服务器获取证书的节点，支持多种模式
- **证书订阅**: 客户端订阅特定域名的证书，自动获取更新
- **自动续期**: 系统自动监控证书有效期并提前续期

## 🤝 获取帮助

- 📚 查看相应的文档章节
- 🐛 遇到 Bug？请提交 [Issue](https://github.com/ParaParty/certdx/issues)

---

> **提示**: 文档中的所有配置示例都可以直接使用，只需要根据你的环境调整相应的域名和路径。
