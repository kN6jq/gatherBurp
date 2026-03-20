# APIKit 智能检测功能验证指南（真实WAF绕过环境）

这个目录包含用于验证APIKit智能检测功能的真实WAF绕过测试环境。

## 📁 文件说明

### 1. backend_server.py - 后端服务器
模拟Spring Boot Actuator后端，不进行WAF检测。

**功能：**
- 返回模拟的Actuator JSON数据
- 处理解码后的URL路径
- 端口：5001

**启动方式：**
```bash
python backend_server.py
```

### 2. waf_proxy.py - WAF代理服务器
模拟WAF拦截，但允许URL编码的请求通过。

**功能：**
- 检查原始URL路径（不解码）
- 拦截敏感路径（/actuator, /mappings等）
- URL编码的请求绕过WAF，转发到后端
- 端口：5000

**启动方式：**
```bash
python waf_proxy.py
```

### 3. test_smart_detection_real.py - 智能检测测试脚本
自动测试各种编码绕过场景，验证智能检测器功能。

**测试场景：**
1. **场景1**: 正常访问 /actuator（通过WAF）
   - 预期: 403 (被WAF拦截)
   - 说明: 基准测试，验证WAF正常工作

2. **场景2**: URL编码访问 /actuator（通过WAF）
   - URL: /%61%63%74%75%61%74%6f%72
   - 预期: 200 (绕过WAF)
   - 说明: 标准URL编码绕过

3. **场景3**: 双重URL编码访问 /actuator（通过WAF）
   - URL: /%2561%2563%2574%2575%2561%2574%256f%2572
   - 预期: 200 (绕过WAF)
   - 说明: 双重编码绕过

4. **场景4**: 直接访问后端 /actuator（绕过WAF）
   - URL: http://localhost:5001/actuator
   - 预期: 200 (直接访问后端)
   - 说明: 验证后端服务器正常工作

5. **场景5**: 正常访问 /test（通过WAF）
   - 预期: 200 (正常访问)
   - 说明: 验证安全路径不被拦截

**运行方式：**
```bash
python test_smart_detection_real.py
```

## 🚀 快速开始

### 步骤1: 启动后端服务器
```bash
# 终端1 - 启动后端服务器
python backend_server.py
```

你应该看到：
```
============================================================
Backend Server - Spring Boot Actuator Simulation
============================================================

Starting backend server on http://localhost:5001

Note: This server does NOT have WAF protection
All requests will be processed normally

============================================================
```

### 步骤2: 启动WAF代理服务器
```bash
# 终端2 - 启动WAF代理服务器
python waf_proxy.py
```

你应该看到：
```
============================================================
WAF Proxy Server
============================================================

Starting WAF server on http://localhost:5000
Backend server: http://localhost:5001

WAF Rules:
  - /actuator
  - /mappings
  - /health
  - /env
  - /configprops
  - /beans

Behavior:
- WAF checks raw URL (not decoded)
- URL encoded requests bypass WAF
- Backend processes decoded URL

Test scenarios:
1. Normal access: http://localhost:5000/actuator (BLOCKED)
2. URL encoded: http://localhost:5000/%61%63%74%75%61%74%6f%72 (BYPASS)
3. Safe endpoint: http://localhost:5000/test (OK)

============================================================
```

### 步骤3: 运行测试脚本
```bash
# 终端3 - 运行测试
python test_smart_detection_real.py
```

你应该看到详细的测试结果：
```
============================================================
APIKit 智能检测功能验证（真实WAF绕过环境）
============================================================

这个脚本将测试以下场景：
1. 正常访问敏感路径（应该被WAF拦截）
2. URL编码访问（应该绕过WAF）
3. 双重URL编码访问（应该绕过WAF）
4. 直接访问后端（绕过WAF，应该成功）
5. 正常访问安全路径（不应该被拦截）

============================================================

============================================================
测试: 场景1: 正常访问 /actuator（通过WAF）
URL: http://localhost:5000/actuator
服务器: WAF代理
预期: 应该被WAF拦截（403）
============================================================
状态码: 403
❌ 被WAF拦截！
错误信息: {"error": "Access Denied", "message": "WAF blocked this request", "path": "/actuator"}

============================================================
测试: 场景2: URL编码访问 /actuator（通过WAF）
URL: http://localhost:5000/%61%63%74%75%61%74%6f%72
服务器: WAF代理
预期: 应该绕过WAF（200）
============================================================
状态码: 200
✅ 成功访问！
响应内容: {"_links": {...}}
...
```

## 📊 预期结果

| 场景 | 状态码 | 说明 |
|--------|---------|------|
| 场景1 | 403 | 被WAF拦截 ✅ |
| 场景2 | 200 | URL编码绕过成功 ✅ |
| 场景3 | 200 | 双重编码绕过成功 ✅ |
| 场景4 | 200 | 直接访问后端成功 ✅ |
| 场景5 | 200 | 正常访问 ✅ |

## 🔍 架构说明

```
客户端 → WAF代理 (5000) → 后端服务器 (5001)
         ↓ 检查原始URL    ↓ 解码URL
         ↓ 拦截敏感路径    ↓ 处理业务逻辑
```

**WAF代理行为：**
1. 接收客户端请求
2. 检查原始URL路径（不解码）
3. 如果匹配敏感路径，返回403
4. 如果不匹配，转发到后端服务器

**后端服务器行为：**
1. 接收来自WAF代理的请求
2. 解码URL路径
3. 处理业务逻辑
4. 返回响应

**URL编码绕过原理：**
- 客户端发送: `/%61%63%74%75%61%74%6f%72`
- WAF检查原始路径: `/%61%63%74%75%61%74%6f%72` (不匹配 `/actuator`)
- WAF允许通过
- 后端解码路径: `/actuator`
- 后端正常处理

## 🔍 APIKit智能检测器工作流程

当你在APIKit中使用智能检测器时：

```
1. APIKit访问 http://localhost:5000/actuator
   ↓
2. WAF检测到 /actuator，返回403
   ↓
3. SmartRequestDetector检测到403
   ↓
4. 自动尝试编码绕过：
   - URL编码: http://localhost:5000/%61%63%74%75%61%74%6f%72
   - 双重编码: http://localhost:5000/%2561%2563...
   - Unicode编码: http://localhost:5000/\u0061\u0063...
   - 混合编码: http://localhost:5000/a%63t%75a...
   ↓
5. WAF检查编码后的路径，不匹配规则
   ↓
6. WAF转发到后端
   ↓
7. 后端解码路径，正常处理
   ↓
8. 返回200响应
   ↓
9. 控制台输出: [SmartDetector] Encoding bypass successful: /actuator
```

## 🎯 验证APIKit集成

### 方法1: 在Burp Suite中测试

1. 编译APIKit:
```bash
cd reference/APIKit
mvn clean package
```

2. 在Burp Suite中加载APIKit插件

3. 配置APIKit:
   - 打开APIKit标签页
   - 启用"Auto send request"

4. 测试:
   - 在Proxy中访问 http://localhost:5000/
   - 右键选择"APIKit"相关功能
   - 观察控制台输出

### 方法2: 查看日志

在Burp Suite的Extender标签页，你应该看到：

```
[SmartDetector] Normal request blocked, trying encoding bypass...
[SmartDetector] Encoding bypass successful: http://localhost:5000/actuator
```

在WAF代理服务器的终端，你应该看到：

```
[WAF] BLOCKED: /actuator
[WAF] ALLOWED: /%61%63%74%75%61%74%6f%72 - forwarding to backend
```

在后端服务器的终端，你应该看到：

```
[BACKEND] /actuator accessed
```

## 🐛 故障排除

### 问题1: 连接失败
**错误**: `❌ 连接失败！请确保服务器已启动`

**解决**: 确保backend_server.py和waf_proxy.py都在运行

### 问题2: 所有场景都返回403
**错误**: URL编码也被拦截

**解决**: 检查waf_proxy.py的WAF规则，确保只检查原始路径

### 问题3: 所有场景都返回200
**错误**: WAF没有拦截任何请求

**解决**: 检查waf_proxy.py的@app.before_request是否正常工作

### 问题4: 后端服务器无法访问
**错误**: `Bad Gateway`

**解决**: 确保backend_server.py在端口5001上运行

## 📝 自定义测试

你可以修改waf_proxy.py来自定义WAF规则：

```python
WAF_RULES = [
    r'/actuator',
    r'/api/admin',      # 新增：拦截admin接口
    r'/config',         # 新增：拦截配置接口
]
```

你也可以修改backend_server.py来添加新的端点：

```python
elif decoded_path == '/api/admin':
    print(f"[BACKEND] /api/admin accessed")
    self.send_json_response({
        "message": "Admin endpoint"
    })
```

## 🔐 安全提示

这个靶场仅用于学习和测试目的：
- 不要在生产环境中使用
- 理解WAF绕过技术的原理
- 在授权的安全测试中使用这些技术

## 📚 参考资料

- URL编码: https://en.wikipedia.org/wiki/Percent-encoding
- Unicode编码: https://en.wikipedia.org/wiki/Unicode
- WAF绕过: https://owasp.org/www-community/attacks/Web_Application_Firewall
- Spring Boot Actuator: https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html

---

**Happy Testing! 🎉**