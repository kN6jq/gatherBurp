# APIKit 智能检测功能验证指南

这个目录包含用于验证APIKit智能检测功能的靶场和测试脚本。

## 📁 文件说明

### 1. test_target.py - Flask靶场服务器
模拟一个带有WAF的Spring Boot Actuator环境，用于测试URL编码绕过。

**功能：**
- 模拟WAF拦截敏感路径（/actuator, /mappings等）
- 返回模拟的Actuator数据
- 支持URL编码绕过

**启动方式：**
```bash
# 安装依赖
pip install flask

# 启动靶场
python test_target.py
```

**访问地址：**
- 主页: http://localhost:5000/
- Actuator: http://localhost:5000/actuator (被拦截)
- Mappings: http://localhost:5000/actuator/mappings (被拦截)
- Test: http://localhost:5000/test (正常)

### 2. test_smart_detection.py - 智能检测测试脚本
自动测试各种编码绕过场景，验证智能检测器功能。

**测试场景：**
1. **场景1**: 正常访问 /actuator
   - 预期: 403 (被WAF拦截)
   - 说明: 基准测试，验证WAF正常工作

2. **场景2**: URL编码访问 /actuator
   - URL: /%61%63%74%75%61%74%6f%72
   - 预期: 200 (绕过成功)
   - 说明: 标准URL编码绕过

3. **场景3**: 双重URL编码访问 /actuator
   - URL: /%2561%2563%2574%2575%2561%2574%256f%2572
   - 预期: 200 (绕过成功)
   - 说明: 双重编码绕过

4. **场景4**: Unicode编码访问 /actuator
   - URL: /\u0061\u0063\u0074\u0075\u0061\u0074\u006f\u0072
   - 预期: 200 (绕过成功)
   - 说明: Unicode编码绕过

5. **场景5**: 正常访问 /test
   - 预期: 200 (正常访问)
   - 说明: 验证安全路径不被拦截

**运行方式：**
```bash
# 安装依赖
pip install requests

# 运行测试
python test_smart_detection.py
```

## 🚀 快速开始

### 步骤1: 启动靶场
```bash
# 终端1 - 启动靶场
python test_target.py
```

你应该看到：
```
============================================================
APIKit Smart Detection Test Target
============================================================

Starting server on http://localhost:5000

Test scenarios:
1. Normal access: http://localhost:5000/actuator (BLOCKED)
2. URL encoded: http://localhost:5000/%61%63%74%75%61%74%6f%72 (BYPASS)
3. Safe endpoint: http://localhost:5000/test (OK)

============================================================
```

### 步骤2: 运行测试脚本
```bash
# 终端2 - 运行测试
python test_smart_detection.py
```

你应该看到：
```
============================================================
APIKit 智能检测功能验证
============================================================

这个脚本将测试以下场景：
1. 正常访问敏感路径（应该被拦截）
2. URL编码访问（应该绕过）
3. 双重URL编码访问（应该绕过）
4. Unicode编码访问（应该绕过）
5. 正常访问安全路径（不应该被拦截）

============================================================

============================================================
测试: 场景1: 正常访问 /actuator
URL: http://localhost:5000/actuator
预期: 应该被WAF拦截（403）
============================================================
状态码: 403
❌ 被WAF拦截！
错误信息: {"error": "Access Denied", "message": "WAF blocked this request", "path": "/actuator"}

============================================================
测试: 场景2: URL编码访问 /actuator
URL: http://localhost:5000/%61%63%74%75%61%74%6f%72
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
| 场景4 | 200 | Unicode编码绕过成功 ✅ |
| 场景5 | 200 | 正常访问 ✅ |

## 🔍 APIKit智能检测器工作流程

当你在APIKit中使用智能检测器时：

```
1. APIKit访问 /actuator
   ↓
2. 返回403（被拦截）
   ↓
3. SmartRequestDetector检测到拦截
   ↓
4. 自动尝试编码绕过：
   - URL编码: /%61%63%74%75%61%74%6f%72
   - 双重编码: /%2561%2563...
   - Unicode编码: /\u0061\u0063...
   - 混合编码: /a%63t%75a...
   ↓
5. 发现绕过成功
   ↓
6. 返回200响应
   ↓
7. 控制台输出: [SmartDetector] Encoding bypass successful: /actuator
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

## 🐛 故障排除

### 问题1: 连接失败
**错误**: `❌ 连接失败！请确保靶场已启动`

**解决**: 确保test_target.py正在运行，端口5000未被占用

### 问题2: 所有场景都返回403
**错误**: URL编码也被拦截

**解决**: 检查test_target.py中的WAF规则，确保只检测原始路径

### 问题3: 所有场景都返回200
**错误**: WAF没有拦截任何请求

**解决**: 检查test_target.py的@app.before_request是否正常工作

## 📝 自定义测试

你可以修改test_target.py来自定义WAF规则：

```python
# 添加新的拦截规则
WAF_RULES = [
    r'/actuator',
    r'/api/admin',      # 新增：拦截admin接口
    r'/config',         # 新增：拦截配置接口
]
```

你也可以修改test_smart_detection.py来添加新的测试场景：

```python
test_scenarios = [
    {
        "name": "新场景: 测试自定义路径",
        "path": "/api/admin",
        "description": "应该被WAF拦截（403）"
    },
    # 添加更多场景...
]
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

---

**Happy Testing! 🎉**