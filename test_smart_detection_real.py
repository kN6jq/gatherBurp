#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APIKit智能检测功能验证脚本（真实WAF绕过环境）
使用WAF代理+后端服务器架构
"""

import requests
import urllib.parse

# 靶场地址
BASE_URL = "http://localhost:5000"  # WAF代理
BACKEND_URL = "http://localhost:5001"  # 后端服务器

# 测试场景
test_scenarios = [
    {
        "name": "场景1: 正常访问 /actuator（通过WAF）",
        "path": "/actuator",
        "description": "应该被WAF拦截（403）"
    },
    {
        "name": "场景2: URL编码访问 /actuator（通过WAF）",
        "path": "/%61%63%74%75%61%74%6f%72",
        "description": "应该绕过WAF（200）"
    },
    {
        "name": "场景3: 双重URL编码访问 /actuator（通过WAF）",
        "path": "/%2561%2563%2574%2575%2561%2574%256f%2572",
        "description": "应该绕过WAF（200）"
    },
    {
        "name": "场景4: 直接访问后端 /actuator（绕过WAF）",
        "path": "/actuator",
        "description": "直接访问后端，应该成功（200）",
        "direct_backend": True
    },
    {
        "name": "场景5: 正常访问 /test（通过WAF）",
        "path": "/test",
        "description": "不应该被拦截（200）"
    }
]

def test_scenario(scenario):
    """测试单个场景"""
    # 判断是否直接访问后端
    url = BACKEND_URL + scenario["path"] if scenario.get("direct_backend") else BASE_URL + scenario["path"]
    server_type = "后端服务器" if scenario.get("direct_backend") else "WAF代理"
    
    print(f"\n{'='*60}")
    print(f"测试: {scenario['name']}")
    print(f"URL: {url}")
    print(f"服务器: {server_type}")
    print(f"预期: {scenario['description']}")
    print(f"{'='*60}")
    
    try:
        response = requests.get(url, timeout=5)
        
        print(f"状态码: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ 成功访问！")
            try:
                print(f"响应内容: {response.json()}")
            except:
                print(f"响应内容: {response.text[:200]}...")
        elif response.status_code == 403:
            print("❌ 被WAF拦截！")
            try:
                print(f"错误信息: {response.json()}")
            except:
                print(f"错误信息: {response.text[:200]}...")
        elif response.status_code == 404:
            print("⚠️  路径不存在")
        else:
            print(f"⚠️  其他状态码: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ 连接失败！请确保服务器已启动")
        print("启动命令:")
        print("  终端1: python backend_server.py")
        print("  终端2: python waf_proxy.py")
    except Exception as e:
        print(f"❌ 错误: {e}")

def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("APIKit 智能检测功能验证（真实WAF绕过环境）")
    print("=" * 60)
    print("\n这个脚本将测试以下场景：")
    print("1. 正常访问敏感路径（应该被WAF拦截）")
    print("2. URL编码访问（应该绕过WAF）")
    print("3. 双重URL编码访问（应该绕过WAF）")
    print("4. 直接访问后端（绕过WAF，应该成功）")
    print("5. 正常访问安全路径（不应该被拦截）")
    print("\n架构说明:")
    print("- WAF代理 (端口5000): 拦截敏感路径")
    print("- 后端服务器 (端口5001): 处理业务逻辑")
    print("- URL编码可以绕过WAF，到达后端")
    print("\n" + "=" * 60)
    
    # 执行所有测试场景
    for scenario in test_scenarios:
        test_scenario(scenario)
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print("\n预期结果：")
    print("- 场景1: 403（被WAF拦截）")
    print("- 场景2: 200（URL编码绕过WAF）")
    print("- 场景3: 200（双重编码绕过WAF）")
    print("- 场景4: 200（直接访问后端）")
    print("- 场景5: 200（正常访问，不被拦截）")
    print("\nAPIKit智能检测器应该：")
    print("1. 先尝试场景1（正常访问）")
    print("2. 检测到403后，自动尝试场景2-3（编码绕过）")
    print("3. 场景5不需要绕过，直接返回")
    print("\n" + "=" * 60)

if __name__ == '__main__':
    main()