#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APIKit智能检测功能验证脚本
演示如何测试URL编码绕过功能
"""

import requests
import urllib.parse

# 靶场地址
BASE_URL = "http://localhost:5000"

# 测试场景
test_scenarios = [
    {
        "name": "场景1: 正常访问 /actuator",
        "path": "/actuator",
        "description": "应该被WAF拦截（403）"
    },
    {
        "name": "场景2: URL编码访问 /actuator",
        "path": "/%61%63%74%75%61%74%6f%72",
        "description": "应该绕过WAF（200）"
    },
    {
        "name": "场景3: 双重URL编码访问 /actuator",
        "path": "/%2561%2563%2574%2575%2561%2574%256f%2572",
        "description": "应该绕过WAF（200）"
    },
    {
        "name": "场景4: Unicode编码访问 /actuator",
        "path": "/\\u0061\\u0063\\u0074\\u0075\\u0061\\u0074\\u006f\\u0072",
        "description": "应该绕过WAF（200）"
    },
    {
        "name": "场景5: 正常访问 /test",
        "path": "/test",
        "description": "不应该被拦截（200）"
    }
]

def test_scenario(scenario):
    """测试单个场景"""
    url = BASE_URL + scenario["path"]
    
    print(f"\n{'='*60}")
    print(f"测试: {scenario['name']}")
    print(f"URL: {url}")
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
        print("❌ 连接失败！请确保靶场已启动")
        print("启动命令: python test_target.py")
    except Exception as e:
        print(f"❌ 错误: {e}")

def main():
    """主函数"""
    print("\n" + "=" * 60)
    print("APIKit 智能检测功能验证")
    print("=" * 60)
    print("\n这个脚本将测试以下场景：")
    print("1. 正常访问敏感路径（应该被拦截）")
    print("2. URL编码访问（应该绕过）")
    print("3. 双重URL编码访问（应该绕过）")
    print("4. Unicode编码访问（应该绕过）")
    print("5. 正常访问安全路径（不应该被拦截）")
    print("\n" + "=" * 60)
    
    # 执行所有测试场景
    for scenario in test_scenarios:
        test_scenario(scenario)
    
    # 总结
    print("\n" + "=" * 60)
    print("测试总结")
    print("=" * 60)
    print("\n预期结果：")
    print("- 场景1: 403（被拦截）")
    print("- 场景2: 200（绕过成功）")
    print("- 场景3: 200（绕过成功）")
    print("- 场景4: 200（绕过成功）")
    print("- 场景5: 200（正常访问）")
    print("\nAPIKit智能检测器应该：")
    print("1. 先尝试场景1（正常访问）")
    print("2. 检测到403后，自动尝试场景2-4（编码绕过）")
    print("3. 场景5不需要绕过，直接返回")
    print("\n" + "=" * 60)

if __name__ == '__main__':
    main()