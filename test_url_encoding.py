#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单的URL编码绕过测试
验证URL编码是否可以绕过WAF
"""

import requests
import urllib.parse

BASE_URL = "http://localhost:5000"

# 测试URL编码绕过
print("=" * 60)
print("URL编码绕过测试")
print("=" * 60)

# 原始路径
original_path = "/actuator"
print(f"\n原始路径: {original_path}")

# URL编码
url_encoded = urllib.parse.quote(original_path, safe='')
print(f"URL编码: {url_encoded}")

# 测试1: 正常访问
print("\n" + "-" * 60)
print("测试1: 正常访问")
print("-" * 60)
url1 = BASE_URL + original_path
print(f"URL: {url1}")
try:
    response1 = requests.get(url1, timeout=5)
    print(f"状态码: {response1.status_code}")
    print(f"结果: {'被拦截' if response1.status_code == 403 else '成功'}")
except Exception as e:
    print(f"错误: {e}")

# 测试2: URL编码访问（使用原始请求，不自动解码）
print("\n" + "-" * 60)
print("测试2: URL编码访问")
print("-" * 60)
url2 = BASE_URL + url_encoded
print(f"URL: {url2}")
try:
    response2 = requests.get(url2, timeout=5)
    print(f"状态码: {response2.status_code}")
    print(f"结果: {'被拦截' if response2.status_code == 403 else '成功'}")
    if response2.status_code == 200:
        print("✅ URL编码绕过成功！")
except Exception as e:
    print(f"错误: {e}")

# 测试3: 使用原始HTTP请求（绕过requests的自动解码）
print("\n" + "-" * 60)
print("测试3: 使用原始HTTP请求")
print("-" * 60)
import socket

def send_raw_request(host, port, path):
    """发送原始HTTP请求"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    request = f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
    sock.send(request.encode())
    response = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    sock.close()
    return response.decode('utf-8', errors='ignore')

# 测试原始路径
print("\n测试原始路径:")
raw_response1 = send_raw_request("localhost", 5000, original_path)
lines = raw_response1.split('\r\n')
status_line = lines[0]
print(f"状态: {status_line}")

# 测试URL编码路径
print("\n测试URL编码路径:")
raw_response2 = send_raw_request("localhost", 5000, url_encoded)
lines = raw_response2.split('\r\n')
status_line = lines[0]
print(f"状态: {status_line}")

print("\n" + "=" * 60)