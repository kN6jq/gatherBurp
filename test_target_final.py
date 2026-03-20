#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
智能检测靶场 - 简化版本
直接模拟WAF拦截和绕过，不依赖URL解码机制
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import re
from urllib.parse import unquote

# 模拟的WAF规则 - 拦截敏感路径（原始路径，不解码）
WAF_RULES = [
    r'/actuator',
    r'/mappings',
    r'/health',
    r'/env',
    r'/configprops',
    r'/beans'
]

# 模拟的Spring Boot Actuator端点数据
ACTUATOR_DATA = {
    "_links": {
        "self": {
            "href": "http://localhost:5000/actuator"
        },
        "mappings": {
            "href": "http://localhost:5000/actuator/mappings"
        },
        "health": {
            "href": "http://localhost:5000/actuator/health"
        },
        "env": {
            "href": "http://localhost:5000/actuator/env"
        }
    }
}

MAPPINGS_DATA = {
    "contexts": {
        "application": {
            "mappings": {
                "/api/test": {
                    "bean": "testController",
                    "method": ["GET"]
                },
                "/api/user": {
                    "bean": "userController",
                    "method": ["GET", "POST"]
                },
                "/api/admin": {
                    "bean": "adminController",
                    "method": ["GET"]
                }
            }
        }
    }
}

class SmartDetectionHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP请求处理器，模拟WAF拦截和绕过"""
    
    def log_message(self, format, *args):
        """自定义日志输出"""
        print(f"[SERVER] {format % args}")
    
    def send_json_response(self, data, status_code=200):
        """发送JSON响应"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def send_error_response(self, error, message, path, status_code=403):
        """发送错误响应"""
        self.send_json_response({
            "error": error,
            "message": message,
            "path": path
        }, status_code)
    
    def check_waf(self, raw_path):
        """
        WAF检测 - 模拟真实的WAF行为
        - 检查原始路径（不解码）
        - 如果匹配敏感路径，返回True
        - URL编码后的路径不会被检测到
        """
        for rule in WAF_RULES:
            if re.search(rule, raw_path):
                print(f"[WAF] Blocked request to: {raw_path}")
                return True
        return False
    
    def is_url_encoded(self, path):
        """检查路径是否包含URL编码"""
        return '%' in path
    
    def do_GET(self):
        """处理GET请求"""
        # 获取原始路径（不解码）
        raw_path = self.path.split('?')[0]
        
        # 模拟WAF检测
        # 如果路径是URL编码的，WAF无法识别敏感路径
        # 如果路径是原始的，WAF可以识别并拦截
        if not self.is_url_encoded(raw_path) and self.check_waf(raw_path):
            self.send_error_response(
                "Access Denied",
                "WAF blocked this request",
                raw_path,
                403
            )
            return
        
        # 解码路径用于路由处理
        decoded_path = unquote(raw_path)
        
        # 路由处理
        if decoded_path == '/':
            self.send_json_response({
                "message": "Welcome to APIKit Test Target",
                "description": "This is a simple target for testing smart detection",
                "endpoints": [
                    "/actuator - Simulated Spring Boot Actuator (blocked by WAF)",
                    "/mappings - API mappings (blocked by WAF)",
                    "/health - Health check (blocked by WAF)"
                ]
            })
        elif decoded_path == '/actuator':
            print(f"[ACCESS] /actuator accessed (bypassed WAF)")
            self.send_json_response(ACTUATOR_DATA)
        elif decoded_path == '/actuator/mappings':
            print(f"[ACCESS] /actuator/mappings accessed (bypassed WAF)")
            self.send_json_response(MAPPINGS_DATA)
        elif decoded_path == '/actuator/health':
            print(f"[ACCESS] /actuator/health accessed (bypassed WAF)")
            self.send_json_response({
                "status": "UP"
            })
        elif decoded_path == '/actuator/env':
            print(f"[ACCESS] /actuator/env accessed (bypassed WAF)")
            self.send_json_response({
                "activeProfiles": ["dev"],
                "propertySources": []
            })
        elif decoded_path == '/test':
            print(f"[ACCESS] /test accessed (not blocked)")
            self.send_json_response({
                "message": "Test endpoint - not blocked by WAF"
            })
        else:
            self.send_error_response(
                "Not Found",
                "The requested resource was not found",
                decoded_path,
                404
            )
    
    def log_request(self, code='-', size='-'):
        """自定义请求日志"""
        print(f"[ACCESS] {self.client_address[0]} - {self.command} {self.path} {code}")

def run_server():
    """启动HTTP服务器"""
    server_address = ('', 5000)
    httpd = HTTPServer(server_address, SmartDetectionHTTPRequestHandler)
    
    print("=" * 60)
    print("APIKit Smart Detection Test Target")
    print("=" * 60)
    print("\nStarting server on http://localhost:5000")
    print("\nTest scenarios:")
    print("1. Normal access: http://localhost:5000/actuator (BLOCKED)")
    print("2. URL encoded: http://localhost:5000/%61%63%74%75%61%74%6f%72 (BYPASS)")
    print("3. Safe endpoint: http://localhost:5000/test (OK)")
    print("\nNote: This target simulates WAF behavior:")
    print("- WAF checks raw URL (not decoded)")
    print("- Backend processes decoded URL")
    print("- URL encoding bypasses WAF but reaches backend")
    print("\n" + "=" * 60 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        httpd.server_close()

if __name__ == '__main__':
    run_server()