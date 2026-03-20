#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
后端服务器 - 模拟Spring Boot Actuator
不进行WAF检测，只处理业务逻辑
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from urllib.parse import unquote

# 模拟的Spring Boot Actuator端点数据
ACTUATOR_DATA = {
    "_links": {
        "self": {
            "href": "http://localhost:5001/actuator"
        },
        "mappings": {
            "href": "http://localhost:5001/actuator/mappings"
        },
        "health": {
            "href": "http://localhost:5001/actuator/health"
        },
        "env": {
            "href": "http://localhost:5001/actuator/env"
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

class BackendHTTPRequestHandler(BaseHTTPRequestHandler):
    """后端HTTP请求处理器"""
    
    def log_message(self, format, *args):
        """自定义日志输出"""
        print(f"[BACKEND] {format % args}")
    
    def send_json_response(self, data, status_code=200):
        """发送JSON响应"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def do_GET(self):
        """处理GET请求"""
        # 解码路径（后端会解码URL）
        decoded_path = unquote(self.path.split('?')[0])
        
        # 路由处理
        if decoded_path == '/':
            self.send_json_response({
                "message": "Backend Server - Spring Boot Actuator Simulation",
                "endpoints": [
                    "/actuator",
                    "/actuator/mappings",
                    "/actuator/health",
                    "/actuator/env"
                ]
            })
        elif decoded_path == '/actuator':
            print(f"[BACKEND] /actuator accessed")
            self.send_json_response(ACTUATOR_DATA)
        elif decoded_path == '/actuator/mappings':
            print(f"[BACKEND] /actuator/mappings accessed")
            self.send_json_response(MAPPINGS_DATA)
        elif decoded_path == '/actuator/health':
            print(f"[BACKEND] /actuator/health accessed")
            self.send_json_response({
                "status": "UP"
            })
        elif decoded_path == '/actuator/env':
            print(f"[BACKEND] /actuator/env accessed")
            self.send_json_response({
                "activeProfiles": ["dev"],
                "propertySources": []
            })
        elif decoded_path == '/test':
            print(f"[BACKEND] /test accessed")
            self.send_json_response({
                "message": "Test endpoint"
            })
        else:
            self.send_json_response({
                "error": "Not Found",
                "path": decoded_path
            }, 404)
    
    def log_request(self, code='-', size='-'):
        """自定义请求日志"""
        print(f"[BACKEND] {self.client_address[0]} - {self.command} {self.path} {code}")

def run_backend_server():
    """启动后端服务器"""
    server_address = ('', 5001)
    httpd = HTTPServer(server_address, BackendHTTPRequestHandler)
    
    print("=" * 60)
    print("Backend Server - Spring Boot Actuator Simulation")
    print("=" * 60)
    print("\nStarting backend server on http://localhost:5001")
    print("\nNote: This server does NOT have WAF protection")
    print("All requests will be processed normally")
    print("\n" + "=" * 60 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBackend server stopped.")
        httpd.server_close()

if __name__ == '__main__':
    run_backend_server()