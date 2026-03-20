#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF代理服务器 - 模拟WAF拦截
拦截敏感路径，但允许URL编码的请求通过
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import re
import socket
import urllib.parse

# 模拟的WAF规则 - 拦截敏感路径（原始路径，不解码）
WAF_RULES = [
    r'/actuator',
    r'/mappings',
    r'/health',
    r'/env',
    r'/configprops',
    r'/beans'
]

class WAFHTTPRequestHandler(BaseHTTPRequestHandler):
    """WAF HTTP请求处理器"""
    
    def log_message(self, format, *args):
        """自定义日志输出"""
        print(f"[WAF] {format % args}")
    
    def send_json_response(self, data, status_code=200):
        """发送JSON响应"""
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        import json
        self.wfile.write(json.dumps(data).encode('utf-8'))
    
    def check_waf(self, raw_path):
        """
        WAF检测
        - 检查原始路径（不解码）
        - 如果匹配敏感路径，返回True
        - URL编码后的路径不会被检测到
        """
        for rule in WAF_RULES:
            if re.search(rule, raw_path):
                print(f"[WAF] BLOCKED: {raw_path}")
                return True
        return False
    
    def forward_request(self, request_data):
        """转发请求到后端服务器"""
        try:
            # 连接到后端服务器
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('localhost', 5001))
            
            # 转发请求
            sock.send(request_data)
            
            # 接收响应
            response_data = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response_data += chunk
            
            sock.close()
            return response_data
        except Exception as e:
            print(f"[WAF] Error forwarding request: {e}")
            return None
    
    def do_GET(self):
        """处理GET请求"""
        # 获取原始路径（不解码）
        raw_path = self.path.split('?')[0]
        
        # WAF检测
        # 如果路径是URL编码的，WAF无法识别敏感路径
        # 如果路径是原始的，WAF可以识别并拦截
        if self.check_waf(raw_path):
            self.send_json_response({
                "error": "Access Denied",
                "message": "WAF blocked this request",
                "path": raw_path
            }, 403)
            return
        
        # WAF允许通过，转发到后端
        print(f"[WAF] ALLOWED: {raw_path} - forwarding to backend")
        
        # 构建转发请求
        request_line = f"GET {self.path} HTTP/1.1\r\n"
        headers = []
        for header, value in self.headers.items():
            headers.append(f"{header}: {value}")
        
        request_data = (request_line + "\r\n".join(headers) + "\r\n\r\n").encode()
        
        # 转发请求
        response_data = self.forward_request(request_data)
        
        if response_data:
            # 解析响应
            response_str = response_data.decode('utf-8', errors='ignore')
            lines = response_str.split('\r\n')
            
            # 发送响应
            status_line = lines[0]
            status_code = int(status_line.split()[1])
            
            self.send_response(status_code)
            
            # 发送响应头
            i = 1
            while i < len(lines):
                if lines[i] == '':
                    break
                header_parts = lines[i].split(': ', 1)
                if len(header_parts) == 2:
                    self.send_header(header_parts[0], header_parts[1])
                i += 1
            
            self.end_headers()
            
            # 发送响应体
            body = '\r\n'.join(lines[i+1:])
            self.wfile.write(body.encode('utf-8'))
        else:
            self.send_json_response({
                "error": "Bad Gateway",
                "message": "Failed to connect to backend"
            }, 502)
    
    def log_request(self, code='-', size='-'):
        """自定义请求日志"""
        print(f"[WAF] {self.client_address[0]} - {self.command} {self.path} {code}")

def run_waf_server():
    """启动WAF服务器"""
    server_address = ('', 5000)
    httpd = HTTPServer(server_address, WAFHTTPRequestHandler)
    
    print("=" * 60)
    print("WAF Proxy Server")
    print("=" * 60)
    print("\nStarting WAF server on http://localhost:5000")
    print("Backend server: http://localhost:5001")
    print("\nWAF Rules:")
    for rule in WAF_RULES:
        print(f"  - {rule}")
    print("\nBehavior:")
    print("- WAF checks raw URL (not decoded)")
    print("- URL encoded requests bypass WAF")
    print("- Backend processes decoded URL")
    print("\nTest scenarios:")
    print("1. Normal access: http://localhost:5000/actuator (BLOCKED)")
    print("2. URL encoded: http://localhost:5000/%61%63%74%75%61%74%6f%72 (BYPASS)")
    print("3. Safe endpoint: http://localhost:5000/test (OK)")
    print("\n" + "=" * 60 + "\n")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWAF server stopped.")
        httpd.server_close()

if __name__ == '__main__':
    run_waf_server()