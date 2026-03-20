#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单靶场 - 用于验证APIKit智能检测功能
模拟WAF拦截和URL编码绕过场景
"""

from flask import Flask, request, jsonify
import re

app = Flask(__name__)

# 存储原始URL的线程本地变量
from threading import local
thread_local = local()

# 模拟的WAF规则 - 拦截敏感路径
WAF_RULES = [
    r'/actuator',
    r'/mappings',
    r'/health',
    r'/env',
    r'/configprops',
    r'/beans'
]

class RawURIMiddleware:
    """WSGI中间件，捕获原始的URL路径"""
    def __init__(self, app):
        self.app = app
    
    def __call__(self, environ, start_response):
        # 保存原始的URL路径（未解码）
        thread_local.raw_uri = environ.get('PATH_INFO', '')
        thread_local.query_string = environ.get('QUERY_STRING', '')
        return self.app(environ, start_response)

# 应用中间件
app.wsgi_app = RawURIMiddleware(app.wsgi_app)

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

@app.before_request
def waf_check():
    """
    模拟WAF检测
    - 对原始路径进行检测（不解码）
    - 如果匹配敏感路径，返回403
    - URL编码后的路径不会被检测到
    """
    # 获取原始URL（未解码）
    raw_uri = getattr(thread_local, 'raw_uri', request.path)
    
    # WAF只检测原始路径，不解码
    for rule in WAF_RULES:
        if re.search(rule, raw_uri):
            print(f"[WAF] Blocked request to: {raw_uri}")
            return jsonify({
                "error": "Access Denied",
                "message": "WAF blocked this request",
                "path": raw_uri
            }), 403
    
    return None

@app.route('/')
def index():
    """首页"""
    return jsonify({
        "message": "Welcome to APIKit Test Target",
        "description": "This is a simple target for testing smart detection",
        "endpoints": [
            "/actuator - Simulated Spring Boot Actuator (blocked by WAF)",
            "/mappings - API mappings (blocked by WAF)",
            "/health - Health check (blocked by WAF)"
        ]
    })

@app.route('/actuator')
def actuator():
    """模拟Spring Boot Actuator端点"""
    print(f"[ACCESS] /actuator accessed (should be blocked by WAF)")
    return jsonify(ACTUATOR_DATA)

@app.route('/actuator/mappings')
def mappings():
    """模拟mappings端点"""
    print(f"[ACCESS] /actuator/mappings accessed (should be blocked by WAF)")
    return jsonify(MAPPINGS_DATA)

@app.route('/actuator/health')
def health():
    """模拟health端点"""
    print(f"[ACCESS] /actuator/health accessed (should be blocked by WAF)")
    return jsonify({
        "status": "UP"
    })

@app.route('/actuator/env')
def env():
    """模拟env端点"""
    print(f"[ACCESS] /actuator/env accessed (should be blocked by WAF)")
    return jsonify({
        "activeProfiles": ["dev"],
        "propertySources": []
    })

@app.route('/test')
def test():
    """测试端点 - 不被拦截"""
    print(f"[ACCESS] /test accessed (not blocked)")
    return jsonify({
        "message": "Test endpoint - not blocked by WAF"
    })

@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({
        "error": "Not Found",
        "message": "The requested resource was not found"
    }), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """405错误处理"""
    return jsonify({
        "error": "Method Not Allowed",
        "message": "The method is not allowed for the requested URL"
    }), 405

if __name__ == '__main__':
    print("=" * 60)
    print("APIKit Smart Detection Test Target")
    print("=" * 60)
    print("\nStarting server on http://localhost:5000")
    print("\nTest scenarios:")
    print("1. Normal access: http://localhost:5000/actuator (BLOCKED)")
    print("2. URL encoded: http://localhost:5000/%61%63%74%75%61%74%6f%72 (BYPASS)")
    print("3. Safe endpoint: http://localhost:5000/test (OK)")
    print("\n" + "=" * 60 + "\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)