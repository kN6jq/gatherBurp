package burp.ui;

import burp.IHttpRequestResponse;

/** 目录穿越模块结果表格条目：length 为响应长度。 */
class AuthEntry {
    final int id;
    final String method;
    final String url;
    final String status;
    final String length;
    final IHttpRequestResponse requestResponse;

    AuthEntry(int id, String method, String url, String status, String length, IHttpRequestResponse requestResponse) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.status = status;
        this.length = length;
        this.requestResponse = requestResponse;
    }
}
