package burp.ui;

import burp.IHttpRequestResponse;

class RedirectEntry {
    final int id;
    final String method;
    final String url;
    final String parameter;
    final String statusCode;
    final boolean isVulnerable;
    final IHttpRequestResponse requestResponse;

    RedirectEntry(int id, String method, String url, String parameter,
                  String statusCode, boolean isVulnerable, IHttpRequestResponse requestResponse) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.parameter = parameter;
        this.statusCode = statusCode;
        this.isVulnerable = isVulnerable;
        this.requestResponse = requestResponse;
    }
}
