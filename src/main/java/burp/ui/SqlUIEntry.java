package burp.ui;

import burp.IHttpRequestResponse;

public class SqlUIEntry {
    final int id;
    final String method;
    final String url;
    final int length;
    final String status;
    final IHttpRequestResponse requestResponse;

    public SqlUIEntry(int id, String method, String url, int length, String status, IHttpRequestResponse requestResponse) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.length = length;
        this.status = status;
        this.requestResponse = requestResponse;
    }
}
