package burp.ui;

import burp.IHttpRequestResponse;

public class PermUIEntry {
    final int id;
    final String method;
    final String url;
    final String originalength;
    final String lowlength;
    final String nolength;
    final String isSuccess;
    IHttpRequestResponse requestResponse;
    IHttpRequestResponse lowRequestResponse;
    IHttpRequestResponse noRequestResponse;

    public PermUIEntry(int id, String method, String url, String originalength, String lowlength, String nolength, String isSuccess, IHttpRequestResponse requestResponse, IHttpRequestResponse lowRequestResponse, IHttpRequestResponse noRequestResponse) {
        this.id = id;
        this.method = method;
        this.url = url;
        this.originalength = originalength;
        this.lowlength = lowlength;
        this.nolength = nolength;
        this.isSuccess = isSuccess;
        this.requestResponse = requestResponse;
        this.lowRequestResponse = lowRequestResponse;
        this.noRequestResponse = noRequestResponse;
    }
}
