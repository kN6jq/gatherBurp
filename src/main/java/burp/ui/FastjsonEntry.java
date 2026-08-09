package burp.ui;

import burp.IHttpRequestResponse;

class FastjsonEntry {
    final int id;
    final String extensionMethod;
    final String url;
    final String status;
    final String res;
    final String req;
    final IHttpRequestResponse requestResponse;

    FastjsonEntry(int id, String extensionMethod, String url, String status, String res, String req, IHttpRequestResponse requestResponse) {
        this.id = id;
        this.extensionMethod = extensionMethod;
        this.url = url;
        this.status = status;
        this.res = res;
        this.req = req;
        this.requestResponse = requestResponse;
    }
}
