package burp.ui;

import burp.IHttpRequestResponse;

public class RouteIssueEntry {
    final int id;
    final String issueName;
    final String url;
    final String status;
    final IHttpRequestResponse requestResponse;

    public RouteIssueEntry(int id, String issueName, String url, String status, IHttpRequestResponse requestResponse) {
        this.id = id;
        this.issueName = issueName;
        this.url = url;
        this.status = status;
        this.requestResponse = requestResponse;
    }
}
