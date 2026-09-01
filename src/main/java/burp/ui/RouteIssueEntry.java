package burp.ui;

import burp.IHttpRequestResponse;

/** 目录探测模块命中问题表格条目（经 LruSet 去重后入表）。 */
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
