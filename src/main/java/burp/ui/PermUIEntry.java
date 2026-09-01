package burp.ui;

import burp.IHttpRequestResponse;

/** 越权模块三态对比结果表格条目：originalength/lowlength/nolength 为原始/低权限/无权限
 *  三种请求的响应长度，isSuccess 为 i18n 判定文本。 */
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
