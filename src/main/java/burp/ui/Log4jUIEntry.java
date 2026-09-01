package burp.ui;

import burp.IHttpRequestResponse;

/** Log4j 模块结果表格条目：length 为响应长度，res 为检测结论标识。 */
public class Log4jUIEntry {
    final int id;
    final String extensionMethod;
    final String url;
    final String length;
    final String res;

    final IHttpRequestResponse requestResponse;

    public Log4jUIEntry(int id, String extensionMethod, String url, String res, String length, IHttpRequestResponse requestResponse) {
        this.id = id;
        this.extensionMethod = extensionMethod;
        this.url = url;
        this.length = length;
        this.res = res;
        this.requestResponse = requestResponse;
    }
}
