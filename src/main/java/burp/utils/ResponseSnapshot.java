package burp.utils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** SQL 证据逻辑用的最小不可变响应快照（状态码/头/体/长度/耗时/WAF/错误页标记）。 */
public final class ResponseSnapshot {
    private final int statusCode;
    private final List<String> headers;
    private final String body;
    private final int bodyLength;
    private final long responseTimeMs;
    private final boolean wafBlocked;
    private final boolean defaultErrorPage;

    public ResponseSnapshot(int statusCode, List<String> headers, String body,
                            int bodyLength, long responseTimeMs,
                            boolean wafBlocked, boolean defaultErrorPage) {
        this.statusCode = statusCode;
        this.headers = headers == null
                ? Collections.<String>emptyList()
                : Collections.unmodifiableList(new ArrayList<>(headers));
        this.body = body == null ? "" : body;
        this.bodyLength = Math.max(0, bodyLength);
        this.responseTimeMs = Math.max(0L, responseTimeMs);
        this.wafBlocked = wafBlocked;
        this.defaultErrorPage = defaultErrorPage;
    }

    public int getStatusCode() { return statusCode; }
    public List<String> getHeaders() { return headers; }
    public String getBody() { return body; }
    public int getBodyLength() { return bodyLength; }
    public long getResponseTimeMs() { return responseTimeMs; }
    public boolean isWafBlocked() { return wafBlocked; }
    public boolean isDefaultErrorPage() { return defaultErrorPage; }
}
