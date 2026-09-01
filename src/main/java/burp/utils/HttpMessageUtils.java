package burp.utils;

import java.util.List;

/**
 * HTTP 报文构建辅助：Burp 的 helpers.buildHttpMessage 只拼接头与体，
 * 不会更新 Content-Length。凡"复用原请求头 + 替换 body"的场景必须先调用
 * {@link #setContentLength}，否则目标按旧长度截断 body，payload 解析失败。
 */
public final class HttpMessageUtils {

    private HttpMessageUtils() {
    }

    /** 更新（或追加）headers 中的 Content-Length，大小写不敏感；纯函数便于单测。 */
    public static void setContentLength(List<String> headers, int bodyLength) {
        if (headers == null) {
            return;
        }
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            if (header != null && header.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                headers.set(i, "Content-Length: " + Math.max(0, bodyLength));
                return;
            }
        }
        headers.add("Content-Length: " + Math.max(0, bodyLength));
    }
}
