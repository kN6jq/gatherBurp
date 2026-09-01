package burp.bean;

/** 目录穿越探测请求：method + 变异 path + 附加头，由 prefix/suffix 规则批量生成。 */
public class AuthBean {
    private String method;
    private String path;
    private String headers;

    public AuthBean() {
    }

    public AuthBean(String method, String path, String headers) {
        this.method = method;
        this.path = path;
        this.headers = headers;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getHeaders() {
        return headers;
    }

    public void setHeaders(String headers) {
        this.headers = headers;
    }
}
