package burp.utils;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** 路由规则表达式求值工具：解析 code="200" && body="xxx" 形式的规则，
 *  对绑定的请求/响应求值；表达式变量支持 code/headers/body/title。
 *  语法为递归下降：|| 最低优先级、&& 次之、括号与单条件最高；
 *  词法扫描感知双引号，引号内的 = && || ( ) 不参与结构拆分。 */
public class ExpressionUtils {
    private IHttpRequestResponse baseRequestResponse;
    private IResponseInfo iResponseInfo;
    // 同一实例会被同一条表达式的多个 body/title 条件求值，解码一次后缓存
    private String cachedBody;
    private String cachedTitle;

    public ExpressionUtils() {
    }

    public ExpressionUtils(IHttpRequestResponse baseRequestResponse) {
        this.baseRequestResponse = baseRequestResponse;
        this.iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(this.baseRequestResponse.getResponse());
    }

    /** 获取请求 URL。 */
    public String getUrl(){
        IRequestInfo iRequestInfo = Utils.callbacks.getHelpers().analyzeRequest(this.baseRequestResponse);
        return iRequestInfo.getUrl().toString();
    }

    /** 获取响应状态码。 */
    public int getCode(){
        return this.iResponseInfo.getStatusCode();
    }

    /** 获取响应头列表。 */
    public List<String> getHeaders(){
        return this.iResponseInfo.getHeaders();
    }

    /** 获取响应体字节数组。 */
    public byte[] getBody(){
        byte[] responseBytes = this.baseRequestResponse.getResponse();
        int bodyOffset = this.iResponseInfo.getBodyOffset();
        return Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);
    }

    /** 响应体字符串（懒解码缓存）。 */
    private String bodyText() {
        if (cachedBody == null) {
            cachedBody = Utils.callbacks.getHelpers().bytesToString(getBody());
        }
        return cachedBody;
    }

    /** 从响应体中提取 HTML title（懒解码缓存）。 */
    public String getTitle(){
        if (cachedTitle == null) {
            byte[] responseBytes = this.baseRequestResponse.getResponse();
            int bodyOffset = this.iResponseInfo.getBodyOffset();
            byte[] responseBody = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);
            cachedTitle = Utils.extractTitle(new String(responseBody, StandardCharsets.UTF_8));
        }
        return cachedTitle;
    }

    /** 相等或包含关系判定（code 精确匹配，headers/body 模糊包含）。 */
    public boolean eq(String key, String value){
        // 去除前后空格
        key = key.trim();
        value = value.trim();
        String field = key; // 保留原始字段名，code 等枚举型字段需要精确比较

        if (key.equals("title")){
            key = getTitle();
        }else if (key.equals("code")) {
            key = String.valueOf(getCode());
        }else if (key.equals("headers")) {
            // 空 needle 时 contains("") 恒真，需与 compareValue 的空值保护保持同一口径
            if (value.isEmpty()) {
                return false;
            }
            // 如果value包含在任意响应头中
            for (String header : getHeaders()) {
                if (header.contains(value)){
                    return true;
                }
            }
            return false;
        }else if (key.equals("body")) {
            key = bodyText();
        }else {
            key = key.trim();
        }

        // 删除value两边的双引号
        value = Utils.RemoveQuotes(value);

        return compareValue(field, key, value);
    }

    /** 不相等或不包含关系判定（eq 的取反）。 */
    public boolean neq(String key, String value){
        // 去除前后空格
        key = key.trim();
        value = value.trim();
        String field = key;

        if (key.equals("title")){
            key = getTitle();
        }else if (key.equals("code")) {
            key = String.valueOf(getCode());
        }else if (key.equals("headers")) {
            // 空 needle 时 contains("") 恒真（即 neq 恒假），需与 eq 分支保持同一口径
            if (value.isEmpty()) {
                return true;
            }
            // 如果value不包含在任意响应头中
            for (String header : getHeaders()) {
                if (header.contains(value)){
                    return false;
                }
            }
            return true;
        }else if (key.equals("body")) {
            key = bodyText();
        }

        value = Utils.RemoveQuotes(value);
        return !compareValue(field, key, value);
    }

    /**
     * 字段值与期望值的比较语义。
     * code 是枚举型取值：只做精确相等——contains 会让 code="200" 命中 2001/1200 等状态码造成误报。
     * 其余字段保持"相等或包含"；空串 needle 对 contains 恒真，同样封堵（body="" 只匹配空 body）。
     */
    static boolean compareValue(String field, String actual, String expected) {
        if ("code".equals(field)) {
            return actual.equals(expected);
        }
        return actual.equals(expected) || (!expected.isEmpty() && actual.contains(expected));
    }

    /**
     * 轻量语法校验：括号配对（引号内不计）、无未闭合引号且至少含一个引号外比较符。
     * 供规则保存前反馈，不参与运行时求值。
     */
    public static boolean isValidExpression(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            return false;
        }
        int depth = 0;
        boolean inQuotes = false;
        boolean hasCondition = false;
        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (!inQuotes) {
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                    if (depth < 0) {
                        return false;
                    }
                } else if (c == '=' && (i == 0 || expression.charAt(i - 1) != '=')
                        && (i + 1 >= expression.length() || expression.charAt(i + 1) != '=')) {
                    hasCondition = true;
                }
            }
        }
        return depth == 0 && !inQuotes && hasCondition;
    }

    /** 表达式求值入口：标准优先级递归下降（|| 最低）。 */
    public boolean process(String expression) {
        if (expression == null) {
            return false;
        }
        return parseOr(expression.trim());
    }

    /** || 层：任一子表达式为真即真（短路）。 */
    private boolean parseOr(String expr) {
        List<String> parts = splitTopLevel(expr, "||");
        if (parts.size() > 1) {
            for (String part : parts) {
                if (parseAnd(part.trim())) {
                    return true;
                }
            }
            return false;
        }
        return parseAnd(expr);
    }

    /** && 层：全部子表达式为真才真（短路）。 */
    private boolean parseAnd(String expr) {
        List<String> parts = splitTopLevel(expr, "&&");
        if (parts.size() > 1) {
            for (String part : parts) {
                if (!parsePrimary(part.trim())) {
                    return false;
                }
            }
            return true;
        }
        return parsePrimary(expr);
    }

    /** 原子层：整体被一对括号包裹则剥壳递归，否则按单条件处理。 */
    private boolean parsePrimary(String expr) {
        expr = expr.trim();
        if (expr.isEmpty()) {
            return false;
        }
        if (isFullyWrapped(expr)) {
            return parseOr(expr.substring(1, expr.length() - 1).trim());
        }
        return processSingle(expr);
    }

    /** 处理单个条件表达式：引号外定位首个 = / != 操作符并调用 eq/neq。 */
    private boolean processSingle(String expression) {
        expression = expression.trim();
        if (expression.equals("true")) return true;
        if (expression.equals("false")) return false;

        int opIndex = findTopLevelOperator(expression);
        if (opIndex < 0) {
            return false;
        }
        boolean negated = expression.charAt(opIndex) == '!';
        String key = expression.substring(0, opIndex).trim();
        String value = expression.substring(opIndex + (negated ? 2 : 1)).trim();
        return negated ? neq(key, value) : eq(key, value);
    }

    /** 引号外首个比较符下标（!= 返回 ! 的位置），找不到返回 -1。 */
    static int findTopLevelOperator(String expr) {
        boolean inQuotes = false;
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (!inQuotes && c == '=') {
                boolean isDoubleEquals = i > 0 && expr.charAt(i - 1) == '=';
                if (isDoubleEquals) {
                    continue;
                }
                return (i > 0 && expr.charAt(i - 1) == '!') ? i - 1 : i;
            }
        }
        return -1;
    }

    /** 按顶层分隔符拆分：双引号字符串与括号组内部不拆分。 */
    static List<String> splitTopLevel(String expr, String delimiter) {
        List<String> parts = new ArrayList<>();
        boolean inQuotes = false;
        int depth = 0;
        int last = 0;
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (!inQuotes) {
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                } else if (depth == 0 && startsAt(expr, i, delimiter)) {
                    parts.add(expr.substring(last, i));
                    i += delimiter.length() - 1;
                    last = i + 1;
                }
            }
        }
        parts.add(expr.substring(last));
        return parts;
    }

    /** 表达式是否整体被一对括号包裹（首个 '(' 的配对 ')' 恰为末字符）。 */
    static boolean isFullyWrapped(String expr) {
        if (!expr.startsWith("(") || !expr.endsWith(")")) {
            return false;
        }
        int depth = 0;
        boolean inQuotes = false;
        for (int i = 0; i < expr.length(); i++) {
            char c = expr.charAt(i);
            if (c == '"') {
                inQuotes = !inQuotes;
            } else if (!inQuotes) {
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                    if (depth == 0) {
                        return i == expr.length() - 1;
                    }
                }
            }
        }
        return false;
    }

    private static boolean startsAt(String expr, int index, String token) {
        return expr.startsWith(token, index);
    }
}
