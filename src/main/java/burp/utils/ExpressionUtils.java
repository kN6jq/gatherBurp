package burp.utils;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 路由规则表达式求值工具：解析 code="200" && body="xxx" 形式的规则，
 *  对绑定的请求/响应求值；表达式变量支持 code/url/headers/body/title。 */
public class ExpressionUtils {
    private IHttpRequestResponse baseRequestResponse;
    private IResponseInfo iResponseInfo;

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

    /** 从响应体中提取 HTML title。 */
    public String getTitle(){
        byte[] responseBytes = this.baseRequestResponse.getResponse();
        int bodyOffset = this.iResponseInfo.getBodyOffset();
        byte[] responseBody = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);
        String decodedString = new String(responseBody, StandardCharsets.UTF_8);
        String title = Utils.extractTitle(decodedString);
        return title;
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
            key = Utils.callbacks.getHelpers().bytesToString(getBody());
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
            key = Utils.callbacks.getHelpers().bytesToString(getBody());
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
     * 轻量语法校验：括号配对且至少含一个比较条件。供规则保存前反馈，不参与运行时求值。
     */
    public static boolean isValidExpression(String expression) {
        if (expression == null || expression.trim().isEmpty()) {
            return false;
        }
        int depth = 0;
        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth < 0) {
                    return false;
                }
            }
        }
        return depth == 0 && expression.contains("=");
    }

    /** 表达式求值入口：trim 后递归处理复合/括号/逻辑运算。 */
    public boolean process(String expression) {
        expression = expression.trim();
        return evaluateExpression(expression);
    }

    /** 表达式求值核心：简单表达式直接处理，复合表达式递归。 */
    private boolean evaluateExpression(String expression) {
        // 如果是简单表达式,直接处理
        if (!isCompoundExpression(expression)) {
            return processSingle(expression);
        }

        // 处理带括号的表达式
        if (expression.contains("(")) {
            return handleBrackets(expression);
        }

        // 处理AND/OR运算
        if (expression.contains("&&") || expression.contains("||")) {
            return handleLogicalOperators(expression);
        }

        return processSingle(expression);
    }

    /** 检查是否为复合表达式（含 &&/||/括号）。 */
    private boolean isCompoundExpression(String expression) {
        return expression.contains("&&") ||
                expression.contains("||") ||
                expression.contains("(") ||
                expression.contains(")");
    }

    /** 处理带括号的表达式：递归求值括号内子表达式并替换。 */
    private boolean handleBrackets(String expression) {
        Stack<Integer> stack = new Stack<>();
        int start = -1;

        for (int i = 0; i < expression.length(); i++) {
            char c = expression.charAt(i);
            if (c == '(') {
                if (stack.isEmpty()) {
                    start = i;
                }
                stack.push(i);
            } else if (c == ')') {
                // 括号不配对：合法表达式已被 isValidExpression 拦截，运行时保守判 false 而不是抛异常
                if (stack.isEmpty()) {
                    return false;
                }
                stack.pop();
                if (stack.isEmpty()) {
                    // 找到匹配的括号对
                    String before = expression.substring(0, start).trim();
                    String middle = expression.substring(start + 1, i).trim();
                    String after = expression.substring(i + 1).trim();

                    // 递归处理括号内的表达式
                    boolean middleResult = evaluateExpression(middle);

                    // 构造新的表达式并继续处理
                    String newExpression;
                    if (before.isEmpty() && after.isEmpty()) {
                        return middleResult;
                    } else if (before.isEmpty()) {
                        newExpression = middleResult + " " + after;
                    } else if (after.isEmpty()) {
                        newExpression = before + " " + middleResult;
                    } else {
                        newExpression = before + " " + middleResult + " " + after;
                    }
                    return evaluateExpression(newExpression);
                }
            }
        }
        return false;
    }

    /** 处理逻辑运算符（&& 短路与 / || 短路或）。 */
    private boolean handleLogicalOperators(String expression) {
        // 优先处理AND运算
        if (expression.contains("&&")) {
            String[] parts = expression.split("&&", 2);
            boolean leftResult = evaluateExpression(parts[0].trim());
            // 短路运算
            if (!leftResult) return false;
            return leftResult && evaluateExpression(parts[1].trim());
        }

        // 处理OR运算
        if (expression.contains("||")) {
            String[] parts = expression.split("\\|\\|", 2);
            boolean leftResult = evaluateExpression(parts[0].trim());
            // 短路运算
            if (leftResult) return true;
            return leftResult || evaluateExpression(parts[1].trim());
        }

        return processSingle(expression);
    }

    /** 处理单个条件表达式：按 = 或 != 操作符拆分并调用 eq/neq。 */
    private boolean processSingle(String expression) {
        expression = expression.trim();
        if (expression.equals("true")) return true;
        if (expression.equals("false")) return false;

        // 使用正则表达式匹配操作符
        Pattern pattern = Pattern.compile("(?<!\\!)=|!=");
        Matcher matcher = pattern.matcher(expression);

        if (matcher.find()) {
            String operator = matcher.group();
            String[] parts = expression.split(Pattern.quote(operator), 2);
            if (parts.length != 2) return false;

            String key = parts[0].trim();
            String value = parts[1].trim();

            // 根据操作符调用相应的比较方法
            if (operator.equals("=")) {
                return eq(key, value);
            } else if (operator.equals("!=")) {
                return neq(key, value);
            }
        }
        return false;
    }
}