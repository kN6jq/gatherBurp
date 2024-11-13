package burp.utils;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Stack;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExpressionUtils {
    private IHttpRequestResponse baseRequestResponse;
    private IResponseInfo iResponseInfo;

    public ExpressionUtils() {
    }

    public ExpressionUtils(IHttpRequestResponse baseRequestResponse) {
        this.baseRequestResponse = baseRequestResponse;
        this.iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(this.baseRequestResponse.getResponse());
    }

    // 获取请求url
    public String getUrl(){
        IRequestInfo iRequestInfo = Utils.callbacks.getHelpers().analyzeRequest(this.baseRequestResponse);
        return iRequestInfo.getUrl().toString();
    }

    // 获取响应码
    public int getCode(){
        return this.iResponseInfo.getStatusCode();
    }

    // 获取响应头列表
    public List<String> getHeaders(){
        return this.iResponseInfo.getHeaders();
    }

    // 获取响应体
    public byte[] getBody(){
        byte[] responseBytes = this.baseRequestResponse.getResponse();
        int bodyOffset = this.iResponseInfo.getBodyOffset();
        byte[] responseBody = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);

        // 将 responseBody 拆分成多个部分
        List<byte[]> parts = new ArrayList<>();
        int chunkSize = 1000; // 每个部分的大小
        for (int i = 0; i < responseBody.length; i += chunkSize) {
            int end = Math.min(responseBody.length, i + chunkSize);
            byte[] part = Arrays.copyOfRange(responseBody, i, end);
            parts.add(part);
        }

        // 拼接所有部分
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            try {
                outputStream.write(part);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return outputStream.toByteArray();
    }

    // 获取title
    public String getTitle(){
        byte[] responseBytes = this.baseRequestResponse.getResponse();
        int bodyOffset = this.iResponseInfo.getBodyOffset();
        byte[] responseBody = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);
        String decodedString = new String(responseBody, StandardCharsets.UTF_8);
        String title = Utils.extractTitle(decodedString);
        return title;
    }

    // 相等或包含关系
    public boolean eq(String key, String value){
        // 去除前后空格
        key = key.trim();
        value = value.trim();

        if (key.equals("title")){
            key = getTitle();
        }else if (key.equals("code")) {
            key = String.valueOf(getCode());
        }else if (key.equals("headers")) {
            // 如果key在getHeaders()里面
            for (String header : getHeaders()) {
                if (header.contains(value)){
                    return true;
                }
            }
        }else if (key.equals("body")) {
            key = Utils.callbacks.getHelpers().bytesToString(getBody());
        }else {
            key = key.trim();
        }

        // 删除value两边的双引号
        value = Utils.RemoveQuotes(value);

        return key.equals(value) || key.contains(value);
    }

    // 不相等或不包含关系
    public boolean neq(String key, String value){
        // 去除前后空格
        key = key.trim();
        value = value.trim();

        if (key.equals("title")){
            key = getTitle();
        }else if (key.equals("code")) {
            key = String.valueOf(getCode());
        }else if (key.equals("headers")) {
            // 如果key在getHeaders()里面
            for (String header : getHeaders()) {
                if (header.contains(value)){
                    return false;  // 如果找到包含的值，返回false
                }
            }
            return true;  // 没找到包含的值，返回true
        }else if (key.equals("body")) {
            key = Utils.callbacks.getHelpers().bytesToString(getBody());
        }

        value = Utils.RemoveQuotes(value);
        return !key.equals(value) && !key.contains(value);
    }

    // 处理表达式的入口方法
    public boolean process(String expression) {
        expression = expression.trim();
        return evaluateExpression(expression);
    }

    // 表达式求值的核心方法
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

    // 检查是否是复合表达式
    private boolean isCompoundExpression(String expression) {
        return expression.contains("&&") ||
                expression.contains("||") ||
                expression.contains("(") ||
                expression.contains(")");
    }

    // 处理带括号的表达式
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

    // 处理逻辑运算符
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

    // 处理单个条件表达式
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