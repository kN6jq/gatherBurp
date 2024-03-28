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
        // 获取
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
        // 获取响应头的长度
        int bodyOffset = this.iResponseInfo.getBodyOffset();
        // 提取响应体
        byte[] responseBody = Arrays.copyOfRange(responseBytes, bodyOffset, responseBytes.length);
        String decodedString = new String(responseBody, StandardCharsets.UTF_8);
        String title = Utils.extractTitle(decodedString);
        // 对其进行utf-8编码
//        return Utils.Utf8Encode(title);
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

        if (key.equals(value) || key.contains(value)){
            return true;
        }else {
            return false;
        }
        // 使用正则表达式匹配
//        return key.matches(value);
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
                    return true;
                }
            }
        }else if (key.equals("body")) {
            key = Utils.callbacks.getHelpers().bytesToString(getBody());
        }else {
            key = key.trim();
        }
        key = key.trim();
        value = value.trim();
        if (!key.equals(value)){
            return true;
        }else {
            return false;
        }
        // 使用正则表达式匹配
//        return !key.matches(value);
    }

    // status_code="200" && (resp_body="\"swaggerVersion\"" || resp_body="\"location\"")
    // 判断语句中是否包含&& 或者 || 或者 ()
    // 多语句关系
    public boolean isExpression(String expression){
        return expression.contains("&&") || expression.contains("||") || expression.contains("(") || expression.contains(")");
    }

    // 处理入口类
    public boolean process(String expression){


        if (isExpression(expression)){
            // 多语句关系
            return processMulti(expression);
        }else {
            // 单语句关系
            return processSingle(expression);
        }
    }

    // 处理多语句关系
    private boolean processMulti(String expression) {
        if (expression.contains("(") && expression.contains(")")) {
            // 处理小括号内的逻辑表达式
            int startIndex = expression.indexOf("(");
            int endIndex = expression.indexOf(")");
            String subExpression = expression.substring(startIndex + 1, endIndex);
            // 递归调用process方法处理小括号内的表达式
            return process(subExpression);
        } else if (expression.contains("&&")){
            String[] split = expression.split("&&", 2);
            return processSingle(split[0]) && processSingle(split[1]);
        } else if (expression.contains("||")){
            String[] split = expression.split("\\|\\|", 2); // 使用"||"时需要转义
            return processSingle(split[0]) || processSingle(split[1]);
        } else {
            return processSingle(expression);
        }
    }

    // 处理单语句关系
    private boolean processSingle(String expression) {
        // 使用更精确的正则表达式匹配等于号和不等于号
        Pattern pattern = Pattern.compile("(?<!\\!)=|!=");
        Matcher matcher = pattern.matcher(expression);

        if (matcher.find()) {
            String operator = matcher.group(); // 获取匹配到的运算符
            String[] split = expression.split(Pattern.quote(operator), 2); // 在匹配到的运算符处分割字符串，限制分割次数为2

            if (operator.equals("=")) {
                return eq(split[0], split[1]);
            } else if (operator.equals("!=")) {
                return neq(split[0], split[1]);
            }
        }

        return false;
    }


}
