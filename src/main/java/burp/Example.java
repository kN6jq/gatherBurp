package burp;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @Author Xm17
 * @Date 2024-06-23 10:27
 */
public class Example {
    public static void main(String[] args) {
        String request = "GET /vulnerabilities/sqli/?id=123&Submit=Submit HTTP/1.1\r\n" +
                "Host: 192.168.11.6:801\r\n" +
                "Upgrade-Insecure-Requests: 1\r\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.118 Safari/537.36\r\n" +
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n" +
                "Referer: http://192.168.11.6:801/vulnerabilities/sqli/?id=1&Submit=Submit\r\n" +
                "Accept-Encoding: gzip, deflate, br\r\n" +
                "Accept-Language: zh-CN,zh;q=0.9\r\n" +
                "Cookie: vue_admin_template_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwiZXhwIjoxNzE5MDY4MzM0LCJlbWFpbCI6IiJ9.GpiGPvleDm8Sd6beJttdIbAHYkHb4SNU6MLNu8XyEVI; sidebarStatus=1; PHPSESSID=gabeni928ahij9gut8f2o6b4a0; security=low\r\n" +
                "Connection: close\r\n\r\n";

        // 定义正则表达式，匹配 ? 及其后面的内容
        String regex = "\\?[^\\s]*";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(request);

        // 删除 ? 后面的内容（查询参数部分）
        if (matcher.find()) {
            request = request.replace(matcher.group(), "");
        }

        System.out.println("Modified request:");
        System.out.println(request);
    }
}
