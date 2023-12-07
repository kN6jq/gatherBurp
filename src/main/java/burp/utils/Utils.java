package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import org.apache.commons.io.FileUtils;
import org.springframework.util.DigestUtils;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URLEncoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class Utils {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static String name = "gatherBurp";
    public static String version = "1.0.1";
    public static String author = "Xm17";
    public static String workdir = System.getProperty("user.home") + "/.gather/";

    public static String writeReqFile(IHttpRequestResponse message) {
        try {
            String host = message.getHttpService().getHost();

            SimpleDateFormat simpleDateFormat =
                    new SimpleDateFormat("MMdd-HHmmss");
            String timeString = simpleDateFormat.format(new Date());
            String filename = host + "." + timeString + ".req";

            File requestFile = new File(workdir, filename);
            FileUtils.writeByteArrayToFile(requestFile, message.getRequest());
            return requestFile.getAbsolutePath();
        } catch (IOException e) {
            Utils.stderr.println(e.getMessage());
            return null;
        }
    }

    public static List<String> getSuffix() {
        List<String> suffix = new ArrayList<>();
        suffix.add(".js");
        suffix.add(".css");
        suffix.add(".jpg");
        suffix.add(".png");
        suffix.add(".gif");
        suffix.add(".ico");
        suffix.add(".svg");
        suffix.add(".woff");
        suffix.add(".ttf");
        suffix.add(".eot");
        suffix.add(".woff2");
        suffix.add(".otf");
        suffix.add(".mp4");
        suffix.add(".mp3");
        suffix.add(".avi");
        suffix.add(".flv");
        suffix.add(".swf");
        suffix.add(".webp");
        suffix.add(".zip");
        suffix.add(".rar");
        suffix.add(".7z");
        suffix.add(".gz");
        suffix.add(".tar");
        suffix.add(".exe");
        suffix.add(".pdf");
        suffix.add(".doc");
        suffix.add(".docx");
        suffix.add(".xls");
        suffix.add(".xlsx");
        suffix.add(".ppt");
        suffix.add(".pptx");
        suffix.add(".txt");
        suffix.add(".xml");
        suffix.add(".apk");
        suffix.add(".ipa");
        suffix.add(".dmg");
        suffix.add(".iso");
        suffix.add(".img");
        suffix.add(".torrent");
        suffix.add(".jar");
        suffix.add(".war");
        suffix.add(".py");
        return suffix;
    }


    // 返回当前时间戳
    public static String getTimeNow() {
        return String.valueOf(System.currentTimeMillis() / 1000);
    }

    // 替换字符串中的特殊字符
    public static String ReplaceChar(String input) {
        // 使用正则表达式替换特殊字符
        return input.replaceAll("[\\n\\r]", "");
    }

    // 对字符串进行url编码
    public static String UrlEncode(String input) {
        return URLEncoder.encode(input);
    }

    // 对字符串进行MD5编码
    public static String MD5Encode(String input) {
        return DigestUtils.md5DigestAsHex(input.getBytes());
    }


}
