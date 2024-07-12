package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import cn.hutool.core.io.FileUtil;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Utils {
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static String name = "GatherBurp";
    public static String version = "1.1.0";
    public static String author = "Xm17";
    public static String workdir = System.getProperty("user.home") + "/.gather/";
    public static boolean isSelect = false;

    // 写req文件
    public static String writeReqFile(IHttpRequestResponse message) {
        String host = message.getHttpService().getHost();

        SimpleDateFormat simpleDateFormat =
                new SimpleDateFormat("MMdd-HHmmss");
        String timeString = simpleDateFormat.format(new Date());
        String filename = host + "." + timeString + ".req";

        File requestFile = new File(workdir, filename);
        FileUtil.writeBytes(message.getRequest(),requestFile);
        return requestFile.getAbsolutePath();
    }
    // 写入socks代理配置文件
    public static File SocksConfigFile(String filename) {
        return new File(workdir, filename);
    }



    // 删除后缀为req的缓存文件
    public static boolean deleteReqFile() {
        File file = new File(workdir);
        if (!file.exists()) {
            return false;
        }
        File[] files = file.listFiles();
        if (files == null) {
            return false;
        }
        for (File f : files) {
            if (f.getName().endsWith(".req")) {
                f.delete();
            }
        }
        return true;
    }

    // 获取后缀列表
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

    // 去除字符串两边的双引号
    public static String RemoveQuotes(String input) {
        // 去除字符串两边的双引号
        if (input.startsWith("\"") && input.endsWith("\"")) {
            input = input.substring(1, input.length() - 1);
        }

        return input;
    }

    // 对字符串进行url编码
    public static String UrlEncode(String input) {
        return URLEncoder.encode(input);
    }
    // 从HTML响应体中提取标题
    public static String extractTitle(String responseBody) {
        String title = "";

        String regex = "<title(.*?)>(.*?)</title>";
        Pattern p = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher m = p.matcher(responseBody);
        while (m.find()) {
            title = m.group(2);// 注意
            if (title != null && !title.equals("")) {
                return title;
            }
        }

        String regex1 = "<h[1-6](.*?)>(.*?)</h[1-6]>";
        Pattern ph = Pattern.compile(regex1, Pattern.CASE_INSENSITIVE);
        Matcher mh = ph.matcher(responseBody);
        while (mh.find()) {
            title = mh.group(2);
            if (title != null && !title.equals("")) {
                return title;
            }
        }
        return title;
    }

    // 对字符串进行utf-8编码
    public static String Utf8Encode(String originalString) {
        byte[] utf8Bytes = originalString.getBytes(StandardCharsets.UTF_8); // 使用UTF-8编码转换成字节数组
        String decodedString = new String(utf8Bytes, StandardCharsets.UTF_8);
        return decodedString;
    }

    // 获取当前时间
    public static String getCurrentTime() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return simpleDateFormat.format(new Date());
    }

    /*
     * http://host:port/path/file.jpg -> http://host:port/path/
     * 获取路径排除文件名
     */
    public static String getUrlWithoutFilename(URL url) {
        String urlRootPath = getUrlRootPath(url);
        String path = url.getPath();

        if (path.length() == 0) {
            path = "/";
        }

        if (url.getFile().endsWith("/?format=openapi")) { //对django swagger做单独处理
            return urlRootPath + url.getFile();
        }

        if (path.endsWith("/")) {
            return urlRootPath + path;
        } else {
            return urlRootPath + path.substring(0, path.lastIndexOf("/") + 1);
        }
    }
    /**
     * 获取根目录的 URL
     */
    public static String getUrlRootPath(URL url) {
        return url.getProtocol() + "://" + url.getHost() + ":" + url.getPort();
    }

}
