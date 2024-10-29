package burp.utils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;

import java.io.*;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Burp扩展工具类
 * 提供文件操作、字符串处理、URL处理等通用功能
 */
public final class Utils {
    // ================ 常量定义 ================
    private static final String DEFAULT_DATETIME_PATTERN = "yyyy-MM-dd HH:mm:ss";
    private static final String DEFAULT_FILE_DATETIME_PATTERN = "MMdd-HHmmss";
    private static final String REQ_FILE_SUFFIX = ".req";
    private static final String DEFAULT_CHARSET = "UTF-8";
    // ================ 静态字段 ================
    public static final String NAME = "GatherBurp";
    public static final String VERSION = "1.1.2";
    public static final String AUTHOR = "Xm17";
    public static final String WORKDIR = System.getProperty("user.home") + "/.gather/";
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static boolean isSelect = false;

    /**
     * HTML标题提取的正则表达式
     */
    private static final Pattern TITLE_PATTERN = Pattern.compile("<title(.*?)>(.*?)</title>", Pattern.CASE_INSENSITIVE);
    private static final Pattern HEADING_PATTERN = Pattern.compile("<h[1-6](.*?)>(.*?)</h[1-6]>", Pattern.CASE_INSENSITIVE);

    // ================ 文件操作相关 ================

    /**
     * 写入请求到文件
     * @param message HTTP请求响应对象
     * @return 文件绝对路径
     */
    public static String writeReqFile(IHttpRequestResponse message) {
        String host = message.getHttpService().getHost();
        String timeString = DateTimeFormatter.ofPattern(DEFAULT_FILE_DATETIME_PATTERN)
                .format(LocalDateTime.now());
        String filename = String.format("%s.%s%s", host, timeString, REQ_FILE_SUFFIX);

        File requestFile = new File(WORKDIR, filename);
        writeBytes(message.getRequest(), requestFile);
        return requestFile.getAbsolutePath();
    }

    /**
     * 获取Socks配置文件
     */
    public static File SocksConfigFile(String filename) {
        return new File(WORKDIR, filename);
    }

    /**
     * 读取文件内容为字符串
     */
    public static String readString(File file, String charset) {
        if (file == null || !file.exists()) {
            return null;
        }

        try {
            return new String(Files.readAllBytes(file.toPath()), charset);
        } catch (IOException e) {
            stderr.println("Error reading file: " + e.getMessage());
            return null;
        }
    }

    /**
     * 将字符串写入文件
     */
    public static boolean writeString(String content, File file, String charset) {
        try {
            createParentDirs(file);
            Files.write(file.toPath(), content.getBytes(charset));
            return true;
        } catch (IOException e) {
            stderr.println("Error writing file: " + e.getMessage());
            return false;
        }
    }

    /**
     * 写入字节数组到文件
     */
    public static boolean writeBytes(byte[] data, File file) {
        if (data == null || file == null) {
            return false;
        }

        try {
            createParentDirs(file);
            try (FileOutputStream out = new FileOutputStream(file)) {
                out.write(data);
                out.flush();
                return true;
            }
        } catch (IOException e) {
            stderr.println("Error writing bytes: " + e.getMessage());
            return false;
        }
    }

    /**
     * 删除所有.req后缀的缓存文件
     */
    public static boolean deleteReqFile() {
        File dir = new File(WORKDIR);
        if (!dir.exists()) {
            return false;
        }

        File[] files = dir.listFiles((d, name) -> name.endsWith(REQ_FILE_SUFFIX));
        if (files == null) {
            return false;
        }

        Arrays.stream(files).forEach(File::delete);
        return true;
    }

    // ================ URL处理相关 ================

    /**
     * 判断URL是否为黑名单后缀
     */
    public static boolean isUrlBlackListSuffix(String url) {
        String noParameterUrl = url.split("\\?")[0];
        int lastDotIndex = noParameterUrl.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return false;
        }

        String urlSuffix = noParameterUrl.substring(lastDotIndex + 1).toLowerCase();
        return getSuffix().contains(urlSuffix.toLowerCase());
    }

    /**
     * 获取URL的根路径（不包含文件名）
     */
    public static String getUrlWithoutFilename(URL url) {
        String rootPath = getUrlRootPath(url);
        String path = url.getPath();

        if (path.isEmpty()) {
            return rootPath + "/";
        }

        // 特殊处理django swagger
        if (url.getFile().endsWith("/?format=openapi")) {
            return rootPath + url.getFile();
        }

        return path.endsWith("/") ?
                rootPath + path :
                rootPath + path.substring(0, path.lastIndexOf('/') + 1);
    }

    /**
     * 获取URL的协议+主机+端口
     */
    public static String getUrlRootPath(URL url) {
        return String.format("%s://%s:%d",
                url.getProtocol(), url.getHost(), url.getPort());
    }

    // ================ 字符串处理相关 ================

    /**
     * 从HTML响应体中提取标题
     */
    public static String extractTitle(String responseBody) {
        // 尝试从title标签提取
        Matcher titleMatcher = TITLE_PATTERN.matcher(responseBody);
        if (titleMatcher.find()) {
            String title = titleMatcher.group(2);
            if (title != null && !title.isEmpty()) {
                return title;
            }
        }

        // 尝试从heading标签提取
        Matcher headingMatcher = HEADING_PATTERN.matcher(responseBody);
        if (headingMatcher.find()) {
            String heading = headingMatcher.group(2);
            if (heading != null && !heading.isEmpty()) {
                return heading;
            }
        }

        return "";
    }

    /**
     * 移除字符串中的特殊字符
     */
    public static String ReplaceChar(String input) {
        return input.replaceAll("[\\n\\r]", "");
    }

    /**
     * 去除字符串两端的双引号
     */
    public static String RemoveQuotes(String input) {
        return input.startsWith("\"") && input.endsWith("\"") ?
                input.substring(1, input.length() - 1) : input;
    }

    // ================ 编码相关 ================

    /**
     * URL编码
     */
    public static String UrlEncode(String input) {
        try {
            return URLEncoder.encode(input, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return input;
        }
    }

    /**
     * UTF-8编码
     */
    public static String Utf8Encode(String input) {
        return new String(input.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    // ================ 时间相关 ================

    /**
     * 获取当前时间的格式化字符串
     */
    public static String getCurrentTime() {
        return LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern(DEFAULT_DATETIME_PATTERN));
    }

    // ================ 私有辅助方法 ================

    /**
     * 创建父目录（如果不存在）
     */
    private static void createParentDirs(File file) {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
    }

    /**
     * 获取静态资源后缀黑名单
     */
    private static Set<String> getSuffix() {
        return new HashSet<>(Arrays.asList(
                "js", "css", "jpg", "png", "gif", "ico", "svg",
                "woff", "ttf", "eot", "woff2", "otf",
                "mp4", "mp3", "avi", "flv", "swf", "webp",
                "zip", "rar", "7z", "gz", "tar",
                "exe", "pdf", "doc", "docx", "xls", "xlsx",
                "ppt", "pptx", "txt", "xml",
                "apk", "ipa", "dmg", "iso", "img",
                "torrent", "jar", "war", "py"
        ));
    }

    // 禁止实例化
    private Utils() {
        throw new AssertionError("No Utils instances for you!");
    }

    /**
     * 检查域名是否匹配给定的域名列表
     * 支持通配符匹配，例如:
     * - 完全匹配: example.com 匹配 example.com
     * - 子域名匹配: sub.example.com 匹配 *.example.com
     * - 多级匹配: a.b.example.com 匹配 *.*.example.com
     *
     * @param targetDomain 要检查的域名
     * @param allowedDomains 允许的域名列表
     * @return 如果匹配返回true，否则返回false
     */
    public static boolean isMatchDomainName(String targetDomain, List<String> allowedDomains) {
        // 参数验证
        if (targetDomain == null || targetDomain.trim().isEmpty() ||
                allowedDomains == null || allowedDomains.isEmpty()) {
            return false;
        }

        // 处理输入域名
        targetDomain = cleanDomainName(targetDomain);
        if (targetDomain.isEmpty()) {
            return false;
        }

        // 反转目标域名，便于从右到左匹配
        String reversedTarget = new StringBuilder(targetDomain).reverse().toString();

        // 遍历允许的域名列表进行匹配
        for (String allowedDomain : allowedDomains) {
            // 清理和反转待匹配的域名
            allowedDomain = cleanDomainName(allowedDomain);
            if (allowedDomain.isEmpty()) {
                continue;
            }

            // 如果完全匹配，直接返回true
            if (targetDomain.equals(allowedDomain)) {
                return true;
            }

            String reversedAllowed = new StringBuilder(allowedDomain).reverse().toString();

            // 如果两个域名都包含点号，进行通配符匹配
            if (reversedTarget.contains(".") && reversedAllowed.contains(".")) {
                if (isWildcardMatch(reversedTarget, reversedAllowed)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * 清理域名字符串，移除端口号和空白字符
     */
    private static String cleanDomainName(String domain) {
        domain = domain.trim();
        // 移除端口号
        int portIndex = domain.indexOf(':');
        if (portIndex > 0) {
            domain = domain.substring(0, portIndex);
        }
        return domain;
    }

    /**
     * 通配符匹配两个反转的域名
     */
    private static boolean isWildcardMatch(String reversedTarget, String reversedPattern) {
        String[] targetParts = reversedTarget.split("\\.");
        String[] patternParts = reversedPattern.split("\\.");

        // 调整两个数组长度一致
        int maxLength = Math.max(targetParts.length, patternParts.length);
        targetParts = adjustArray(targetParts, maxLength);
        patternParts = adjustArray(patternParts, maxLength);

        // 逐级比较
        for (int i = 0; i < maxLength; i++) {
            String targetPart = targetParts[i];
            String patternPart = patternParts[i];

            // 如果模式中有通配符或者两部分相等，继续比较
            if (!patternPart.equals("*") && !patternPart.equals(targetPart)) {
                return false;
            }
        }

        return true;
    }

    /**
     * 调整数组长度，使用通配符填充
     */
    private static String[] adjustArray(String[] array, int targetLength) {
        if (array.length >= targetLength) {
            return array;
        }

        String[] newArray = new String[targetLength];
        System.arraycopy(array, 0, newArray, 0, array.length);
        Arrays.fill(newArray, array.length, targetLength, "*");
        return newArray;
    }
}