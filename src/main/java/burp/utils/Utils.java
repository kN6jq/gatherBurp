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
 * 全局工具类：文件读写（~/.gather 工作目录）、字符串/URL/请求处理、dnslog 载荷生成等。
 * 注意全局可变状态——callbacks/helpers/stdout/stderr 由 BurpExtender 在插件加载时注入，
 * 注入前调用依赖这些字段的方法会 NPE（调用方需判空）。
 */
public final class Utils {
    // ================ 常量定义 ================
    private static final String DEFAULT_DATETIME_PATTERN = "yyyy-MM-dd HH:mm:ss";
    private static final String DEFAULT_FILE_DATETIME_PATTERN = "MMdd-HHmmss";
    private static final String REQ_FILE_SUFFIX = ".req";
    private static final String DEFAULT_CHARSET = "UTF-8";
    // ================ 静态字段 ================
    public static final String NAME = "GatherBurp";
    public static final String VERSION = "1.2.0";
    public static final String AUTHOR = "Xm17";
    public static final String WORKDIR = System.getProperty("user.home") + "/.gather/";
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static boolean isSelect = false;

    /** HTML标题提取的正则表达式。 */
    private static final Pattern TITLE_PATTERN = Pattern.compile("<title(.*?)>(.*?)</title>", Pattern.CASE_INSENSITIVE);
    private static final Pattern HEADING_PATTERN = Pattern.compile("<h[1-6](.*?)>(.*?)</h[1-6]>", Pattern.CASE_INSENSITIVE);

    // ================ 文件操作相关 ================

    /** 将请求写入 ~/.gather 目录下的 .req 文件，返回文件绝对路径。 */
    public static String writeReqFile(IHttpRequestResponse message) {
        String host = message.getHttpService().getHost();
        String timeString = DateTimeFormatter.ofPattern(DEFAULT_FILE_DATETIME_PATTERN)
                .format(LocalDateTime.now());
        String filename = String.format("%s.%s%s", host, timeString, REQ_FILE_SUFFIX);

        File requestFile = new File(WORKDIR, filename);
        writeBytes(message.getRequest(), requestFile);
        return requestFile.getAbsolutePath();
    }

    /** 获取 ~/.gather 目录下的配置文件句柄。 */
    public static File SocksConfigFile(String filename) {
        return new File(WORKDIR, filename);
    }

    /** 读取文件内容为字符串。文件不存在或读取失败返回 null。 */
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

    /** 将字符串写入文件（自动创建父目录），失败返回 false。 */
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

    /** 写入字节数组到文件（自动创建父目录），失败返回 false。 */
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

    /** 删除 ~/.gather 目录下全部 .req 缓存文件。目录不存在返回 false。 */
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

    /** 判断 URL 后缀是否属于静态资源黑名单（js/css/jpg/png/…）。 */
    public static boolean isUrlBlackListSuffix(String url) {
        String noParameterUrl = url.split("\\?")[0];
        int lastDotIndex = noParameterUrl.lastIndexOf('.');
        if (lastDotIndex == -1) {
            return false;
        }

        String urlSuffix = noParameterUrl.substring(lastDotIndex + 1).toLowerCase();
        return getSuffix().contains(urlSuffix.toLowerCase());
    }

    /** 获取 URL 的根路径（不含文件名，保留目录层级）。 */
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

    /** 获取 URL 的协议+主机+端口字符串。 */
    public static String getUrlRootPath(URL url) {
        return String.format("%s://%s:%d",
                url.getProtocol(), url.getHost(), url.getPort());
    }

    // ================ 字符串处理相关 ================

    /** 从 HTML 响应体中提取 <title> 或 <hN> 标签内容；无匹配返回空串。 */
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

    /** 移除字符串中的换行符（\n/\r）。 */
    public static String ReplaceChar(String input) {
        return input.replaceAll("[\\n\\r]", "");
    }

    /**
     * 字面量替换第一次出现的目标串（不做正则解析）。
     * String.replaceFirst 的第一参数是正则，路径中的 ? . + 等元字符会导致替换错位或失配。
     */
    public static String replaceFirstLiteral(String text, String target, String replacement) {
        if (text == null || target == null || replacement == null || target.isEmpty()) {
            return text;
        }
        int index = text.indexOf(target);
        if (index < 0) {
            return text;
        }
        return text.substring(0, index) + replacement + text.substring(index + target.length());
    }

    /**
     * 请求头行与配置头名精确匹配（名称段大小写不敏感，忽略值）。
     * contains 匹配会让 "Cookie" 误命中 "X-Cookie-Flag: ..." 等无关头。
     */
    public static boolean headerNameMatches(String requestHeader, String configuredName) {
        if (requestHeader == null || configuredName == null) {
            return false;
        }
        String name = configuredName.trim();
        if (name.isEmpty()) {
            return false;
        }
        int separator = requestHeader.indexOf(':');
        if (separator <= 0) {
            return false;
        }
        return requestHeader.substring(0, separator).trim().equalsIgnoreCase(name);
    }

    /**
     * 解析代理池文本，每行格式 ip:port 或 ip:port:user:pass。
     * 返回 [ip, port, user, pass] 数组列表，非法行（缺端口/端口非数字）跳过。
     * 按第 3 个冒号限制切分：密码中可含冒号；IPv6 地址（多个冒号）暂不支持，
     * 需先转为 IPv4 或方括号形式。
     */
    public static java.util.List<String[]> parseProxyPool(String text) {
        java.util.List<String[]> proxies = new java.util.ArrayList<>();
        if (text == null || text.isEmpty()) {
            return proxies;
        }
        for (String line : text.replaceAll("\r\n|\r", "\n").split("\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] parts = trimmed.split(":", 4);
            if (parts.length < 2) {
                continue;
            }
            String port = parts[1].trim();
            if (!port.matches("\\d{1,5}")) {
                continue;
            }
            String user = parts.length >= 3 ? parts[2].trim().replaceAll("[\\r\\n]", "") : "";
            String pass = parts.length >= 4 ? parts[3].trim().replaceAll("[\\r\\n]", "") : "";
            proxies.add(new String[]{parts[0].trim(), port, user, pass});
        }
        return proxies;
    }

    /** 去除字符串两端的双引号。 */
    public static String RemoveQuotes(String input) {
        return input.startsWith("\"") && input.endsWith("\"") ?
                input.substring(1, input.length() - 1) : input;
    }

    // ================ 编码相关 ================

    /** URL 编码（UTF-8）。失败返回原文。 */
    public static String UrlEncode(String input) {
        try {
            return URLEncoder.encode(input, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            return input;
        }
    }

    /** UTF-8 编码转换。 */
    public static String Utf8Encode(String input) {
        return new String(input.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    // ================ 时间相关 ================

    /** 获取当前时间的格式化字符串（yyyy-MM-dd HH:mm:ss）。 */
    public static String getCurrentTime() {
        return LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern(DEFAULT_DATETIME_PATTERN));
    }

    // ================ 私有辅助方法 ================

    /** 创建父目录（如果不存在）。 */
    private static void createParentDirs(File file) {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
    }

    /** 获取静态资源后缀黑名单集合。 */
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

    /** 检查域名是否匹配给定域名列表（支持通配符：完全匹配 / 子域名匹配 / 多级匹配）。 */
    public static boolean isMatchDomainName(String targetDomain, List<String> allowedDomains) {
        if (targetDomain == null || targetDomain.trim().isEmpty() ||
                allowedDomains == null || allowedDomains.isEmpty()) {
            return false;
        }

        targetDomain = cleanDomainName(targetDomain);
        if (targetDomain.isEmpty()) {
            return false;
        }

        String[] targetParts = targetDomain.split("\\.");

        for (String allowedDomain : allowedDomains) {
            allowedDomain = cleanDomainName(allowedDomain);
            if (allowedDomain.isEmpty()) {
                continue;
            }

            if (targetDomain.equals(allowedDomain)) {
                return true;
            }

            if (!allowedDomain.contains("*")) {
                continue;
            }

            String[] patternParts = allowedDomain.split("\\.");

            if (matchWildcard(targetParts, patternParts)) {
                return true;
            }
        }

        return false;
    }

    /** 从右到左通配符匹配域名段。 */
    private static boolean matchWildcard(String[] targetParts, String[] patternParts) {
        int ti = targetParts.length - 1;
        int pi = patternParts.length - 1;

        while (ti >= 0 && pi >= 0) {
            if ("*".equals(patternParts[pi])) {
                return true;
            }
            if (!targetParts[ti].equals(patternParts[pi])) {
                return false;
            }
            ti--;
            pi--;
        }

        // pattern用完了，如果target还有剩余部分，需全部为*才能匹配
        while (ti >= 0) {
            if (!"*".equals(patternParts[0])) {
                return false;
            }
            ti--;
        }

        return true;
    }

    /** 清理域名字符串：移除端口号和空白字符。 */
    private static String cleanDomainName(String domain) {
        domain = domain.trim();
        int portIndex = domain.indexOf(':');
        if (portIndex > 0) {
            domain = domain.substring(0, portIndex);
        }
        return domain;
    }

    /** 生成带目标信息的 dnslog 地址（目标域名.URI路径.fastjson.dnslog地址）。 */
    public static String generateDnsPayload(URL targetUrl, String dnslog) {
        if (targetUrl == null || dnslog == null || dnslog.isEmpty()) {
            return dnslog;
        }

        // 获取目标域名和URI
        String targetDomain = targetUrl.getHost();
        String targetUri = targetUrl.getPath();
        if(targetUri.startsWith("/")) {
            targetUri = targetUri.substring(1);
        }

        // 拼接dnslog地址:目标域名.URI路径.dnslog地址
        String dnslogPayload = targetDomain + "." + targetUri + "." + "fastjson" + "." + dnslog;

        // 处理特殊字符
        dnslogPayload = sanitizeDnsPayload(dnslogPayload);

        return dnslogPayload;
    }

    /** 清理 DNS payload 中的特殊字符（非字母数字替换为点号，合并连续点号）。 */
    private static String sanitizeDnsPayload(String payload) {
        if (payload == null || payload.isEmpty()) {
            return payload;
        }

        // 将非字母数字的字符替换为点号
        String sanitized = payload.replaceAll("[^a-zA-Z0-9.]", ".");

        // 处理可能出现的多个连续点号
        sanitized = sanitized.replaceAll("\\.+", ".");

        // 如果末尾有点号，去除
        sanitized = sanitized.replaceAll("\\.$", "");

        return sanitized;
    }
}