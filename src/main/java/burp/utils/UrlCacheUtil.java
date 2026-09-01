package burp.utils;

import burp.IParameter;

import java.net.URL;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * URL缓存工具类。
 *
 * <p>缓存保存完整的规范化特征，而不是短整型 hash，避免不同请求因 hash 碰撞被错误去重。</p>
 */
public final class UrlCacheUtil {
    private static final String DEFAULT_HTTP_PORT = "80";
    private static final String DEFAULT_HTTPS_PORT = "443";
    /** 单模块去重键上限：超过后按访问序淘汰最旧条目，长时间被动扫描不再无限增长。 */
    private static final int MAX_URL_KEYS_PER_MODULE = 2000;

    // 为不同模块创建独立的缓存集合
    private static final ConcurrentHashMap<String, LruSet<String>> MODULE_CACHES = new ConcurrentHashMap<>();

    private UrlCacheUtil() {
    }

    /**
     * 检查 URL 是否第一次出现。返回 true 表示应继续扫描，false 表示已处理过或特征无效。
     */
    public static boolean checkUrlUnique(String moduleName, String method, URL url,
                                         List<IParameter> parameters) {
        if (moduleName == null || moduleName.trim().isEmpty() || url == null) {
            return false;
        }
        try {
            LruSet<String> urlKeys = MODULE_CACHES.computeIfAbsent(moduleName,
                    key -> new LruSet<String>(MAX_URL_KEYS_PER_MODULE));
            return urlKeys.add(buildCanonicalKey(method, url, parameters));
        } catch (RuntimeException e) {
            logError(moduleName + " URL去重处理异常: " + e.getMessage(), e);
            // 特征构建失败时停止本次扫描，避免异常导致重复请求风暴。
            return false;
        }
    }

    /** 构建稳定、可读且保留重复参数的规范化请求特征。 */
    static String buildCanonicalKey(String method, URL url, List<IParameter> parameters) {
        String protocol = lower(url.getProtocol());
        String host = lower(url.getHost());
        String port = normalizedPort(protocol, url.getPort());
        String path = normalizePath(url.getPath());

        StringBuilder feature = new StringBuilder(128)
                .append(value(method == null ? "" : method.toUpperCase(java.util.Locale.ROOT))).append('|')
                .append(protocol).append('|')
                .append(host).append('|')
                .append(port).append('|')
                .append(path);

        List<String> parameterFeatures = new ArrayList<>();
        if (parameters != null) {
            for (IParameter parameter : parameters) {
                if (parameter == null || parameter.getName() == null) {
                    continue;
                }
                // 类型必须参与特征，避免同名的 query/body/cookie 参数互相去重。
                parameterFeatures.add(lengthPrefixed(parameter.getName())
                        + lengthPrefixed(value(parameter.getValue()))
                        + parameter.getType());
            }
        }
        parameterFeatures.sort(Comparator.naturalOrder());
        feature.append('|').append(parameterFeatures.size());
        for (String parameterFeature : parameterFeatures) {
            feature.append('|').append(parameterFeature);
        }
        return feature.toString();
    }

    /** 构建长度前缀字符串（"len:value"）。 */
    private static String lengthPrefixed(String value) {
        return value.length() + ":" + value;
    }

    /** null 安全的值获取。 */
    private static String value(String value) {
        return value == null ? "" : value;
    }

    /** null 安全的小写转换。 */
    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(java.util.Locale.ROOT);
    }

    /** 规范化端口号：显式端口原样返回，默认端口补全，无端口返回 -1。 */
    private static String normalizedPort(String protocol, int port) {
        if (port >= 0) {
            return String.valueOf(port);
        }
        if ("http".equals(protocol)) {
            return DEFAULT_HTTP_PORT;
        }
        if ("https".equals(protocol)) {
            return DEFAULT_HTTPS_PORT;
        }
        return "-1";
    }

    /** 规范化路径：空路径返回 "/"，确保以 "/" 开头。 */
    private static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        // 不合并连续斜杠或尾部斜杠：这些路径在不同 Web 服务器上的语义可能不同，
        // 去重逻辑不应为了“看起来规范”而跳过潜在的扫描目标。
        return path.startsWith("/") ? path : "/" + path;
    }

    /** 重置指定模块的缓存。 */
    public static void resetCache(String moduleName) {
        if (moduleName != null) {
            MODULE_CACHES.remove(moduleName);
        }
    }

    /** 重置全部模块缓存。 */
    public static void resetAllCaches() {
        MODULE_CACHES.clear();
    }

    /** 返回指定模块的缓存条目数。 */
    public static int getCacheSize(String moduleName) {
        LruSet<String> cache = MODULE_CACHES.get(moduleName);
        return cache == null ? 0 : cache.size();
    }

    /** 错误日志：优先写 Burp stderr，未注入时写 System.err。 */
    private static void logError(String message, Throwable throwable) {
        if (Utils.stderr != null) {
            Utils.stderr.println(message);
            throwable.printStackTrace(Utils.stderr);
        } else {
            System.err.println(message);
            throwable.printStackTrace(System.err);
        }
    }
}
