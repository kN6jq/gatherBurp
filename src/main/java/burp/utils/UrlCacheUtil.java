package burp.utils;

import burp.IParameter;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * URL缓存工具类。
 *
 * <p>缓存保存完整的规范化特征，而不是短整型 hash，避免不同请求因 hash 碰撞被错误去重。</p>
 */
public final class UrlCacheUtil {
    private static final String DEFAULT_HTTP_PORT = "80";
    private static final String DEFAULT_HTTPS_PORT = "443";

    // 为不同模块创建独立的缓存集合
    private static final ConcurrentHashMap<String, Set<String>> MODULE_CACHES = new ConcurrentHashMap<>();

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
            Set<String> urlKeys = MODULE_CACHES.computeIfAbsent(moduleName,
                    key -> Collections.newSetFromMap(new ConcurrentHashMap<String, Boolean>()));
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

    private static String lengthPrefixed(String value) {
        return value.length() + ":" + value;
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private static String lower(String value) {
        return value == null ? "" : value.toLowerCase(java.util.Locale.ROOT);
    }

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

    private static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        // 不合并连续斜杠或尾部斜杠：这些路径在不同 Web 服务器上的语义可能不同，
        // 去重逻辑不应为了“看起来规范”而跳过潜在的扫描目标。
        return path.startsWith("/") ? path : "/" + path;
    }

    public static void resetCache(String moduleName) {
        if (moduleName != null) {
            MODULE_CACHES.remove(moduleName);
        }
    }

    public static void resetAllCaches() {
        MODULE_CACHES.clear();
    }

    public static int getCacheSize(String moduleName) {
        Set<String> cache = MODULE_CACHES.get(moduleName);
        return cache == null ? 0 : cache.size();
    }

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
