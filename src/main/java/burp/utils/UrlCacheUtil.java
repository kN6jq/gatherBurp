package burp.utils;

import burp.IParameter;

import javax.rmi.CORBA.Util;
import java.net.URL;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

/**
 * URL缓存工具类
 */
public class UrlCacheUtil {
    // 为不同模块创建独立的缓存集合
    private static final Map<String, Set<String>> MODULE_CACHES = new ConcurrentHashMap<>();

    /**
     * 检查URL是否重复
     */
    public static boolean checkUrlUnique(String moduleName, String method, URL url,
                                         List<IParameter> parameters) {
        try {
            // 获取模块的缓存集合，如果不存在则创建
            Set<String> urlHashSet = MODULE_CACHES.computeIfAbsent(moduleName,
                    k -> Collections.synchronizedSet(new HashSet<>()));

            // 构建URL特征
            String urlHash = buildUrlHash(method, url, parameters);

            // 检查是否重复，不重复则添加
            return urlHashSet.add(urlHash);

        } catch (Exception e) {
            Utils.stderr.println(moduleName + " URL去重处理异常: " + e.getMessage());
            return true;
        }
    }

    /**
     * 构建URL特征值
     */
    private static String buildUrlHash(String method, URL url, List<IParameter> parameters) {
        StringBuilder urlFeature = new StringBuilder();
        urlFeature.append(method.toUpperCase())
                .append("|")
                .append(url.getProtocol())
                .append("://")
                .append(url.getHost().toLowerCase())
                .append(":")
                .append(url.getPort())
                .append(normalizePath(url.getPath()));

        if (parameters != null && !parameters.isEmpty()) {
            Map<String, String> paramMap = new TreeMap<>();
            for (IParameter param : parameters) {
                if (param != null && param.getName() != null) {
                    paramMap.put(param.getName(), param.getValue());
                }
            }

            if (!paramMap.isEmpty()) {
                urlFeature.append("?");
                for (Map.Entry<String, String> entry : paramMap.entrySet()) {
                    urlFeature.append(entry.getKey())
                            .append("=")
                            .append(entry.getValue())
                            .append("&");
                }
            }
        }

        return simpleHash(urlFeature.toString());
    }

    /**
     * 简单的字符串哈希函数
     */
    private static String simpleHash(String input) {
        int hash = 0;
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            hash = 31 * hash + (b & 0xff);
        }
        return String.format("%08x", hash);
    }

    /**
     * 规范化路径
     */
    private static String normalizePath(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        path = path.replaceAll("/+", "/");
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }

    /**
     * 重置指定模块的缓存
     */
    public static void resetCache(String moduleName) {
        Set<String> cache = MODULE_CACHES.get(moduleName);
        if (cache != null) {
            cache.clear();
        }
    }

    /**
     * 重置所有缓存
     */
    public static void resetAllCaches() {
        MODULE_CACHES.clear();
    }

    /**
     * 获取指定模块的缓存大小
     */
    public static int getCacheSize(String moduleName) {
        Set<String> cache = MODULE_CACHES.get(moduleName);
        return cache != null ? cache.size() : 0;
    }
}