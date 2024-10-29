package burp.ui.SimilarHelper;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class CacheManager {
    private static final int MAX_CACHE_SIZE = 1000;
    private static final long CACHE_DURATION = TimeUnit.MINUTES.toMillis(30); // 缓存30分钟

    private static class CacheEntry {
        final String value;
        final long timestamp;

        CacheEntry(String value) {
            this.value = value;
            this.timestamp = System.currentTimeMillis();
        }

        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_DURATION;
        }
    }

    private static final Map<String, CacheEntry> domainIpCache = new ConcurrentHashMap<>();
    private static final Map<Integer, Set<String>> projectDomainCache = new ConcurrentHashMap<>();
    private static final Map<Integer, Set<String>> projectUrlCache = new ConcurrentHashMap<>();

    // 域名-IP缓存
    public static String getCachedIP(String domain) {
        CacheEntry entry = domainIpCache.get(domain);
        if (entry != null) {
            if (entry.isExpired()) {
                domainIpCache.remove(domain);
                return null;
            }
            return entry.value;
        }
        return null;
    }

    public static void cacheIP(String domain, String ip) {
        if (domainIpCache.size() >= MAX_CACHE_SIZE) {
            // 清理过期缓存
            clearExpiredCache();
            // 如果仍然超过大小限制，移除最早的条目
            if (domainIpCache.size() >= MAX_CACHE_SIZE) {
                Optional<String> firstKey = domainIpCache.keySet().stream().findFirst();
                firstKey.ifPresent(domainIpCache::remove);
            }
        }
        domainIpCache.put(domain, new CacheEntry(ip));
    }

    // 项目域名缓存
    public static void cacheProjectDomain(int projectId, String domain) {
        projectDomainCache.computeIfAbsent(projectId, k -> ConcurrentHashMap.newKeySet())
                .add(domain);
    }

    public static boolean isProjectDomainCached(int projectId, String domain) {
        Set<String> domains = projectDomainCache.get(projectId);
        return domains != null && domains.contains(domain);
    }

    // 项目URL缓存
    public static void cacheProjectUrl(int projectId, String url) {
        projectUrlCache.computeIfAbsent(projectId, k -> ConcurrentHashMap.newKeySet())
                .add(url);
    }

    public static boolean isProjectUrlCached(int projectId, String url) {
        Set<String> urls = projectUrlCache.get(projectId);
        return urls != null && urls.contains(url);
    }

    // 清理缓存
    public static void clearProjectCache(int projectId) {
        projectDomainCache.remove(projectId);
        projectUrlCache.remove(projectId);
    }

    private static void clearExpiredCache() {
        domainIpCache.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }

    public static void clearAllCache() {
        domainIpCache.clear();
        projectDomainCache.clear();
        projectUrlCache.clear();
    }

    // 获取缓存统计信息
    public static Map<String, Integer> getCacheStats() {
        Map<String, Integer> stats = new HashMap<>();
        stats.put("domainIpCache", domainIpCache.size());
        stats.put("projectDomainCache", projectDomainCache.values().stream()
                .mapToInt(Set::size).sum());
        stats.put("projectUrlCache", projectUrlCache.values().stream()
                .mapToInt(Set::size).sum());
        return stats;
    }
}