package burp.ui.SimilarHelper;


import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public class CacheManager {
    // 域名-IP映射缓存
    private static final ConcurrentMap<String, String> domainIPCache = new ConcurrentHashMap<>();

    // 项目域名缓存 (项目ID -> 域名集合)
    private static final ConcurrentMap<Integer, Set<String>> projectDomainCache = new ConcurrentHashMap<>();

    // 项目URL缓存 (项目ID -> URL集合)
    private static final ConcurrentMap<Integer, Set<String>> projectUrlCache = new ConcurrentHashMap<>();

    // 缓存过期时间（毫秒）
    private static final long CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24小时

    // 域名-IP缓存时间记录
    private static final ConcurrentMap<String, Long> domainIPCacheTime = new ConcurrentHashMap<>();

    /**
     * 缓存域名的IP地址
     */
    public static void cacheIP(String domain, String ip) {
        domainIPCache.put(domain.toLowerCase(), ip);
        domainIPCacheTime.put(domain.toLowerCase(), System.currentTimeMillis());
    }

    /**
     * 获取缓存的IP地址
     */
    public static String getCachedIP(String domain) {
        String lowerDomain = domain.toLowerCase();
        Long cacheTime = domainIPCacheTime.get(lowerDomain);

        if (cacheTime == null) {
            return null;
        }

        // 检查缓存是否过期
        if (System.currentTimeMillis() - cacheTime > CACHE_EXPIRY) {
            domainIPCache.remove(lowerDomain);
            domainIPCacheTime.remove(lowerDomain);
            return null;
        }

        return domainIPCache.get(lowerDomain);
    }

    /**
     * 缓存项目的域名
     */
    public static void cacheProjectDomain(int projectId, String domain) {
        projectDomainCache.computeIfAbsent(projectId, k -> ConcurrentHashMap.newKeySet())
                .add(domain.toLowerCase());
    }

    /**
     * 检查域名是否已缓存
     */
    public static boolean isProjectDomainCached(int projectId, String domain) {
        Set<String> domains = projectDomainCache.get(projectId);
        return domains != null && domains.contains(domain.toLowerCase());
    }

    /**
     * 缓存项目的URL
     */
    public static void cacheProjectUrl(int projectId, String url) {
        projectUrlCache.computeIfAbsent(projectId, k -> ConcurrentHashMap.newKeySet())
                .add(url);
    }

    /**
     * 检查URL是否已缓存
     */
    public static boolean isProjectUrlCached(int projectId, String url) {
        Set<String> urls = projectUrlCache.get(projectId);
        return urls != null && urls.contains(url);
    }

    /**
     * 清除指定项目的缓存
     */
    public static void clearProjectCache(int projectId) {
        projectDomainCache.remove(projectId);
        projectUrlCache.remove(projectId);
    }

    /**
     * 清除所有缓存
     */
    public static void clearAllCache() {
        domainIPCache.clear();
        domainIPCacheTime.clear();
        projectDomainCache.clear();
        projectUrlCache.clear();
    }

    /**
     * 获取缓存统计信息
     */
    public static Map<String, Integer> getCacheStats() {
        Map<String, Integer> stats = new HashMap<>();

        // 统计域名IP缓存数量
        stats.put("domainIpCache", domainIPCache.size());

        // 统计所有项目的域名缓存总数
        int totalDomains = projectDomainCache.values().stream()
                .mapToInt(Set::size)
                .sum();
        stats.put("projectDomainCache", totalDomains);

        // 统计所有项目的URL缓存总数
        int totalUrls = projectUrlCache.values().stream()
                .mapToInt(Set::size)
                .sum();
        stats.put("projectUrlCache", totalUrls);

        return stats;
    }

    /**
     * 获取指定项目的缓存统计
     */
    public static Map<String, Integer> getProjectCacheStats(int projectId) {
        Map<String, Integer> stats = new HashMap<>();

        Set<String> domains = projectDomainCache.get(projectId);
        stats.put("domains", domains != null ? domains.size() : 0);

        Set<String> urls = projectUrlCache.get(projectId);
        stats.put("urls", urls != null ? urls.size() : 0);

        return stats;
    }

    /**
     * 检查并清理过期的IP缓存
     */
    public static void cleanExpiredIPCache() {
        long currentTime = System.currentTimeMillis();
        Set<String> expiredDomains = new HashSet<>();

        domainIPCacheTime.forEach((domain, cacheTime) -> {
            if (currentTime - cacheTime > CACHE_EXPIRY) {
                expiredDomains.add(domain);
            }
        });

        expiredDomains.forEach(domain -> {
            domainIPCache.remove(domain);
            domainIPCacheTime.remove(domain);
        });
    }

    /**
     * 检查域名IP是否需要刷新缓存
     */
    public static boolean needsIPRefresh(String domain) {
        String lowerDomain = domain.toLowerCase();
        Long cacheTime = domainIPCacheTime.get(lowerDomain);
        return cacheTime == null || System.currentTimeMillis() - cacheTime > CACHE_EXPIRY;
    }
}
