package burp.ui.SimilarHelper;


import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Similar 模块缓存管理器（全静态，ConcurrentMap 保证线程安全）：
 * ① 域名→IP 缓存（24h TTL + 10min 解析失败负缓存）；② 项目级域名/URL 去重缓存（内存，切换项目时清空）。
 * 缓存仅是提速层——SimilarUI 命中缓存后仍可能需数据库兜底校验。
 */
public class CacheManager {
    // 域名-IP映射缓存
    private static final ConcurrentMap<String, String> domainIPCache = new ConcurrentHashMap<>();

    // 项目域名缓存 (项目ID -> 域名集合)
    private static final ConcurrentMap<Integer, Set<String>> projectDomainCache = new ConcurrentHashMap<>();

    // 项目URL缓存 (项目ID -> URL集合)
    private static final ConcurrentMap<Integer, Set<String>> projectUrlCache = new ConcurrentHashMap<>();

    // 缓存过期时间（毫秒）
    private static final long CACHE_EXPIRY = 24 * 60 * 60 * 1000; // 24小时

    // 解析失败负缓存有效期（毫秒）：同一失败域名短期内不再重复发起 DNS 查询
    private static final long NEGATIVE_CACHE_TTL = 10 * 60 * 1000L;

    // 域名-IP缓存时间记录
    private static final ConcurrentMap<String, Long> domainIPCacheTime = new ConcurrentHashMap<>();

    // 域名-DNS解析失败时间记录（负缓存）
    private static final ConcurrentMap<String, Long> domainIPNegativeTime = new ConcurrentHashMap<>();

    /** 缓存域名的 IP 地址。 */
    public static void cacheIP(String domain, String ip) {
        domainIPCache.put(domain.toLowerCase(), ip);
        domainIPCacheTime.put(domain.toLowerCase(), System.currentTimeMillis());
    }

    /**
     * 记录一次失败的 DNS 解析（负缓存），避免不可解析域名在后续每个响应中重复触发查询。
     */
    public static void cacheIpFailure(String domain) {
        if (domain != null) {
            domainIPNegativeTime.put(domain.toLowerCase(), System.currentTimeMillis());
        }
    }

    /**
     * 判断域名是否处于 DNS 解析失败的负缓存窗口内。
     */
    public static boolean isIpCacheNegative(String domain) {
        if (domain == null) {
            return false;
        }
        String lowerDomain = domain.toLowerCase();
        Long negativeTime = domainIPNegativeTime.get(lowerDomain);
        if (negativeTime == null) {
            return false;
        }
        if (System.currentTimeMillis() - negativeTime > NEGATIVE_CACHE_TTL) {
            domainIPNegativeTime.remove(lowerDomain);
            return false;
        }
        return true;
    }

    /** 获取缓存的 IP 地址，过期或不存在返回 null。 */
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

    /** 缓存项目的域名（小写）。 */
    public static void cacheProjectDomain(int projectId, String domain) {
        projectDomainCache.computeIfAbsent(projectId, k -> ConcurrentHashMap.newKeySet())
                .add(domain.toLowerCase());
    }

    /** 检查域名是否已缓存。 */
    public static boolean isProjectDomainCached(int projectId, String domain) {
        Set<String> domains = projectDomainCache.get(projectId);
        return domains != null && domains.contains(domain.toLowerCase());
    }

    /** 缓存项目的 URL。 */
    public static void cacheProjectUrl(int projectId, String url) {
        projectUrlCache.computeIfAbsent(projectId, k -> ConcurrentHashMap.newKeySet())
                .add(url);
    }

    /** 检查 URL 是否已缓存。 */
    public static boolean isProjectUrlCached(int projectId, String url) {
        Set<String> urls = projectUrlCache.get(projectId);
        return urls != null && urls.contains(url);
    }

    /** 清除指定项目的缓存。 */
    public static void clearProjectCache(int projectId) {
        projectDomainCache.remove(projectId);
        projectUrlCache.remove(projectId);
    }

    /** 清除全部缓存。 */
    public static void clearAllCache() {
        domainIPCache.clear();
        domainIPCacheTime.clear();
        domainIPNegativeTime.clear();
        projectDomainCache.clear();
        projectUrlCache.clear();
    }

    /** 获取缓存统计信息。 */
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

    /** 获取指定项目的缓存统计。 */
    public static Map<String, Integer> getProjectCacheStats(int projectId) {
        Map<String, Integer> stats = new HashMap<>();

        Set<String> domains = projectDomainCache.get(projectId);
        stats.put("domains", domains != null ? domains.size() : 0);

        Set<String> urls = projectUrlCache.get(projectId);
        stats.put("urls", urls != null ? urls.size() : 0);

        return stats;
    }

    /** 检查并清理过期的 IP 缓存（正缓存 + 负缓存）。 */
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

        domainIPNegativeTime.forEach((domain, negativeTime) -> {
            if (currentTime - negativeTime > NEGATIVE_CACHE_TTL) {
                domainIPNegativeTime.remove(domain);
            }
        });
    }

    /** 检查域名 IP 是否需要刷新缓存。 */
    public static boolean needsIPRefresh(String domain) {
        String lowerDomain = domain.toLowerCase();
        Long cacheTime = domainIPCacheTime.get(lowerDomain);
        return cacheTime == null || System.currentTimeMillis() - cacheTime > CACHE_EXPIRY;
    }
}
