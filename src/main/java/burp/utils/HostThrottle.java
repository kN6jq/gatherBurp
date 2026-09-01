package burp.utils;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 跨模块共享的同目标请求节流器。
 *
 * <p>Fastjson/Log4j/Auth/UrlRedirect/Route 等主动+被动探测统一走这里，
 * 避免各模块重复实现；被标记为疑似 WAF 的目标自动放大间隔。
 * host 维度自然有界，另设上限双保险。</p>
 */
public final class HostThrottle {
    public static final long NORMAL_INTERVAL_MS = 80L;
    public static final long SLOW_INTERVAL_MS = 300L;
    /** 慢速主机标记有效期：到期后目标自动恢复常规间隔，避免一次 WAF 命中永久降速。
     *  包内可见以便单测覆盖过期逻辑（测试中临时调小）。 */
    static long SLOW_HOST_TTL_MS = 10 * 60 * 1000L;

    private static final ConcurrentHashMap<String, AtomicLong> LAST_REQUEST_TIMES = new ConcurrentHashMap<>();
    private static final LruSet<String> SLOW_HOSTS = new LruSet<>(2048);
    private static final ConcurrentHashMap<String, Long> SLOW_HOST_MARK_TIMES = new ConcurrentHashMap<>();

    private HostThrottle() {
    }

    /** 按默认间隔（正常 80ms / 慢速主机 300ms）节流，必要时 sleep。 */
    public static void throttle(String hostKey) {
        throttle(hostKey, NORMAL_INTERVAL_MS);
    }

    /** 按指定基础间隔节流；慢速主机取 max(interval, SLOW_INTERVAL_MS)。 */
    public static void throttle(String hostKey, long intervalMs) {
        if (hostKey == null || hostKey.isEmpty()) {
            return;
        }
        long interval = isSlowActive(hostKey) ? Math.max(intervalMs, SLOW_INTERVAL_MS) : intervalMs;
        AtomicLong previous = LAST_REQUEST_TIMES.computeIfAbsent(hostKey, k -> new AtomicLong(0L));
        synchronized (previous) {
            long now = System.currentTimeMillis();
            long wait = interval - (now - previous.get());
            if (wait > 0L) {
                try {
                    Thread.sleep(wait);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            previous.set(System.currentTimeMillis());
        }
    }

    /** 标记疑似 WAF/受控主机，后续节流自动放大间隔（{@link #SLOW_HOST_TTL_MS} 后失效）。 */
    public static void markSlow(String hostKey) {
        if (hostKey != null && !hostKey.isEmpty()) {
            SLOW_HOSTS.add(hostKey);
            SLOW_HOST_MARK_TIMES.put(hostKey, System.currentTimeMillis());
        }
    }

    public static boolean isSlow(String hostKey) {
        return hostKey != null && isSlowActive(hostKey);
    }

    /** 判断慢速标记是否仍在有效期内；过期时顺带清理，防止 SLOW_HOSTS 长期滞留。 */
    private static boolean isSlowActive(String hostKey) {
        if (!SLOW_HOSTS.contains(hostKey)) {
            return false;
        }
        Long markTime = SLOW_HOST_MARK_TIMES.get(hostKey);
        if (markTime == null || System.currentTimeMillis() - markTime > SLOW_HOST_TTL_MS) {
            SLOW_HOSTS.remove(hostKey);
            SLOW_HOST_MARK_TIMES.remove(hostKey);
            return false;
        }
        return true;
    }

    public static void reset() {
        LAST_REQUEST_TIMES.clear();
        SLOW_HOSTS.clear();
        SLOW_HOST_MARK_TIMES.clear();
    }
}
