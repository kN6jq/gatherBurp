package burp.utils;

import java.net.URI;
import java.util.Locale;

/** 重定向扫描用的 URL 辅助工具（不依赖 Burp API 类）。 */
public final class RedirectLocationUtils {
    private RedirectLocationUtils() {
    }

    /** 判断 location 的主机是否等于或为 expectedDomain 的子域名。 */
    public static boolean isHostOrSubdomain(String location, String expectedDomain) {
        if (location == null || location.trim().isEmpty()
                || expectedDomain == null || expectedDomain.trim().isEmpty()) {
            return false;
        }
        try {
            URI uri = new URI(location.trim().replace('\\', '/'));
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            String normalizedHost = host.toLowerCase(Locale.ROOT);
            String normalizedDomain = expectedDomain.toLowerCase(Locale.ROOT);
            return normalizedDomain.equals(normalizedHost)
                    || normalizedHost.endsWith("." + normalizedDomain);
        } catch (Exception ignored) {
            return false;
        }
    }
}
