package burp.utils;

import java.net.URI;
import java.util.Locale;

/** URL helpers used by redirect scanning without depending on Burp API classes. */
public final class RedirectLocationUtils {
    private RedirectLocationUtils() {
    }

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
