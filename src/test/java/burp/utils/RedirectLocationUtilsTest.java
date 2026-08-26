package burp.utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RedirectLocationUtilsTest {
    @Test
    public void validatesRedirectByParsedHostInsteadOfSubstring() {
        assertTrue(RedirectLocationUtils.isHostOrSubdomain("https://evil.com/path", "evil.com"));
        assertTrue(RedirectLocationUtils.isHostOrSubdomain("//sub.evil.com/path", "evil.com"));
        assertTrue(RedirectLocationUtils.isHostOrSubdomain("HTTPS://EVIL.COM/path", "evil.com"));

        assertFalse(RedirectLocationUtils.isHostOrSubdomain("https://not-evil.com/path", "evil.com"));
        assertFalse(RedirectLocationUtils.isHostOrSubdomain("https://evil.com.attacker.test/path", "evil.com"));
        assertFalse(RedirectLocationUtils.isHostOrSubdomain("/redirect?next=https://evil.com", "evil.com"));
        assertFalse(RedirectLocationUtils.isHostOrSubdomain(null, "evil.com"));
    }
}
