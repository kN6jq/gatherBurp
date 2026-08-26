package burp.utils;

import org.junit.After;
import org.junit.Test;

import java.net.URL;
import java.util.Collections;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class UrlCacheUtilTest {
    @After
    public void tearDown() {
        UrlCacheUtil.resetAllCaches();
    }

    @Test
    public void normalizesDefaultPorts() throws Exception {
        assertTrue(UrlCacheUtil.checkUrlUnique("port-test", "GET",
                new URL("http://example.com/api"), Collections.emptyList()));
        assertFalse(UrlCacheUtil.checkUrlUnique("port-test", "get",
                new URL("http://EXAMPLE.com:80/api"), Collections.emptyList()));
    }

    @Test
    public void keepsPotentiallyDifferentPathsSeparate() throws Exception {
        assertTrue(UrlCacheUtil.checkUrlUnique("path-test", "GET",
                new URL("https://example.com/a/b"), Collections.emptyList()));
        assertTrue(UrlCacheUtil.checkUrlUnique("path-test", "GET",
                new URL("https://example.com/a//b"), Collections.emptyList()));
        assertTrue(UrlCacheUtil.checkUrlUnique("path-test", "GET",
                new URL("https://example.com/a/b/"), Collections.emptyList()));
    }

    @Test
    public void rejectsInvalidFeaturesInsteadOfAllowingRepeatStorms() throws Exception {
        assertFalse(UrlCacheUtil.checkUrlUnique(null, "GET",
                new URL("https://example.com"), Collections.emptyList()));
        assertFalse(UrlCacheUtil.checkUrlUnique("test", "GET", null, Collections.emptyList()));
    }
}
