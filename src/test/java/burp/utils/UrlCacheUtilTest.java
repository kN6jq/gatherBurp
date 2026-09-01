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

    @Test
    public void evictsOldestKeysBeyondModuleCapacity() throws Exception {
        // 单模块容量上限 2000：插入 2001 个不同 URL 后最旧的键被淘汰，可再次作为新键加入。
        for (int i = 0; i < 2000; i++) {
            assertTrue(UrlCacheUtil.checkUrlUnique("evict-test", "GET",
                    new URL("https://example.com/p" + i), Collections.<burp.IParameter>emptyList()));
        }
        assertTrue(UrlCacheUtil.checkUrlUnique("evict-test", "GET",
                new URL("https://example.com/p2000"), Collections.<burp.IParameter>emptyList()));
        // 最旧的 p0 已被淘汰，重新出现视为新 URL。
        assertTrue(UrlCacheUtil.checkUrlUnique("evict-test", "GET",
                new URL("https://example.com/p0"), Collections.<burp.IParameter>emptyList()));
    }
}
