package burp.utils;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class UtilsTest {

    @Test
    public void replaceFirstLiteralIgnoresRegexMetacharacters() {
        // replaceFirst 会把 ? 当量词、. 当任意字符，字面量替换不受影响
        String request = "GET /api/user?id=1 HTTP/1.1";
        assertEquals("GET /api/user/;%2e?id=1 HTTP/1.1",
                Utils.replaceFirstLiteral(request, "/api/user?id=1", "/api/user/;%2e?id=1"));
        assertEquals("GET /a.b/c HTTP/1.1",
                Utils.replaceFirstLiteral("GET /a.b/c HTTP/1.1", "/a.b", "/a.b"));
        // 无匹配时原样返回
        assertEquals("GET /x HTTP/1.1", Utils.replaceFirstLiteral("GET /x HTTP/1.1", "/missing", "/y"));
        // 非法入参原样返回
        assertNull(Utils.replaceFirstLiteral(null, "/a", "/b"));
        assertEquals("text", Utils.replaceFirstLiteral("text", "", "/b"));
    }

    @Test
    public void headerNameMatchesIsCaseInsensitiveAndNameScoped() {
        assertTrue(Utils.headerNameMatches("Cookie: session=abc", "cookie"));
        assertTrue(Utils.headerNameMatches("content-length: 5", "Content-Length"));
        // contains 语义会误命中值或子串，这里必须不命中
        assertFalse(Utils.headerNameMatches("X-Cookie-Flag: 1", "Cookie"));
        assertFalse(Utils.headerNameMatches("Host: example.test", "X-Forwarded-Host"));
        assertFalse(Utils.headerNameMatches("garbage-without-colon", "Host"));
        assertFalse(Utils.headerNameMatches("Host: h", " "));
        assertFalse(Utils.headerNameMatches(null, "Host"));
    }

    @Test
    public void parseProxyPoolAcceptsValidLinesAndRejectsInvalid() {
        List<String[]> proxies = Utils.parseProxyPool(
                "1.2.3.4:8080\n\n5.6.7.8:1080:user:pass\r\nbad-line\n1.2.3.4:notaport\n 9.9.9.9:9090 \n");
        assertEquals(3, proxies.size());
        assertArrayEquals(new String[]{"1.2.3.4", "8080", "", ""}, proxies.get(0));
        assertArrayEquals(new String[]{"5.6.7.8", "1080", "user", "pass"}, proxies.get(1));
        assertArrayEquals(new String[]{"9.9.9.9", "9090", "", ""}, proxies.get(2));
        assertTrue(Utils.parseProxyPool(null).isEmpty());
        assertTrue(Utils.parseProxyPool("").isEmpty());
    }
}
