package burp.utils;

import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class SmartRequestDetectorTest {

    @Test
    public void bypassVariantKeepsHeadersAndBody() {
        byte[] request = ("POST /api/user?id=1 HTTP/1.1\r\n"
                + "Host: example.test\r\n"
                + "Cookie: session=abc\r\n"
                + "Authorization: Bearer token123\r\n"
                + "Content-Length: 5\r\n"
                + "\r\n"
                + "a=b&c").getBytes(StandardCharsets.ISO_8859_1);

        byte[] variant = SmartRequestDetector.buildRequestWithTarget(request, "/%2e%2e/actuator");

        String text = new String(variant, StandardCharsets.ISO_8859_1);
        assertTrue("请求行 target 必须被替换", text.startsWith("POST /%2e%2e/actuator HTTP/1.1\r\n"));
        assertTrue("Cookie 头必须保留", text.contains("Cookie: session=abc\r\n"));
        assertTrue("Authorization 头必须保留", text.contains("Authorization: Bearer token123\r\n"));
        assertTrue("body 必须保留", text.endsWith("a=b&c"));
        // 除请求行外，其余字节必须与原始请求完全一致
        String original = new String(request, StandardCharsets.ISO_8859_1);
        assertEquals(original.substring(original.indexOf("\r\n")),
                text.substring(text.indexOf("\r\n")));
    }

    @Test
    public void bypassVariantSupportsTargetWithQuery() {
        byte[] request = ("GET /nacos/v1/auth/users?pageNo=1&pageSize=10 HTTP/1.1\r\n"
                + "Host: example.test\r\n"
                + "\r\n").getBytes(StandardCharsets.ISO_8859_1);

        byte[] variant = SmartRequestDetector.buildRequestWithTarget(
                request, "/%6Eacos/v1/auth/users?pageNo=1&pageSize=10");

        String text = new String(variant, StandardCharsets.ISO_8859_1);
        assertTrue(text.startsWith("GET /%6Eacos/v1/auth/users?pageNo=1&pageSize=10 HTTP/1.1\r\n"));
        assertTrue(text.contains("Host: example.test\r\n"));
    }

    @Test
    public void rejectsMalformedRequests() {
        assertNull(SmartRequestDetector.buildRequestWithTarget(new byte[0], "/x"));
        assertNull(SmartRequestDetector.buildRequestWithTarget(null, "/x"));
        assertNull(SmartRequestDetector.buildRequestWithTarget("GET / HTTP/1.1".getBytes(StandardCharsets.ISO_8859_1), "/x"));
        assertNull(SmartRequestDetector.buildRequestWithTarget(
                "GET / HTTP/1.1\r\nHost: h\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1), null));
    }
}
