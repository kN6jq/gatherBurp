package burp.utils;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HttpMessageUtilsTest {

    @Test
    public void updatesExistingContentLengthCaseInsensitively() {
        List<String> headers = new ArrayList<>(Arrays.asList(
                "POST /api HTTP/1.1",
                "content-length: 5",
                "Host: example.test"));
        HttpMessageUtils.setContentLength(headers, 1234);
        assertEquals("Content-Length: 1234", headers.get(1));
        assertEquals(3, headers.size());
    }

    @Test
    public void appendsContentLengthWhenMissing() {
        List<String> headers = new ArrayList<>(Arrays.asList(
                "POST /api HTTP/1.1",
                "Host: example.test"));
        HttpMessageUtils.setContentLength(headers, 42);
        assertEquals("Content-Length: 42", headers.get(headers.size() - 1));
    }

    @Test
    public void neverTouchesRequestLine() {
        List<String> headers = new ArrayList<>(Arrays.asList(
                "POST /api HTTP/1.1"));
        HttpMessageUtils.setContentLength(headers, 7);
        assertEquals("POST /api HTTP/1.1", headers.get(0));
        assertEquals(2, headers.size());
        assertTrue(headers.get(1).startsWith("Content-Length:"));
    }

    @Test
    public void clampsNegativeLength() {
        List<String> headers = new ArrayList<>(Arrays.asList(
                "POST /api HTTP/1.1"));
        HttpMessageUtils.setContentLength(headers, -5);
        assertEquals("Content-Length: 0", headers.get(1));
    }
}
