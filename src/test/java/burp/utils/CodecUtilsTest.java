package burp.utils;

import org.junit.Assert;
import org.junit.Test;

/** CodecUtils 纯逻辑单测：Unicode 转义解码与 JSON 美化、编码转码。 */
public class CodecUtilsTest {

    @Test
    public void unescapeUnicodeConvertsBasicEscapes() {
        Assert.assertEquals("用户未登录", CodecUtils.unescapeUnicode("\\u7528\\u6237\\u672a\\u767b\\u5f55"));
        Assert.assertEquals("a$b", CodecUtils.unescapeUnicode("a\\u0024b"));
        Assert.assertFalse(CodecUtils.containsUnicodeEscape(CodecUtils.unescapeUnicode("\\u7528\\u6237")));
    }

    @Test
    public void unescapeRepeatedlyHandlesDoubleEscaping() {
        // 源内容为字面量 "\\u7528"（双反斜杠转义），两层解码后得到中文
        Assert.assertEquals("用", CodecUtils.unescapeRepeatedly("\\\\u7528", 3));
        Assert.assertEquals("用", CodecUtils.unescapeRepeatedly("\\u7528", 3));
    }

    @Test
    public void prettyJsonConvertsUnicodeAndFormats() {
        String pretty = CodecUtils.prettyJson("{\"errno\":1003,\"errmsg\":\"\\u7528\\u6237\\u672a\\u767b\\u5f55\"}");
        Assert.assertNotNull(pretty);
        Assert.assertTrue("应含转码后的中文: " + pretty, pretty.contains("用户未登录"));
        Assert.assertTrue("应多行美化: " + pretty, pretty.contains("\n"));
    }

    @Test
    public void prettyJsonReturnsNullOnInvalidJson() {
        Assert.assertNull(CodecUtils.prettyJson("STK_7411({\"errno\":1003});"));
        Assert.assertNull(CodecUtils.prettyJson("not json at all"));
    }

    @Test
    public void convertCharsetRoundTripsGbkToUtf8() {
        byte[] gbk = "用户未登录".getBytes(java.nio.charset.Charset.forName("GBK"));
        byte[] utf8 = CodecUtils.convertCharset(gbk, "GBK", "UTF-8");
        Assert.assertEquals("用户未登录", new String(utf8, java.nio.charset.Charset.forName("UTF-8")));
    }
}
