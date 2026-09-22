package burp.utils;

import burp.IBurpExtenderCallbacks;
import org.junit.Assert;
import org.junit.Test;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.regex.Pattern;

/** FakeIPUtils 纯逻辑单测：整数转点分 IP、随机 IP 格式、应用范围匹配。 */
public class FakeIPUtilsTest {
    private static final Pattern IPV4 = Pattern.compile("(\\d{1,3}\\.){3}\\d{1,3}");

    @Test
    public void num2ipConvertsPositiveInt() {
        Assert.assertEquals("127.0.0.1", FakeIPUtils.num2ip(0x7F000001));
        Assert.assertEquals("8.8.8.8", FakeIPUtils.num2ip(0x08080808));
    }

    @Test
    public void num2ipHandlesNegativeHighRangeInts() {
        Assert.assertEquals("192.168.1.1", FakeIPUtils.num2ip(-1062731519));
        Assert.assertEquals("255.255.255.255", FakeIPUtils.num2ip(-1));
    }

    @Test
    public void randomIpIsDottedQuad() {
        for (int i = 0; i < 1000; i++) {
            String ip = FakeIPUtils.getRandomIp();
            Assert.assertTrue("非法 IP: " + ip, IPV4.matcher(ip).matches());
            for (String part : ip.split("\\.")) {
                Assert.assertTrue("IP 段超界: " + ip, Integer.parseInt(part) <= 255);
            }
        }
    }

    @Test
    public void scopeMatchesConfiguredToolsOnly() {
        FakeIPUtils.setScopeNames(new LinkedHashSet<>(Collections.singletonList("proxy")));
        Assert.assertTrue(FakeIPUtils.isInScope(IBurpExtenderCallbacks.TOOL_PROXY));
        Assert.assertFalse(FakeIPUtils.isInScope(IBurpExtenderCallbacks.TOOL_REPEATER));
        FakeIPUtils.setScopeNames(Collections.emptySet());
        Assert.assertTrue("空范围应回退默认", FakeIPUtils.isInScope(IBurpExtenderCallbacks.TOOL_PROXY));
        Assert.assertTrue(FakeIPUtils.isInScope(IBurpExtenderCallbacks.TOOL_REPEATER));
    }
}
