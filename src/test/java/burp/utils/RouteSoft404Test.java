package burp.utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class RouteSoft404Test {

    private static final String LOGIN_PAGE = "<html><title>登录</title><script>location.href='/Home/Index';</script></html>";

    @Test
    public void identicalBaselineAndProbeIsSoft() {
        // 软404 目标：任意路径都回同一张登录页（本次误报的实际场景）
        assertTrue(RouteSoft404.isSoftResponse(200, LOGIN_PAGE, 200, LOGIN_PAGE));
    }

    @Test
    public void highlySimilarDynamicPageIsSoft() {
        // 软404 页面常带动态字段（时间戳/流水号），预处理剥掉后仍高度相似。
        // 注意动态字段须为纯数字（10+ 位被时间戳正则整体剥除）：
        // 混入字母的 hex 串会被部分剥除，剩余内容差异反而变大（误报教训，勿用）
        String baseline = "<html><body>seq=12345678901 date=2026-10-08 页面主体内容保持一致</body></html>";
        String probe = "<html><body>seq=10987654321 date=2026-10-09 页面主体内容保持一致</body></html>";
        assertTrue(RouteSoft404.isSoftResponse(200, baseline, 200, probe));
    }

    @Test
    public void distinctRealEndpointResponseIsNotSoft() {
        // 真实命中：/swagger-resources 返回 JSON 列表，与登录页完全不同
        String swaggerJson = "[{\"name\":\"default\",\"location\":\"/v2/api-docs\",\"swaggerVersion\":\"2.0\"}]";
        assertFalse(RouteSoft404.isSoftResponse(200, LOGIN_PAGE, 200, swaggerJson));
    }

    @Test
    public void differentStatusIsNotSoft() {
        assertFalse(RouteSoft404.isSoftResponse(200, LOGIN_PAGE, 302, LOGIN_PAGE));
    }

    @Test
    public void emptyOrNullBodiesFailOpen() {
        // 基线或探测体缺失时不启用防护（宁可放行也不静默吞掉真实命中）
        assertFalse(RouteSoft404.isSoftResponse(200, "", 200, LOGIN_PAGE));
        assertFalse(RouteSoft404.isSoftResponse(200, null, 200, LOGIN_PAGE));
        assertFalse(RouteSoft404.isSoftResponse(200, LOGIN_PAGE, 200, ""));
    }
}
