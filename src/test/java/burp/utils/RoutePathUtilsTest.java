package burp.utils;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class RoutePathUtilsTest {

    @Test
    public void capsPathDepthToBoundRequestVolume() {
        List<String> paths = RoutePathUtils.generateTestPaths("/a/b/c/d/e/f/g", "/actuator");
        // 深度上限 4：payload 单发 + 前 4 段前缀 = 5 条，而不是 8 条
        assertEquals(5, paths.size());
        assertEquals("/actuator", paths.get(0));
        assertEquals("/a/actuator", paths.get(1));
        assertEquals("/a/b/c/d/actuator", paths.get(4));
    }

    @Test
    public void cleansPathParamsAndHandlesRootPath() {
        List<String> paths = RoutePathUtils.generateTestPaths("/a;b/c", "/druid/index.html");
        assertEquals(3, paths.size());
        assertEquals("/druid/index.html", paths.get(0));
        assertEquals("/a/druid/index.html", paths.get(1));
        assertEquals("/a/c/druid/index.html", paths.get(2));
        // 根路径只有 payload 单发一条
        assertEquals(1, RoutePathUtils.generateTestPaths("/", "/actuator").size());
    }
}
