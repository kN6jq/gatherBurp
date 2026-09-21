package burp.utils;

import java.util.ArrayList;
import java.util.List;

/**
 * 路由扫描的纯路径组合逻辑，不依赖 Burp 接口，便于单元测试。
 */
public final class RoutePathUtils {
    /** 每条规则最多探测的路径段数（payload 单发 + 前 N 段前缀），约束请求数 = (1+N)×规则数。 */
    public static final int MAX_TEST_PATH_DEPTH = 4;

    private RoutePathUtils() {
    }

    public static List<String> generateTestPaths(String originalPath, String payload) {
        List<String> testPaths = new ArrayList<>();
        originalPath = cleanPath(originalPath);

        List<String> segments = new ArrayList<>();
        for (String segment : originalPath.split("/")) {
            if (!segment.isEmpty()) {
                segments.add(cleanSegment(segment));
            }
        }
        // 末段形如文件名（含点）时不作为目录前缀：/index.php 不应产出 /index.php/actuator
        // 这类 pathinfo 探测请求量翻倍，且前端控制器常对未知后缀回 200 整页造成误报
        if (!segments.isEmpty() && segments.get(segments.size() - 1).contains(".")) {
            segments.remove(segments.size() - 1);
        }

        StringBuilder currentPath = new StringBuilder();

        testPaths.add(payload);

        int depth = 0;
        for (String segment : segments) {
            // 深度上限：约束请求数 = (1 + MAX_TEST_PATH_DEPTH) × 规则数
            if (depth >= MAX_TEST_PATH_DEPTH) {
                break;
            }
            depth++;
            currentPath.append("/").append(segment);
            testPaths.add(currentPath + payload);
        }

        return testPaths;
    }

    private static String cleanPath(String path) {
        return path.replaceAll(";[^/]*", "");
    }

    private static String cleanSegment(String segment) {
        int semicolonIndex = segment.indexOf(';');
        if (semicolonIndex != -1) {
            return segment.substring(0, semicolonIndex);
        }
        return segment;
    }
}
