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

        String[] pathSegments = originalPath.split("/");
        StringBuilder currentPath = new StringBuilder();

        testPaths.add(payload);

        int depth = 0;
        for (String segment : pathSegments) {
            if (!segment.isEmpty()) {
                // 深度上限：约束请求数 = (1 + MAX_TEST_PATH_DEPTH) × 规则数
                if (depth >= MAX_TEST_PATH_DEPTH) {
                    break;
                }
                depth++;
                if (currentPath.length() == 0) {
                    currentPath.append("/").append(cleanSegment(segment));
                } else {
                    currentPath.append("/").append(cleanSegment(segment));
                }
                testPaths.add(currentPath + payload);
            }
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
