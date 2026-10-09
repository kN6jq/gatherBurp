package burp.utils;

/**
 * 路由扫描的软 404 判定（纯函数，不依赖 Burp 接口，便于单元测试）。
 *
 * <p>很多站点（ASP.NET 前端控制器、SPA catch-all）对任意不存在的路径都返回
 * 200 + 同一张固定页面。这类目标上"状态码 + body 特征"的目录规则必然失真——
 * 特征词再精确，也可能撞上固定页面里的普通词汇（如 JS 的 location.href）。
 * 判定方法：探测前先请求一个随机不存在的基线路径，若规则探测响应与基线
 * 状态一致且内容高度相似，则本次命中不可信，跳过上报。</p>
 */
public final class RouteSoft404 {

    /** 与 ResponseSimilarityMatcher 的整体阈值保持同一口径。 */
    public static final double SIMILARITY_THRESHOLD = 0.85d;

    private RouteSoft404() {
    }

    /**
     * 判断探测响应是否与基线（随机不存在路径的响应）高度一致。
     *
     * @param baselineStatus 基线响应状态码
     * @param baselineBody   基线响应体文本
     * @param probeStatus    规则探测响应状态码
     * @param probeBody      规则探测响应体文本
     * @return true = 目标对任意路径返回同一页面，命中不可信
     */
    public static boolean isSoftResponse(int baselineStatus, String baselineBody,
                                         int probeStatus, String probeBody) {
        if (baselineBody == null || probeBody == null
                || baselineBody.isEmpty() || probeBody.isEmpty()) {
            return false;
        }
        if (baselineStatus != probeStatus) {
            return false;
        }
        if (baselineBody.equals(probeBody)) {
            return true;
        }
        return ResponseSimilarityMatcher.calculateSimilarity(baselineBody, probeBody)
                >= SIMILARITY_THRESHOLD;
    }
}
