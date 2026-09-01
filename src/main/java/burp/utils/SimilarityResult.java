package burp.utils;

import java.util.Collections;
import java.util.List;

/** 三响应两两相似度结果（原始/异常/正常），供 SQL 盲注评分使用。 */
public final class SimilarityResult {
    private final double originalNormal;
    private final double originalAbnormal;
    private final double normalAbnormal;

    public SimilarityResult(double originalNormal, double originalAbnormal, double normalAbnormal) {
        this.originalNormal = originalNormal;
        this.originalAbnormal = originalAbnormal;
        this.normalAbnormal = normalAbnormal;
    }

    public double getOriginalNormal() { return originalNormal; }
    public double getOriginalAbnormal() { return originalAbnormal; }
    public double getNormalAbnormal() { return normalAbnormal; }
    /** 判断是否满足布尔盲注相似度模式（原始与正常 >= 阈值，异常双低于阈值）。 */
    public boolean matches(double threshold) {
        return originalNormal >= threshold
                && originalAbnormal < threshold
                && normalAbnormal < threshold;
    }
}
