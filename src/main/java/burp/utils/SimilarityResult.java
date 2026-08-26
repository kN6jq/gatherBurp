package burp.utils;

import java.util.Collections;
import java.util.List;

/** Detailed three-response similarity values for SQL boolean checks. */
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
    public boolean matches(double threshold) {
        return originalNormal >= threshold
                && originalAbnormal < threshold
                && normalAbnormal < threshold;
    }
}
