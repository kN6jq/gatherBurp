package burp.utils;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/** SQL 错误证据的不可变汇总（高/中/低置信签名集 + 识别的数据库类型 + 总分）。 */
public final class SqlErrorEvidence {
    private final Set<String> high;
    private final Set<String> medium;
    private final Set<String> low;
    private final SqlInjectionDetector.DatabaseType databaseType;
    private final int score;

    public SqlErrorEvidence(Set<String> high, Set<String> medium, Set<String> low,
                            SqlInjectionDetector.DatabaseType databaseType, int score) {
        this.high = immutable(high);
        this.medium = immutable(medium);
        this.low = immutable(low);
        this.databaseType = databaseType == null ? SqlInjectionDetector.DatabaseType.UNKNOWN : databaseType;
        this.score = Math.max(0, Math.min(100, score));
    }

    private static Set<String> immutable(Set<String> values) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(values == null
                ? Collections.<String>emptySet() : values));
    }

    public static SqlErrorEvidence empty() {
        return new SqlErrorEvidence(null, null, null,
                SqlInjectionDetector.DatabaseType.UNKNOWN, 0);
    }

    public Set<String> getHighConfidenceSignatures() { return high; }
    public Set<String> getMediumConfidenceSignatures() { return medium; }
    public Set<String> getLowConfidenceSignatures() { return low; }
    public SqlInjectionDetector.DatabaseType getDatabaseType() { return databaseType; }
    public int getScore() { return score; }
    public boolean hasHighConfidenceSignature() { return !high.isEmpty(); }
    public boolean hasMediumOrHighSignature() { return !high.isEmpty() || !medium.isEmpty(); }
    public boolean isLowConfidenceOnly() { return high.isEmpty() && medium.isEmpty() && !low.isEmpty(); }
    public boolean isEmpty() { return high.isEmpty() && medium.isEmpty() && low.isEmpty(); }
}
