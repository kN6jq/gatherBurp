package burp.utils;

import java.util.regex.Pattern;

public final class SqlErrorRule {
    public enum Confidence { HIGH, MEDIUM, LOW }

    private final String id;
    private final Pattern pattern;
    private final Confidence confidence;
    private final SqlInjectionDetector.DatabaseType databaseType;
    private final int score;

    public SqlErrorRule(String id, String regex, Confidence confidence,
                        SqlInjectionDetector.DatabaseType databaseType, int score) {
        this.id = id == null ? "" : id;
        this.pattern = Pattern.compile(regex == null ? "(?!)" : regex, Pattern.CASE_INSENSITIVE);
        this.confidence = confidence == null ? Confidence.LOW : confidence;
        this.databaseType = databaseType == null ? SqlInjectionDetector.DatabaseType.UNKNOWN : databaseType;
        this.score = Math.max(0, score);
    }

    public String getId() { return id; }
    public Pattern getPattern() { return pattern; }
    public Confidence getConfidence() { return confidence; }
    public SqlInjectionDetector.DatabaseType getDatabaseType() { return databaseType; }
    public int getScore() { return score; }
}
