package burp.utils;

/** 布尔盲注评估的不可变证据（长度/相似度匹配、状态安全、排除标记与置信分）。 */
public final class BooleanEvidence {
    private final boolean lengthMatched;
    private final boolean similarityMatched;
    private final boolean statusSafe;
    private final boolean excluded;
    private final int score;

    public BooleanEvidence(boolean lengthMatched, boolean similarityMatched,
                           boolean statusSafe, boolean excluded, int score) {
        this.lengthMatched = lengthMatched;
        this.similarityMatched = similarityMatched;
        this.statusSafe = statusSafe;
        this.excluded = excluded;
        this.score = Math.max(0, Math.min(100, score));
    }

    public static BooleanEvidence empty() { return new BooleanEvidence(false, false, false, true, 0); }
    public boolean isLengthMatched() { return lengthMatched; }
    public boolean isSimilarityMatched() { return similarityMatched; }
    public boolean isStatusSafe() { return statusSafe; }
    public boolean isExcluded() { return excluded; }
    public boolean isConfirmedPattern() { return !excluded && statusSafe && lengthMatched && similarityMatched; }
    public boolean isPartialPattern() { return !excluded && statusSafe && (lengthMatched || similarityMatched); }
    public int getScore() { return score; }
}
