package burp.utils;

public final class TimeDelayEvidence {
    private final boolean shortMatched;
    private final boolean longMatched;
    private final boolean monotonic;
    private final boolean highVariance;
    private final int score;

    public TimeDelayEvidence(boolean shortMatched, boolean longMatched, boolean monotonic,
                             boolean highVariance, int score) {
        this.shortMatched = shortMatched;
        this.longMatched = longMatched;
        this.monotonic = monotonic;
        this.highVariance = highVariance;
        this.score = Math.max(0, Math.min(100, score));
    }

    public static TimeDelayEvidence empty() { return new TimeDelayEvidence(false, false, false, false, 0); }
    public boolean isShortMatched() { return shortMatched; }
    public boolean isLongMatched() { return longMatched; }
    public boolean isMonotonic() { return monotonic; }
    public boolean isHighVariance() { return highVariance; }
    public boolean isHighConfidence() { return !highVariance && shortMatched && longMatched && monotonic; }
    public boolean isRepeatedOnly() { return !highVariance && (shortMatched || longMatched); }
    public int getScore() { return score; }
}
