package burp.utils;

/** WAF or upstream blocking evidence. */
public final class WafEvidence {
    private final boolean blocked;
    private final String provider;
    private final int penalty;
    private final String reason;
    private final boolean connectionReset;

    public WafEvidence(boolean blocked, String provider, int penalty,
                       String reason, boolean connectionReset) {
        this.blocked = blocked;
        this.provider = provider == null ? "" : provider;
        this.penalty = Math.max(0, penalty);
        this.reason = reason == null ? "" : reason;
        this.connectionReset = connectionReset;
    }

    public static WafEvidence none() {
        return new WafEvidence(false, "", 0, "", false);
    }

    public boolean isBlocked() { return blocked; }
    public String getProvider() { return provider; }
    public int getPenalty() { return penalty; }
    public String getReason() { return reason; }
    public boolean isConnectionReset() { return connectionReset; }
}
