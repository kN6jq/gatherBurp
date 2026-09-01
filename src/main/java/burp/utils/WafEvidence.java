package burp.utils;

/** WAF 或上游拦截的不可变证据（拦截标记/提供商/罚分/原因/连接重置）。 */
public final class WafEvidence {
    /**
     * 共享的 WAF/上游拦截状态码集合：Route（trackWafSignals）、SmartRequestDetector
     * （编码绕过触发条件）统一引用此常量，避免各处维护不同集合导致判定不一致。
     */
    public static final int[] BLOCKED_STATUS_CODES = {403, 406, 410, 429};

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
