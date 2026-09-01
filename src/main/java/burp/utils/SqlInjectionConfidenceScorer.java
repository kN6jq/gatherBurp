package burp.utils;

/** SQL 注入置信度评分器：汇总错误/布尔/时间/WAF 证据输出 CERTAIN/FIRM/NONE 等级。 */
public final class SqlInjectionConfidenceScorer {
    public enum Level { CERTAIN, FIRM, NONE }

    public static final class Result {
        private final int score;
        private final Level level;
        private final boolean counterEvidenceRequired;

        public Result(int score, Level level, boolean counterEvidenceRequired) {
            this.score = score;
            this.level = level;
            this.counterEvidenceRequired = counterEvidenceRequired;
        }
        public int getScore() { return score; }
        public Level getLevel() { return level; }
        public boolean isCounterEvidenceRequired() { return counterEvidenceRequired; }
    }

    private SqlInjectionConfidenceScorer() { }

    public static Result score(SqlErrorEvidence error, BooleanEvidence bool,
                               TimeDelayEvidence time, WafEvidence waf,
                               boolean defaultErrorPage, boolean highVariance,
                               boolean counterEvidenceValidated) {
        int value = 0;
        boolean lowOnly = error != null && error.isLowConfidenceOnly();
        if (error != null) {
            value += error.getScore();
            // 能识别具体数据库时，错误指纹与目标技术栈形成第二个独立维度。
            if (error.getDatabaseType() != null
                    && error.getDatabaseType() != burp.utils.SqlInjectionDetector.DatabaseType.UNKNOWN) {
                value += 15;
            }
        }
        if (bool != null) value += bool.getScore();
        if (time != null) value += time.getScore();
        boolean hasPrimaryEvidence = (error != null && !error.isEmpty())
                || (bool != null && bool.getScore() > 0)
                || (time != null && time.getScore() > 0);
        // 独立重放验证对布尔模式贡献稍高：单次三响应模式只是候选，
        // 只有重放后的模式仍稳定时才允许进入 Firm；报错/时间证据沿用 +10。
        if (counterEvidenceValidated && hasPrimaryEvidence) {
            // 反证成功是必要条件，也是独立稳定性证据；但不会让单一信号直接升为 Certain。
            value += 25;
        }
        if (defaultErrorPage) value -= 25;
        if (highVariance && time != null && time.getScore() > 0) value -= 20;
        if (waf != null && waf.isBlocked()) value -= Math.max(40, waf.getPenalty());
        value = Math.max(0, Math.min(100, value));
        if (lowOnly) value = Math.min(49, value);
        if (!counterEvidenceValidated) value = Math.min(79, value);
        Level level = value >= 80 ? Level.CERTAIN : value >= 50 ? Level.FIRM : Level.NONE;
        return new Result(value, level, !counterEvidenceValidated);
    }
}
