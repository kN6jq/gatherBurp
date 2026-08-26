package burp.utils;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.*;

public class SqlInjectionEvidenceTest {
    @Test
    public void calculatesMedianAndFlagsNoisyBaseline() {
        BaselineStats stable = BaselineStats.calculate(
                Arrays.asList(100L, 110L, 120L),
                Arrays.asList(1000, 1002, 998),
                Arrays.asList("a", "b", "c"),
                Arrays.asList(200, 200, 200), 0.5d);
        assertEquals(110L, stable.getMedianResponseTimeMs());
        assertFalse(stable.isHighVariance());
        assertTrue(stable.isStatusStable());

        BaselineStats noisy = BaselineStats.calculate(
                Arrays.asList(100L, 110L, 1000L),
                Arrays.asList(1000, 1000, 1000), null,
                Arrays.asList(200, 200, 500), 0.5d);
        assertTrue(noisy.isHighVariance());
        assertFalse(noisy.isStatusStable());
    }

    @Test
    public void separatesStrongAndGenericSqlErrors() {
        SqlErrorEvidence strong = SqlInjectionDetector.analyzeSqlError(
                "normal", "java.sql.SQLException: ORA-00933",
                SqlInjectionDetector.defaultErrorRules(), null);
        assertTrue(strong.hasHighConfidenceSignature());
        assertEquals(SqlInjectionDetector.DatabaseType.ORACLE, strong.getDatabaseType());
        assertEquals(40, strong.getScore());

        SqlErrorEvidence generic = SqlInjectionDetector.analyzeSqlError(
                "normal", "A syntax error occurred",
                SqlInjectionDetector.defaultErrorRules(), null);
        assertTrue(generic.isLowConfidenceOnly());
        assertEquals(15, generic.getScore());

        SqlErrorEvidence baselineExisting = SqlInjectionDetector.analyzeSqlError(
                "syntax error", "syntax error",
                SqlInjectionDetector.defaultErrorRules(), null);
        assertTrue(baselineExisting.isEmpty());
    }

    @Test
    public void requiresLengthAndSimilarityForConfirmedBooleanEvidence() {
        ResponseSnapshot original = snapshot(200, "items alpha beta gamma delta normal response");
        ResponseSnapshot normal = snapshot(200, "items alpha beta gamma delta normal response");
        ResponseSnapshot abnormal = snapshot(200, "completely different rejected empty result content");
        BooleanEvidence evidence = SqlInjectionDetector.evaluateBooleanDifference(
                original, abnormal, normal, null, 5, 0.85d);
        assertTrue(evidence.isConfirmedPattern());
        assertEquals(35, evidence.getScore());

        ResponseSnapshot error = new ResponseSnapshot(500, Collections.<String>emptyList(),
                "Internal Server Error", 21, 0, false, true);
        assertTrue(SqlInjectionDetector.evaluateBooleanDifference(
                original, error, normal, null, 5, 0.85d).isExcluded());
        ResponseSnapshot nonDefaultError = new ResponseSnapshot(500, Collections.<String>emptyList(),
                "application-specific failure", 27, 0, false, false);
        assertTrue(SqlInjectionDetector.evaluateBooleanDifference(
                original, nonDefaultError, normal, null, 5, 0.85d).isExcluded());
    }

    @Test
    public void identifiesWafOnlyWhenBlockingSignalsAreCorrelated() {
        WafEvidence cloudflare = SqlInjectionDetector.detectWaf(403,
                Arrays.asList("HTTP/1.1 403 Forbidden", "Server: cloudflare", "CF-Ray: abc"),
                "Access denied. Cloudflare Ray ID: abc", false);
        assertTrue(cloudflare.isBlocked());
        assertEquals("Cloudflare", cloudflare.getProvider());

        assertFalse(SqlInjectionDetector.detectWaf(403,
                Collections.singletonList("Server: application"),
                "Permission denied for this account", false).isBlocked());
    }

    @Test
    public void scoresOnlyValidatedCrossCheckedEvidence() {
        SqlErrorEvidence error = SqlInjectionDetector.analyzeSqlError(
                "normal", "java.sql.SQLException", SqlInjectionDetector.defaultErrorRules(), null);
        SqlInjectionConfidenceScorer.Result unverified = SqlInjectionConfidenceScorer.score(
                error, null, null, WafEvidence.none(), false, false, false);
        assertEquals(SqlInjectionConfidenceScorer.Level.NONE, unverified.getLevel());
        assertEquals(40, unverified.getScore());

        SqlInjectionConfidenceScorer.Result verified = SqlInjectionConfidenceScorer.score(
                error, null, null, WafEvidence.none(), false, false, true);
        assertEquals(SqlInjectionConfidenceScorer.Level.FIRM, verified.getLevel());
        assertEquals(65, verified.getScore());

        SqlInjectionConfidenceScorer.Result waf = SqlInjectionConfidenceScorer.score(
                error, null, null, new WafEvidence(true, "WAF", 40, "blocked", false),
                false, false, true);
        assertEquals(SqlInjectionConfidenceScorer.Level.NONE, waf.getLevel());
    }

    @Test
    public void requiresDifferentDelayDurationsToBeMonotonic() {
        BaselineStats baseline = BaselineStats.calculate(
                Arrays.asList(100L, 110L, 120L), Arrays.asList(100, 100, 100),
                null, Arrays.asList(200, 200, 200), 0.5d);
        TimeDelayEvidence evidence = SqlInjectionDetector.evaluateTimeDelay(
                baseline, 3200L, 6400L, 3000L, 6000L, 0L, 1500L);
        assertTrue(evidence.isHighConfidence());
        assertEquals(40, evidence.getScore());

        TimeDelayEvidence nonMonotonic = SqlInjectionDetector.evaluateTimeDelay(
                baseline, 6500L, 6400L, 3000L, 6000L, 0L, 1500L);
        assertFalse(nonMonotonic.isHighConfidence());
    }

    @Test
    public void shortDelayUsesExpectedSleepWhileLongDelayKeepsConfiguredThreshold() {
        assertTrue(SqlInjectionDetector.isLikelyExpectedTimeDelay(
                100L, 1500L, 2000L, false, 6000L, 2500L));
        assertFalse(SqlInjectionDetector.isLikelyExpectedTimeDelay(
                100L, 5200L, 5000L, true, 6000L, 2500L));
        assertTrue(SqlInjectionDetector.isLikelyExpectedTimeDelay(
                100L, 6200L, 5000L, true, 6000L, 2500L));
    }

    @Test
    public void rewritesSupportedDelayPayloadsWithoutChangingEncoding() {
        assertTrue(SqlInjectionDetector.containsDelayPayload("AND SLEEP(6)"));
        assertEquals(2, SqlInjectionDetector.extractDelaySeconds("AND SLEEP(2)"));
        assertEquals("AND SLEEP(5)", SqlInjectionDetector.changeDelaySeconds("AND SLEEP(2)", 5));
        assertEquals("pg_sleep%285%29", SqlInjectionDetector.changeDelaySeconds("pg_sleep%282%29", 5));
        assertEquals("WAITFOR DELAY '0:0:5'", SqlInjectionDetector.changeDelaySeconds("WAITFOR DELAY '0:0:2'", 5));
        assertEquals("WAITFOR DELAY %270:0:5%27", SqlInjectionDetector.changeDelaySeconds("WAITFOR DELAY %270:0:2%27", 5));
        assertFalse(SqlInjectionDetector.containsDelayPayload("AND 1=1"));
    }

    @Test
    public void auxiliaryCdnHeaderDoesNotAloneCreateWafEvidence() {
        assertFalse(SqlInjectionDetector.detectWaf(403,
                Arrays.asList("HTTP/1.1 403 Forbidden", "X-CDN: edge"),
                "Permission denied for this account", false).isBlocked());
    }

    private static ResponseSnapshot snapshot(int status, String body) {
        return new ResponseSnapshot(status, Collections.<String>emptyList(), body,
                body.length(), 0L, false, false);
    }
}
