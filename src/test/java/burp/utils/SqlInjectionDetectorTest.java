package burp.utils;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class SqlInjectionDetectorTest {
    @Test
    public void formatsSignedResponseLengthDelta() {
        assertEquals("+21", SqlInjectionDetector.formatSignedLengthChange(539, 560));
        assertEquals("-29", SqlInjectionDetector.formatSignedLengthChange(539, 510));
        assertEquals("0", SqlInjectionDetector.formatSignedLengthChange(539, 539));
        assertEquals("N/A", SqlInjectionDetector.formatSignedLengthChange(539, -1));
        assertEquals("N/A", SqlInjectionDetector.formatSignedLengthChange(-1, 539));
    }

    @Test
    public void supportsMutationFriendlyHttpMethodsOnly() {
        assertTrue(SqlInjectionDetector.isSupportedMethod("GET"));
        assertTrue(SqlInjectionDetector.isSupportedMethod("put"));
        assertTrue(SqlInjectionDetector.isSupportedMethod("PATCH"));
        assertTrue(SqlInjectionDetector.isSupportedMethod("DELETE"));
        assertFalse(SqlInjectionDetector.isSupportedMethod("TRACE"));
        assertFalse(SqlInjectionDetector.isSupportedMethod("CONNECT"));
    }

    @Test
    public void checksOnlyEnabledInputLocations() {
        List<Integer> url = Collections.singletonList((int) burp.IParameter.PARAM_URL);
        List<Integer> cookie = Collections.singletonList((int) burp.IParameter.PARAM_COOKIE);
        assertTrue(SqlInjectionDetector.hasDetectableInput(url, false, false, false));
        assertFalse(SqlInjectionDetector.hasDetectableInput(cookie, false, false, false));
        assertTrue(SqlInjectionDetector.hasDetectableInput(cookie, true, false, false));
        assertTrue(SqlInjectionDetector.hasDetectableInput(Collections.<Integer>emptyList(), false, true, true));
        assertFalse(SqlInjectionDetector.hasDetectableInput(Collections.<Integer>emptyList(), false, true, false));
    }

    @Test
    public void usesActualResponseBodyLength() {
        assertEquals(3, SqlInjectionDetector.actualBodyLength(new byte[]{1, 2, 3, 4, 5}, 2));
        assertEquals(0, SqlInjectionDetector.actualBodyLength(new byte[]{1}, 2));
        assertEquals(0, SqlInjectionDetector.actualBodyLength(null, 0));
    }

    @Test
    public void reportsOnlyNewSqlErrorSignatures() {
        List<Pattern> rules = Collections.singletonList(Pattern.compile("ORA-\\d{5}", Pattern.CASE_INSENSITIVE));
        assertFalse(SqlInjectionDetector.hasNewErrorSignature("ORA-00933", "ORA-00933", rules, null));
        assertTrue(SqlInjectionDetector.hasNewErrorSignature("normal", "ORA-00933", rules, null));
        assertTrue(SqlInjectionDetector.hasNewErrorSignature("normal", "database failed", rules,
                Collections.singletonList("database failed")));
    }

    @Test
    public void recognizesPassiveDatabaseErrorDisclosureWithoutCallingItInjection() {
        String body = "{\"errorMessage\":\"查询数据库出错\n"
                + "com.csg.persist.exception.DBException: 执行数据库查询出错!"
                + " 查询语句：select count(1) from HS_SCH_JFCSYCXX";
        assertTrue(SqlInjectionDetector.isLikelySqlErrorDisclosure(
                body, SqlInjectionDetector.defaultErrorRules(), null));
        SqlErrorEvidence evidence = SqlInjectionDetector.analyzeSqlError(
                "", body, SqlInjectionDetector.defaultErrorRules(), null);
        assertTrue(evidence.hasHighConfidenceSignature());
        assertFalse(evidence.isLowConfidenceOnly());
    }

    @Test
    public void comparesTimeToBothConfiguredThresholdAndBaseline() {
        assertTrue(SqlInjectionDetector.isLikelyTimeDelay(500, 6500, 6000, 2500));
        assertFalse(SqlInjectionDetector.isLikelyTimeDelay(5000, 6100, 6000, 2500));
        assertTrue(SqlInjectionDetector.isLikelyTimeDelay(5000, 8000, 6000, 2500));
    }

    @Test
    public void requiresTimeDelayConfirmation() {
        assertTrue(SqlInjectionDetector.isRepeatedTimeDelay(500, 6500, 6700, 6000, 2500));
        assertFalse(SqlInjectionDetector.isRepeatedTimeDelay(500, 6500, 900, 6000, 2500));
    }

    @Test
    public void identifiesBooleanResponsePattern() {
        String normal = "<html><body>items:1</body></html>";
        String abnormal = "<html><body>SQL error page with a lot of changed content</body></html>";
        assertTrue(SqlInjectionDetector.isBooleanDifference(normal, abnormal, normal, 10, 0.85));
        assertFalse(SqlInjectionDetector.isBooleanDifference(normal, normal, normal, 10, 0.85));
    }
    @Test
    public void replacesHeaderByExactCaseInsensitiveNameWithoutMutation() {
        List<String> headers = Arrays.asList(
                "GET / HTTP/1.1",
                "Host: example.test",
                "X-Test: old",
                "X-Test-Extra: keep"
        );

        List<String> replaced = SqlInjectionDetector.replaceHeader(headers, "x-test", "new-value");

        assertEquals("X-Test: new-value", replaced.get(2));
        assertEquals("X-Test-Extra: keep", replaced.get(3));
        assertEquals("X-Test: old", headers.get(2));
        assertTrue(SqlInjectionDetector.replaceHeader(headers, "missing", "value").isEmpty());
    }

}
