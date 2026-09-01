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

    @Test
    public void insertsMissingHeaderWithoutMutatingSource() {
        List<String> headers = Arrays.asList("GET / HTTP/1.1", "Host: example.test");
        List<String> inserted = SqlInjectionDetector.insertHeader(headers, "X-Probe", "'-1");
        assertEquals(3, inserted.size());
        assertEquals("X-Probe: '-1", inserted.get(2));
        assertEquals(2, headers.size());
        assertTrue(SqlInjectionDetector.insertHeader(headers, " ", "v").isEmpty());
    }

    @Test
    public void replacesRawUrlAndFormParametersWithoutExtraEncoding() {
        String line = "GET /api?x=1&id=2&y=3 HTTP/1.1";
        assertEquals("GET /api?x=1&id=%27%20OR%201%3D1&y=3 HTTP/1.1",
                SqlInjectionDetector.replaceUrlParamInRequestLine(line, "id", "%27%20OR%201%3D1"));
        assertNull(SqlInjectionDetector.replaceUrlParamInRequestLine("GET /api HTTP/1.1", "id", "x"));
        assertNull(SqlInjectionDetector.replaceUrlParamInRequestLine(line, "missing", "x"));

        String body = "a=1&id=2&flag=x";
        assertEquals("a=1&id=%27OR&flag=x", SqlInjectionDetector.replaceFormParamValue(body, "id", "%27OR"));
        assertNull(SqlInjectionDetector.replaceFormParamValue(body, "nope", "v"));

        // query 中已编码的参数名按解码后的名字匹配
        String encodedLine = "GET /api?na%6D%65=1 HTTP/1.1";
        assertEquals("GET /api?na%6D%65=%27 HTTP/1.1",
                SqlInjectionDetector.replaceUrlParamInRequestLine(encodedLine, "name", "%27"));
    }

    @Test
    public void replayMustStaySimilarToFirstProbe() {
        String firstAbnormal = "order list alpha beta gamma";
        String firstNormal = "completely different rejected empty content";
        assertTrue(SqlInjectionDetector.isBooleanReplayConsistent(
                firstAbnormal, firstAbnormal, firstNormal, firstNormal, 0.85d));
        // abnormal 重放返回了完全不同的页面 → 模式不可信
        assertFalse(SqlInjectionDetector.isBooleanReplayConsistent(
                firstAbnormal, firstNormal, firstNormal, firstNormal, 0.85d));
        assertFalse(SqlInjectionDetector.isBooleanReplayConsistent(
                firstAbnormal, firstAbnormal, firstNormal, firstAbnormal, 0.85d));
        assertFalse(SqlInjectionDetector.isBooleanReplayConsistent(
                null, firstAbnormal, firstNormal, firstNormal, 0.85d));
    }

    @Test
    public void booleanLengthThresholdScalesWithBaselineLength() {
        // 基线长度 1000、零方差：19 字节差异在旧公式（max(10, 0)）下会误报，新公式阈值 = max(10, 20, 1000*2%, 0) = 20。
        // 注意 body 不能用 a-f 字符：会被 ResponseSimilarityMatcher 的 MD5 正则整体清空。
        BaselineStats baseline = BaselineStats.calculate(
                Arrays.asList(100L, 110L, 120L),
                Arrays.asList(1000, 1000, 1000),
                null, Arrays.asList(200, 200, 200), 0.5d);
        ResponseSnapshot original = new ResponseSnapshot(200, Collections.<String>emptyList(),
                repeat('w', 100), 1000, 0L, false, false);
        ResponseSnapshot normal = new ResponseSnapshot(200, Collections.<String>emptyList(),
                repeat('w', 100), 1000, 0L, false, false);
        // abnormal 清洗后 119 字节（差异 19 ≤ 20）→ 不构成布尔差异
        ResponseSnapshot smallAbnormal = new ResponseSnapshot(200, Collections.<String>emptyList(),
                repeat('w', 119), 1019, 0L, false, false);
        BooleanEvidence small = SqlInjectionDetector.evaluateBooleanDifference(
                original, smallAbnormal, normal, baseline, 10, 0.85d);
        assertFalse(small.isConfirmedPattern());

        // abnormal 清洗后 143 字节（差异 43 > 20）且 token 结构不同 → 构成布尔差异
        ResponseSnapshot bigAbnormal = new ResponseSnapshot(200, Collections.<String>emptyList(),
                repeat('w', 100) + repeat('z', 43), 1043, 0L, false, false);
        BooleanEvidence big = SqlInjectionDetector.evaluateBooleanDifference(
                original, bigAbnormal, normal, baseline, 10, 0.85d);
        assertTrue(big.isConfirmedPattern());
        assertEquals(35, big.getScore());
    }

    @Test
    public void recognizesOraclePipeDelayPrimitive() {
        String payload = "' || DBMS_PIPE.RECEIVE_MESSAGE('a', 6) || '";
        assertTrue(SqlInjectionDetector.containsDelayPayload(payload));
        assertEquals(6, SqlInjectionDetector.extractDelaySeconds(payload));
        assertEquals("' || DBMS_PIPE.RECEIVE_MESSAGE('a', 2) || '",
                SqlInjectionDetector.changeDelaySeconds(payload, 2));
    }

    private static String repeat(char c, int count) {
        StringBuilder builder = new StringBuilder(count);
        for (int i = 0; i < count; i++) {
            builder.append(c);
        }
        return builder.toString();
    }

}
