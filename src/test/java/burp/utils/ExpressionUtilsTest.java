package burp.utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ExpressionUtilsTest {

    @Test
    public void codeComparisonUsesExactEqualsOnly() {
        assertTrue(ExpressionUtils.compareValue("code", "200", "200"));
        // contains 会让 code="200" 命中 2001/1200 等状态码，必须精确相等
        assertFalse(ExpressionUtils.compareValue("code", "2001", "200"));
        assertFalse(ExpressionUtils.compareValue("code", "1200", "200"));
        assertFalse(ExpressionUtils.compareValue("code", "404", "200"));
    }

    @Test
    public void bodyComparisonKeepsContainsSemanticsButRejectsEmptyNeedle() {
        assertTrue(ExpressionUtils.compareValue("body", "welcome admin page", "admin"));
        assertFalse(ExpressionUtils.compareValue("body", "welcome page", "admin"));
        // 空串 needle 对 contains 恒真：body="" 只应匹配空 body
        assertFalse(ExpressionUtils.compareValue("body", "any body content", ""));
        assertTrue(ExpressionUtils.compareValue("body", "", ""));
    }

    @Test
    public void neqIsExactNegationOfCompareValue() {
        // code=2001 对 "200" 的 neq 应为 true（不相等）
        assertFalse(ExpressionUtils.compareValue("code", "2001", "200"));
        assertTrue(ExpressionUtils.compareValue("code", "200", "200"));
    }

    @Test
    public void validatesBracketBalanceAndConditionPresence() {
        assertTrue(ExpressionUtils.isValidExpression("code=\"200\" && body=\"_links\""));
        assertTrue(ExpressionUtils.isValidExpression("(code=\"200\" || title=\"x\") && body=\"y\""));
        assertTrue(ExpressionUtils.isValidExpression("code=\"405\""));
        assertFalse("括号不配对应被拦截", ExpressionUtils.isValidExpression("code=\"200\" && (body=\"x\""));
        assertFalse("多右括号应被拦截", ExpressionUtils.isValidExpression("code=\"200\" && body=\"x\")"));
        assertFalse("无比较条件应被拦截", ExpressionUtils.isValidExpression("code"));
        assertFalse("空表达式应被拦截", ExpressionUtils.isValidExpression(""));
        assertFalse(ExpressionUtils.isValidExpression(null));
    }
}
