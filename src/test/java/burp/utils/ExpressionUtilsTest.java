package burp.utils;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;
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

    @Test
    public void quoteAwareValidationIgnoresOperatorsInsideValues() {
        // 引号内的括号/等号不参与结构校验
        assertTrue(ExpressionUtils.isValidExpression("body=\"a(b\""));
        assertTrue(ExpressionUtils.isValidExpression("body=\"x=y\" && code=\"200\""));
        // 未闭合引号应被拦截
        assertFalse(ExpressionUtils.isValidExpression("body=\"abc"));
    }

    @Test
    public void splitTopLevelUsesOrAsLowestPrecedence() {
        // || 是最低层：a || b && c 先按 || 拆，&& 留在右段
        List<String> parts = ExpressionUtils.splitTopLevel("a || b && c", "||");
        assertEquals(2, parts.size());
        assertEquals("a ", parts.get(0));
        assertEquals(" b && c", parts.get(1));
    }

    @Test
    public void splitTopLevelSkipsQuotesAndBrackets() {
        // 括号组内部不拆分
        List<String> parts = ExpressionUtils.splitTopLevel("code=\"200\" && (body=\"a\" || body=\"b\")", "||");
        assertEquals(1, parts.size());
        // 引号内的 || 不拆分
        parts = ExpressionUtils.splitTopLevel("body=\"a||b\" || code=\"200\"", "||");
        assertEquals(2, parts.size());
        assertTrue(parts.get(0).contains("a||b"));
    }

    @Test
    public void findTopLevelOperatorLocatesComparisonOutsideQuotes() {
        assertEquals(4, ExpressionUtils.findTopLevelOperator("code=\"200\""));
        // body="a=b" 的运算符是引号外第一个 =
        assertEquals(4, ExpressionUtils.findTopLevelOperator("body=\"a=b\""));
        // != 返回 ! 的位置
        assertEquals(4, ExpressionUtils.findTopLevelOperator("body!=\"x\""));
        assertEquals(-1, ExpressionUtils.findTopLevelOperator("body"));
    }

    @Test
    public void isFullyWrappedOnlyForOutermostBracketPair() {
        assertTrue(ExpressionUtils.isFullyWrapped("(code=\"200\" && body=\"x\")"));
        assertFalse("(a) && (b) 不是整体包裹", ExpressionUtils.isFullyWrapped("(a) && (b)"));
        // 引号内的括号不算结构
        assertFalse(ExpressionUtils.isFullyWrapped("(body=\"x\") "));
        assertTrue(ExpressionUtils.isFullyWrapped("(body=\"a)b\")"));
    }
}
