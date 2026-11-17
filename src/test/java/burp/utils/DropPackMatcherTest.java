package burp.utils;

import burp.bean.DropPackRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** DropPackMatcher 匹配逻辑单元测试：不依赖 Burp 运行时，直接操作静态规则快照。 */
public class DropPackMatcherTest {

    @Before
    public void setUpState() {
        // 匹配核心默认带着总开关，单测前置打开；个别用例自行关闭验证开关语义
        DropPackMatcher.setEnabled(true);
        DropPackMatcher.rebuild(Collections.<DropPackRule>emptyList());
    }

    @After
    public void tearDownState() {
        DropPackMatcher.setEnabled(false);
        DropPackMatcher.rebuild(Collections.<DropPackRule>emptyList());
    }

    /** 构建一条规则（默认启用、丢弃动作）。 */
    private static DropPackRule rule(long id, String action, String matchType, String pattern) {
        DropPackRule rule = new DropPackRule();
        rule.setId(id);
        rule.setAction(action);
        rule.setMatchType(matchType);
        rule.setPattern(pattern);
        rule.setEnabled(true);
        return rule;
    }

    @Test
    public void hostExactMatchIsCaseInsensitive() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_HOST, "Example.COM")));
        assertNotNull(DropPackMatcher.firstMatch("example.com", "https://example.com/"));
        // 精确匹配不扩散到子域名
        assertNull(DropPackMatcher.firstMatch("sub.example.com", "https://sub.example.com/"));
        assertNull(DropPackMatcher.firstMatch("evil-example.com", "https://evil-example.com/"));
    }

    @Test
    public void hostWildcardMatchesSubdomainsOnly() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_HOST, "*.example.com")));
        assertNotNull(DropPackMatcher.firstMatch("sub.example.com", "https://sub.example.com/"));
        assertNotNull(DropPackMatcher.firstMatch("a.b.Example.COM", "https://a.b.example.com/"));
        // 通配不命中根域名
        assertNull(DropPackMatcher.firstMatch("example.com", "https://example.com/"));
        assertNull(DropPackMatcher.firstMatch("notexample.com", "https://notexample.com/"));
    }

    @Test
    public void urlPrefixMatchesWithQuery() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_URL, "https://target.com/api")));
        assertNotNull(DropPackMatcher.firstMatch("target.com", "https://target.com/api/v1?x=1"));
        // /api 前缀不允许吞掉 /apix 这类同段延伸
        assertNull(DropPackMatcher.firstMatch("target.com", "https://target.com/apix"));
        // 忽略大小写
        assertNotNull(DropPackMatcher.firstMatch("target.com", "https://TARGET.COM/API/v1"));
    }

    @Test
    public void keywordMatchesAnywhereInUrl() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "/css/")));
        assertNotNull(DropPackMatcher.firstMatch("any.com", "https://any.com/static/css/main.css"));
        assertNull(DropPackMatcher.firstMatch("any.com", "https://any.com/static/js/main.js"));
    }

    @Test
    public void regexMatchesAndBadRegexSkipped() {
        List<DropPackRule> rules = Arrays.asList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_REGEX, ".*\\.png$"),
                rule(2, DropPackRule.ACTION_DROP, DropPackRule.MATCH_REGEX, "(unclosed"));
        DropPackMatcher.rebuild(rules);
        assertNotNull(DropPackMatcher.firstMatch("any.com", "https://any.com/img/logo.png"));
        assertNull(DropPackMatcher.firstMatch("any.com", "https://any.com/img/logo.jpg"));
        // 非法正则的规则被跳过且不抛异常（坏正则 + 好 URL 也不命中，避免代理线程被炸）
        assertNull(DropPackMatcher.firstMatch("any.com", "https://any.com/(unclosed"));
    }

    @Test
    public void firstMatchWinsByListOrder() {
        List<DropPackRule> rules = Arrays.asList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "noise"),
                rule(2, DropPackRule.ACTION_FORWARD, DropPackRule.MATCH_KEYWORD, "noise"));
        DropPackMatcher.rebuild(rules);
        DropPackMatcher.CompiledRule hit = DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js");
        assertNotNull(hit);
        assertEquals(1, hit.getId());
        assertTrue(hit.isDrop());
    }

    @Test
    public void disabledRulesAreExcluded() {
        DropPackRule disabled = rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "noise");
        disabled.setEnabled(false);
        DropPackMatcher.rebuild(Collections.singletonList(disabled));
        assertNull(DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js"));
    }

    @Test
    public void disabledModuleMatchesNothing() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "noise")));
        DropPackMatcher.setEnabled(false);
        assertNull(DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js"));
    }

    @Test
    public void forwardActionIsNotDrop() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(1, DropPackRule.ACTION_FORWARD, DropPackRule.MATCH_KEYWORD, "noise")));
        DropPackMatcher.CompiledRule hit = DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js");
        assertNotNull(hit);
        assertFalse(hit.isDrop());
    }

    @Test
    public void matchesRuleIgnoresEnableFlag() {
        // 右键"取消命中此包的规则"需要把未启用但条件命中的规则也能撤销
        DropPackRule disabled = rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "noise");
        disabled.setEnabled(false);
        assertTrue(DropPackMatcher.matchesRule(disabled, "any.com", "https://any.com/noise.js"));
        DropPackRule badRegex = rule(2, DropPackRule.ACTION_DROP, DropPackRule.MATCH_REGEX, "(unclosed");
        assertFalse(DropPackMatcher.matchesRule(badRegex, "any.com", "https://any.com/(unclosed"));
    }

    @Test
    public void hitCountersAccumulateAndSurviveRebuild() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(7, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "noise")));
        DropPackMatcher.recordHit(DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js"));
        DropPackMatcher.recordHit(DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js"));
        DropPackMatcher.recordHit(DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js"));
        assertEquals(3, DropPackMatcher.getHitCount(7));
        assertEquals(3, DropPackMatcher.getTotalDropped());
        // rebuild 换规则不清零，调规则时历史计数仍有参考价值
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(7, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "other")));
        assertEquals(3, DropPackMatcher.getHitCount(7));
        DropPackMatcher.recordHit(DropPackMatcher.firstMatch("any.com", "https://any.com/other.js"));
        assertEquals(4, DropPackMatcher.getHitCount(7));
    }

    @Test
    public void nullInputsDoNotThrow() {
        DropPackMatcher.rebuild(Collections.singletonList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, "noise")));
        assertNull(DropPackMatcher.firstMatch(null, null));
        assertNull(DropPackMatcher.firstMatch(null, ""));
        DropPackMatcher.rebuild(new ArrayList<DropPackRule>(Arrays.asList(
                rule(1, DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, null), null)));
        assertNull(DropPackMatcher.firstMatch("any.com", "https://any.com/noise.js"));
    }
}
