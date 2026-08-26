package burp.utils;

import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class I18nUtilsTest {
    @After
    public void restoreDefaultLanguage() {
        I18nUtils.setLanguage(I18nUtils.Language.ENGLISH);
    }

    @Test
    public void formatsChineseSqlBlindMessagesWithoutRawPlaceholders() {
        I18nUtils.setLanguage(I18nUtils.Language.CHINESE);

        String numeric = I18nUtils.format(
                "sql.vuln.possible_blind",
                "id",
                I18nUtils.get("sql.blind.type.number")
        );
        String quoteBased = I18nUtils.format(
                "sql.vuln.possible_blind",
                "name",
                I18nUtils.get("sql.blind.type.quote")
        );
        String json = I18nUtils.format("sql.vuln.json_blind", "user.id");

        assertEquals("参数id可能存在数字型盲注", numeric);
        assertEquals("参数name可能存在引号型盲注", quoteBased);
        assertEquals("JSON参数user.id可能存在盲注", json);
        assertNoRawPlaceholders(numeric);
        assertNoRawPlaceholders(quoteBased);
        assertNoRawPlaceholders(json);
    }

    @Test
    public void formatsEnglishSqlBlindMessagesWithoutRawPlaceholders() {
        I18nUtils.setLanguage(I18nUtils.Language.ENGLISH);

        String message = I18nUtils.format(
                "sql.vuln.possible_blind",
                "id",
                I18nUtils.get("sql.blind.type.number")
        );

        assertEquals("Parameter id may have numeric blind injection", message);
        assertNoRawPlaceholders(message);
    }

    @Test
    public void formatsSqlIssueDetailsWithAllArguments() {
        I18nUtils.setLanguage(I18nUtils.Language.CHINESE);

        String detail = I18nUtils.format("sql.issue.json_blind", "user.id", 100, 80, 101);

        assertEquals("在JSON参数user.id中发现SQL盲注\n原始长度:100\n单引号长度:80\n双引号长度:101", detail);
        assertNoRawPlaceholders(detail);
    }

    private static void assertNoRawPlaceholders(String value) {
        assertFalse(value.contains("{0}"));
        assertFalse(value.contains("{1}"));
        assertFalse(value.contains("{2}"));
        assertFalse(value.contains("{3}"));
    }
}

