package burp.dao;

import burp.bean.RouteBean;
import burp.utils.DbUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Comparator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/** 老库弱特征词迁移：存量规则里的 body="location" / body="self" 必须被自动修正。 */
public class RouteDaoLegacyRuleFixTest {
    private String originalProjectPath;
    private String originalDbPath;
    private String originalDbUrl;
    private Path tempDirectory;

    @Before
    public void setUp() throws Exception {
        originalProjectPath = DbUtils.PROJECT_PATH;
        originalDbPath = DbUtils.DB_PATH;
        originalDbUrl = DbUtils.DB_URL;
        tempDirectory = Files.createTempDirectory("gatherburp-route-fix-test-");
        DbUtils.PROJECT_PATH = tempDirectory.toString();
        DbUtils.DB_PATH = tempDirectory.resolve("test.db").toString();
        DbUtils.DB_URL = "jdbc:sqlite:" + DbUtils.DB_PATH;
        DbUtils.init();
    }

    @After
    public void tearDown() throws Exception {
        DbUtils.PROJECT_PATH = originalProjectPath;
        DbUtils.DB_PATH = originalDbPath;
        DbUtils.DB_URL = originalDbUrl;
        if (tempDirectory != null && Files.exists(tempDirectory)) {
            Files.walk(tempDirectory)
                    .sorted(Comparator.reverseOrder())
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (Exception ignored) {
                        }
                    });
        }
    }

    @Test
    public void legacyWeakKeywordsAreReplacedAndOthersUntouched() throws Exception {
        // 模拟老版本种子写入的存量规则（当前种子文件已修复，老用户库里还是旧表达式）
        insertRule("Swagger Resources", "/swagger-resources",
                "code=\"200\" && (body=\"swaggerVersion\" || body=\"location\")");
        insertRule("Spring Actuator", "/actuator",
                "code=\"200\" && (body=\"health\" || body=\"self\" || body=\"_links\")");
        // 正常规则不应被改动
        insertRule("Git Leak", "/.git/config", "code=\"200\" && body=\"repositoryformatversion\"");

        RouteDao.ensureDefaultRules();

        List<RouteBean> rules = RouteDao.getRouteLists();
        String swaggerExpress = findExpress(rules, "/swagger-resources");
        String actuatorExpress = findExpress(rules, "/actuator");
        String gitExpress = findExpress(rules, "/.git/config");

        assertFalse("location 弱词必须被替换: " + swaggerExpress,
                swaggerExpress.contains("body=\"location\""));
        assertTrue(swaggerExpress.contains("body=\"api-docs\""));
        assertTrue(swaggerExpress.contains("body=\"swaggerVersion\""));
        assertFalse("self 弱词必须被移除: " + actuatorExpress,
                actuatorExpress.contains("body=\"self\""));
        assertTrue(actuatorExpress.contains("body=\"_links\""));
        assertEquals("code=\"200\" && body=\"repositoryformatversion\"", gitExpress);
    }

    @Test
    public void freshSeedsContainNoWeakKeywords() {
        RouteDao.ensureDefaultRules();
        for (RouteBean rule : RouteDao.getRouteLists()) {
            assertFalse("种子规则含弱特征词 body=\"location\": " + rule.getPath(),
                    rule.getExpress().contains("body=\"location\""));
            assertFalse("种子规则含弱特征词 body=\"self\": " + rule.getPath(),
                    rule.getExpress().contains(" || body=\"self\""));
        }
    }

    @Test
    public void migrationIsIdempotent() throws Exception {
        insertRule("Swagger Resources", "/swagger-resources",
                "code=\"200\" && (body=\"swaggerVersion\" || body=\"location\")");
        RouteDao.ensureDefaultRules();
        RouteDao.ensureDefaultRules();
        RouteDao.ensureDefaultRules();

        List<RouteBean> rules = RouteDao.getRouteLists();
        String express = findExpress(rules, "/swagger-resources");
        assertEquals(1, countOccurrences(express, "body=\"api-docs\""));
    }

    private static void insertRule(String name, String path, String express) throws Exception {
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(
                     "INSERT INTO route (enable, name, path, express) VALUES (1, ?, ?, ?)")) {
            ps.setString(1, name);
            ps.setString(2, path);
            ps.setString(3, express);
            ps.executeUpdate();
        }
    }

    private static String findExpress(List<RouteBean> rules, String path) {
        List<String> candidates = new ArrayList<>();
        for (RouteBean rule : rules) {
            if (path.equals(rule.getPath())) {
                candidates.add(rule.getExpress());
            }
        }
        // ensureDefaultRules 只按 path 去重，不插入重复行；这里取首条即可
        assertTrue("规则未找到: " + path, !candidates.isEmpty());
        return candidates.get(0);
    }

    private static int countOccurrences(String text, String needle) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(needle, index)) != -1) {
            count++;
            index += needle.length();
        }
        return count;
    }
}
