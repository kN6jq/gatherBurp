package burp.utils;

import burp.bean.ConfigBean;
import burp.bean.SimilarDomainResultBean;
import burp.dao.ConfigDao;
import burp.dao.SimilarDomainResultDao;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Comparator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DbUtilsTest {
    private String originalProjectPath;
    private String originalDbPath;
    private String originalDbUrl;
    private Path tempDirectory;

    @Before
    public void setUp() throws Exception {
        originalProjectPath = DbUtils.PROJECT_PATH;
        originalDbPath = DbUtils.DB_PATH;
        originalDbUrl = DbUtils.DB_URL;

        tempDirectory = Files.createTempDirectory("gatherburp-db-test-");
        DbUtils.PROJECT_PATH = tempDirectory.toString();
        DbUtils.DB_PATH = tempDirectory.resolve("test.db").toString();
        DbUtils.DB_URL = "jdbc:sqlite:" + DbUtils.DB_PATH;
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
    public void initIsIdempotentAndConfigKeyIncludesModule() throws Exception {
        DbUtils.init();
        DbUtils.init();

        ConfigDao.saveConfig(new ConfigBean("module-a", "shared-type", "one"));
        ConfigDao.saveConfig(new ConfigBean("module-b", "shared-type", "two"));
        ConfigDao.saveConfig(new ConfigBean("module-a", "shared-type", "updated"));

        assertEquals("updated", ConfigDao.getConfig("module-a", "shared-type").getValue());
        assertEquals("two", ConfigDao.getConfig("module-b", "shared-type").getValue());

        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(
                     "SELECT COUNT(*) FROM config WHERE type = 'shared-type'");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals(2, rs.getInt(1));
        }
    }

    @Test
    public void legacyConfigUniqueTypeIsMigrated() throws Exception {
        Files.createDirectories(tempDirectory);
        try (Connection connection = DriverManager.getConnection(DbUtils.DB_URL);
             Statement statement = connection.createStatement()) {
            statement.execute("CREATE TABLE config (id INTEGER PRIMARY KEY, module TEXT, type TEXT, value TEXT, UNIQUE(type))");
            statement.execute("INSERT INTO config VALUES (100, 'legacy', 'shared-type', 'legacy-value')");
        }

        DbUtils.create();
        ConfigDao.saveConfig(new ConfigBean("new-module", "shared-type", "new-value"));

        assertEquals("legacy-value", ConfigDao.getConfig("legacy", "shared-type").getValue());
        assertEquals("new-value", ConfigDao.getConfig("new-module", "shared-type").getValue());
    }

    @Test
    public void restartDoesNotRestoreUserDeletedSeedConfig() throws Exception {
        DbUtils.init();
        ConfigDao.deleteConfig("tool", "sqlmap");

        DbUtils.init();

        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(
                     "SELECT COUNT(*) FROM config WHERE module = 'tool' AND type = 'sqlmap'");
             ResultSet rs = ps.executeQuery()) {
            assertTrue(rs.next());
            assertEquals(0, rs.getInt(1));
        }
    }

    @Test
    public void similarDomainUpdateUsesExistingTimestampColumn() throws Exception {
        DbUtils.init();
        int projectId;
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(
                     "INSERT INTO projects(name, create_time) VALUES('test', datetime('now','localtime'))")) {
            ps.executeUpdate();
            try (Statement statement = connection.createStatement();
                 ResultSet rs = statement.executeQuery("SELECT last_insert_rowid()")) {
                assertTrue(rs.next());
                projectId = rs.getInt(1);
            }
        }

        SimilarDomainResultBean result = new SimilarDomainResultBean(projectId, "example.com", "1.1.1.1");
        int id = SimilarDomainResultDao.saveDomainResult(result);
        assertTrue(id > 0);
        result.setId(id);
        result.setIp("2.2.2.2");
        SimilarDomainResultDao.updateDomainResult(result);

        assertEquals("2.2.2.2", SimilarDomainResultDao.getDomainResults(projectId).get(0).getIp());
    }
}
