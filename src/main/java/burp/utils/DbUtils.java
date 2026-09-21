package burp.utils;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * SQLite 存储层：数据库文件位于 ~/.gather/gatherburp.db。
 * init() 每次插件加载执行：建目录 + 幂等建表 + 迁移旧库。
 * 各 DAO 通过 getConnection() 获取连接（调用方负责关闭）。
 */
public class DbUtils {
    public static String DB_NAME = "gatherburp.db";
    public static String PROJECT_PATH = System.getProperty("user.home") + "/.gather/";
    public static String DB_PATH = System.getProperty("user.home") + "/.gather/" + DB_NAME;
    public static String DB_URL = "jdbc:sqlite:" + DB_PATH;
    public static String DB_DRIVER = "org.sqlite.JDBC";

    static {
        try {
            Class.forName(DB_DRIVER);
        } catch (ClassNotFoundException e) {
            logError(I18nUtils.format("db.message.driver_failed", e.getMessage()));
        }
    }

    /**
     * 创建数据目录、应用幂等 schema 并迁移旧库。每次插件加载执行，
     * 确保删除/损坏的数据库文件或新增的表/索引能被修复。
     */
    public static synchronized void init() {
        try {
            Files.createDirectories(Paths.get(PROJECT_PATH));
            create();
        } catch (Exception e) {
            logError(I18nUtils.format("db.message.init_failed", e.getMessage()));
        }
    }

    /** 获取 SQLite 连接（调用方负责关闭）。 */
    public static Connection getConnection() throws SQLException {
        Connection connection = DriverManager.getConnection(DB_URL);
        configureConnection(connection);
        return connection;
    }

    /** 幂等建表 + 迁移：全量执行 schema（CREATE/INDEX），仅在全新库时执行 INSERT 种子数据。 */
    public static synchronized void create() {
        try (Connection connection = getConnection()) {
            connection.setAutoCommit(false);
            try {
                boolean freshDatabase = !tableExists(connection, "config");
                List<String> sqlStatements = readSqlFromResource();

                // Always apply schema/index changes, but only seed a newly-created database.
                // Re-seeding on every startup would silently restore rows deliberately deleted
                // by the user from the configuration UI.
                for (String sql : sqlStatements) {
                    if (sql == null || sql.trim().isEmpty() || isSeedStatement(sql)) {
                        continue;
                    }
                    try (Statement statement = connection.createStatement()) {
                        statement.execute(sql);
                    }
                }
                migrateConfigTable(connection);

                if (freshDatabase) {
                    for (String sql : sqlStatements) {
                        if (!isSeedStatement(sql)) {
                            continue;
                        }
                        try (Statement statement = connection.createStatement()) {
                            statement.execute(sql);
                        }
                    }
                }
                connection.commit();
                logInfo(I18nUtils.get("db.message.init_success"));
            } catch (Exception e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (Exception e) {
            logError(I18nUtils.format("db.message.schema_failed", e.getMessage()));
        }
    }

    /** 配置连接 PRAGMA（外键 + busy_timeout）。 */
    private static void configureConnection(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 5000");
        }
    }

    /** 判断 SQL 是否为 INSERT 种子语句。 */
    private static boolean isSeedStatement(String sql) {
        return sql != null && sql.trim().toUpperCase(java.util.Locale.ROOT).startsWith("INSERT ");
    }

    /** 迁移旧 config 表（type UNIQUE → module+type UNIQUE），已迁移则跳过。 */
    static void migrateConfigTable(Connection connection) throws SQLException {
        if (!tableExists(connection, "config") || hasCompositeConfigUniqueIndex(connection)) {
            return;
        }

        try (Statement statement = connection.createStatement()) {
            statement.execute("DROP TABLE IF EXISTS config_migration_new");
            statement.execute("CREATE TABLE config_migration_new (" +
                    "id INTEGER PRIMARY KEY, " +
                    "module TEXT NOT NULL, " +
                    "type TEXT NOT NULL, " +
                    "value TEXT, " +
                    "UNIQUE(module, type))");
            statement.execute("INSERT OR REPLACE INTO config_migration_new (id, module, type, value) " +
                    "SELECT id, COALESCE(module, ''), type, value FROM config WHERE type IS NOT NULL ORDER BY id");
            statement.execute("DROP TABLE config");
            statement.execute("ALTER TABLE config_migration_new RENAME TO config");
        }
        logInfo(I18nUtils.get("db.message.migrated_config"));
    }

    /** 判断表是否存在。 */
    private static boolean tableExists(Connection connection, String tableName) throws SQLException {
        String sql = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, tableName);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    /** 判断 config 表是否已有 (module, type) 复合唯一索引。 */
    private static boolean hasCompositeConfigUniqueIndex(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet indexes = statement.executeQuery("PRAGMA index_list('config')")) {
            while (indexes.next()) {
                if (indexes.getInt("unique") != 1) {
                    continue;
                }
                String indexName = indexes.getString("name");
                List<String> columns = new ArrayList<>();
                String escapedName = indexName.replace("'", "''");
                try (Statement indexStatement = connection.createStatement();
                     ResultSet indexInfo = indexStatement.executeQuery("PRAGMA index_info('" + escapedName + "')")) {
                    while (indexInfo.next()) {
                        columns.add(indexInfo.getString("name"));
                    }
                }
                if (columns.equals(Arrays.asList("module", "type"))) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 从 classpath 读取 sql/init.sql 并按分号拆分为语句列表。 */
    private static List<String> readSqlFromResource() {
        List<String> sqls = new ArrayList<>();
        try (InputStream is = DbUtils.class.getClassLoader().getResourceAsStream("sql/init.sql")) {
            if (is == null) {
                throw new IllegalStateException("Could not find sql/init.sql resource");
            }
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                StringBuilder sb = new StringBuilder();
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("--")) continue;
                    sb.append(line);
                    if (line.endsWith(";")) {
                        sqls.add(sb.toString());
                        sb.setLength(0);
                    } else {
                        sb.append(' ');
                    }
                }
                if (sb.length() > 0) sqls.add(sb.toString());
            }
        } catch (Exception e) {
            throw new IllegalStateException("Error reading SQL resource", e);
        }
        return sqls;
    }

    /** 安全关闭连接/预编译语句/结果集（任一为 null 跳过）。 */
    public static void close(Connection connection, PreparedStatement preparedStatement, ResultSet resultSet) {
        try {
            if (resultSet != null) resultSet.close();
            if (preparedStatement != null) preparedStatement.close();
            if (connection != null) connection.close();
        } catch (Exception e) {
            logError(e.getMessage());
        }
    }

    /** 信息日志：优先写 Burp stdout，未注入时写 System.out。 */
    private static void logInfo(String message) {
        if (Utils.stdout != null) Utils.stdout.println(message);
        else System.out.println(message);
    }

    /** 错误日志：优先写 Burp stderr，未注入时写 System.err。 */
    private static void logError(String message) {
        if (Utils.stderr != null) Utils.stderr.println(message);
        else System.err.println(message);
    }
}
