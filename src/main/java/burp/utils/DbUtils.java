package burp.utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

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
            System.err.println("Failed to load SQLite driver: " + e.getMessage());
        }
    }

    /**
     * Initialize database — must be called AFTER Utils.stdout/stderr are set up.
     * Creates the data directory and database tables if they don't exist.
     */
    public static synchronized void init() {
        Path path = Paths.get(PROJECT_PATH);
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
                Utils.stdout.println("init filepath success");
            } catch (Exception e) {
                Utils.stderr.println("创建文件夹失败");
            }
            create();
        }
    }

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }

    // 如果数据库不存在，创建数据库
    public static void create() {
        // 判断数据库是否存在
        try {
            Connection connection = DriverManager.getConnection(DB_URL);
            List<String> sqls = readSqlFromResource();

            for (String sql : sqls) {
                if (sql == null || sql.trim().isEmpty()) continue;
                Statement statement = connection.createStatement();
                statement.execute(sql);
                statement.close();
            }
            Utils.stdout.println("init db success");
        } catch (SQLException e) {
            System.out.println(e.getMessage());
            Utils.stderr.println(e.getMessage());
        }
    }

    private static List<String> readSqlFromResource() {
        List<String> sqls = new ArrayList<>();
        try (InputStream is = DbUtils.class.getClassLoader().getResourceAsStream("sql/init.sql")) {
            if (is == null) {
                throw new RuntimeException("Could not find sql/init.sql resource");
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
                        sb.append(" ");
                    }
                }
                if (sb.length() > 0) {
                    sqls.add(sb.toString());
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("Error reading SQL resource: " + e.getMessage());
        }
        return sqls;
    }

    public static void close(Connection connection, PreparedStatement preparedStatement, ResultSet resultSet) {
        try {
            if (connection != null) {
                connection.close();
            }
            if (preparedStatement != null) {
                preparedStatement.close();
            }
            if (resultSet != null) {
                resultSet.close();
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

}
