package burp.dao;

import burp.bean.RouteBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/** 目录探测规则（route 表）数据访问：所有方法在 EDT（规则管理界面）调用；
 *  异常统一打 stderr，读方法降级为空列表、写方法静默失败。 */
public class RouteDao {
    /** 读取全部规则。失败时返回空列表（界面表现为无规则）。 */
    public static List<RouteBean> getRouteLists(){
        String sql = "SELECT * FROM route";
        List<RouteBean> routeBeans = new ArrayList<>();
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()){
                    RouteBean routeBean = new RouteBean();
                    routeBean.setEnable(rs.getInt("enable"));
                    routeBean.setName(rs.getString("name"));
                    routeBean.setPath(rs.getString("path"));
                    routeBean.setExpress(rs.getString("express"));
                    routeBeans.add(routeBean);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return routeBeans;
    }

    /** 更新指定 id 的规则（enable/name/path/express）。 */
    public static void updateRouteById(RouteBean routeBean){
        String sql = "UPDATE route SET enable = ?, name = ?, path = ?, express = ? WHERE id = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, routeBean.getEnable());
            ps.setString(2, routeBean.getName());
            ps.setString(3, routeBean.getPath());
            ps.setString(4, routeBean.getExpress());
            ps.setInt(5, routeBean.getId());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    /** 仅切换规则的 enable 字段（按 name+path+express 定位）。 */
    public static void updateRouteEnable(RouteBean routeBean){
        String sql = "UPDATE route SET enable = ? WHERE name = ? and path = ? and express = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, routeBean.getEnable());
            ps.setString(2, routeBean.getName());
            ps.setString(3, routeBean.getPath());
            ps.setString(4, routeBean.getExpress());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    /** 按 name+path+express 删除规则。返回是否执行成功。 */
    public static boolean deleteRoute(RouteBean routeBean){
        String sql = "DELETE FROM route WHERE name = ? and path = ? and express = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, routeBean.getName());
            ps.setString(2, routeBean.getPath());
            ps.setString(3, routeBean.getExpress());
            ps.executeUpdate();
            return true;
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
            return false;
        }
    }

    /** 插入一条新规则。 */
    public static void addRoute(RouteBean routeBean){
        String sql = "INSERT INTO route (enable, name, path, express) VALUES (?, ?, ?, ?)";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, routeBean.getEnable());
            ps.setString(2, routeBean.getName());
            ps.setString(3, routeBean.getPath());
            ps.setString(4, routeBean.getExpress());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    /**
     * 默认探测规则集 {name, path, express}：吸收外部高质量规则集并按本项目 DSL 改写
     * （仅用 code/body/headers/title + = != && || 与括号嵌套，needle 不含引号/转义序列），
     * 覆盖 Swagger 全家桶 / Spring Actuator / Jolokia / Tomcat / Git·SVN·DS_Store 泄露 /
     * Nacos / Druid / S3 / Prometheus Metrics / WSDL，并保留本地独有的
     * Actuator Loggers、Nacos Users/Configs、XXL-JOB、JeecgBoot 组合。
     */
    private static final String[][] DEFAULT_RULES = {
            // Swagger UI 页面
            {"Swagger UI", "/swagger-ui.html", "code=\"200\" && (body=\"swagger-ui.css\" || body=\"swagger-ui.js\" || title=\"Swagger UI\")"},
            {"Swagger UI", "/swagger-ui/index.html", "code=\"200\" && (body=\"swagger-ui.css\" || body=\"swagger-ui.js\" || title=\"Swagger UI\")"},
            {"Swagger UI", "/swagger/index.html", "code=\"200\" && (body=\"swagger-ui.css\" || body=\"swagger-ui.js\" || title=\"Swagger UI\")"},
            // Swagger Resources
            {"Swagger Resources", "/swagger-resources", "code=\"200\" && (body=\"swaggerVersion\" || body=\"location\")"},
            {"Swagger Resources", "/api/swagger-resources", "code=\"200\" && (body=\"swaggerVersion\" || body=\"location\")"},
            // swagger.json 系列（文档 JSON 必带 info 段，与 swagger/openapi 版本字段组合判）
            {"Swagger", "/v1/swagger.json", "code=\"200\" && body=\"info\" && (body=\"swagger\" || body=\"openapi\")"},
            {"Swagger", "/v2/swagger.json", "code=\"200\" && body=\"info\" && (body=\"swagger\" || body=\"openapi\")"},
            {"Swagger", "/swagger.json", "code=\"200\" && body=\"info\" && (body=\"swagger\" || body=\"openapi\")"},
            // OpenAPI 文档端点
            {"Swagger API Doc", "/v2/api-docs", "code=\"200\" && body=\"info\" && (body=\"swagger\" || body=\"openapi\")"},
            {"Swagger API Doc", "/v3/api-docs", "code=\"200\" && body=\"info\" && (body=\"swagger\" || body=\"openapi\")"},
            {"Swagger API Doc", "/api/v2/api-docs", "code=\"200\" && body=\"info\" && (body=\"swagger\" || body=\"openapi\")"},
            // Spring Boot Actuator
            {"Spring Actuator Env", "/env", "code=\"200\" && (body=\"java.version\" || body=\"os.arch\")"},
            {"Spring Actuator Env", "/actuator/env", "code=\"200\" && (body=\"java.version\" || body=\"os.arch\")"},
            {"Spring Actuator", "/actuator", "code=\"200\" && (body=\"health\" || body=\"self\" || body=\"_links\" || headers=\"application/vnd.spring-boot.actuator\")"},
            {"Spring Actuator", "/api/actuator", "code=\"200\" && (body=\"health\" || body=\"self\" || body=\"_links\" || headers=\"application/vnd.spring-boot.actuator\")"},
            {"Spring Actuator Loggers", "/actuator/loggers", "code=\"200\" && body=\"configuredLevel\""},
            // Spring Jolokia（Actuator 下可 RCE）
            {"Spring Jolokia", "/jolokia/list", "code=\"200\" && (body=\"springframework\" || body=\"reloadByURL\" || body=\"createJNDIRealm\")"},
            {"Spring Jolokia", "/actuator/jolokia/list", "code=\"200\" && (body=\"springframework\" || body=\"reloadByURL\" || body=\"createJNDIRealm\")"},
            // Tomcat 示例/管理后台
            {"Tomcat Session Example", "/examples/servlets/servlet/SessionExample", "title=\"Sessions Example\" || (body=\"../sessions.html\" && body=\"SessionExample;\")"},
            {"Tomcat Manager App", "/manager/html", "title=\"401 Unauthorized\" || title=\"403 Access Denied\" || (body=\"manager-gui\" && body=\"s3cret\")"},
            // 版本控制 / 系统文件泄露
            {"Git Leak", "/.git/config", "code=\"200\" && body=\"repositoryformatversion\""},
            {"SVN Leak", "/.svn/entries", "code=\"200\" && body=\"dir\" && body=\"file\""},
            {"DS_Store Leak", "/.DS_Store", "code=\"200\" && body=\"Bud1\""},
            // Nacos：控制台指纹 / 列用户 / 读配置
            {"Nacos", "/nacos/v1/console/server/state", "code=\"200\" && body=\"auth_enabled\" && body=\"false\""},
            {"Nacos Users", "/nacos/v1/auth/users?pageNo=1&pageSize=10", "code=\"200\" && body=\"username\" && body=\"totalCount\""},
            {"Nacos Configs", "/nacos/v1/cs/configs?search=accurate&pageNo=1&pageSize=10", "code=\"200\" && body=\"dataId\" && body=\"totalCount\""},
            // Druid 连接池监控未授权
            {"Alibaba Druid", "/druid/index.html", "code=\"200\" && title=\"Druid Stat Index\""},
            // S3 兼容存储桶列表泄露
            {"S3 Bucket Listing", "/", "body=\"<ListBucketResult \" && body=\"<?xml \""},
            // Prometheus node_exporter 未授权
            {"Metrics", "/metrics", "code=\"200\" && body=\"# HELP node_uname_info\" && body=\"# TYPE node_uname_info gauge\""},
            // WebService WSDL 列表
            {"WSDL Service", "/services", "code=\"200\" && (body=\"Available SOAP services:\" || body=\"Available Services:\") && body=\"?wsdl\""},
            // XXL-JOB 后台（默认 admin/123456，空 token 可 RCE）
            {"XXL-JOB Admin", "/xxl-job-admin/toLogin", "code=\"200\" && (title=\"XXL-JOB\" || body=\"XXL-JOB\")"},
            // JeecgBoot 标识接口 / 积木报表 SQL 注入点(405=端点存在但需 POST)
            {"JeecgBoot", "/sys/getCheckCode", "code=\"200\" && body=\"checkKey\""},
            {"JeecgBoot JMReport", "/jmreport/queryFieldBySql", "code=\"405\""},
    };

    /**
     * 重置规则：清空 route 表（含用户自定义与历史遗留行）后重新播种 DEFAULT_RULES。
     * ensureDefaultRules 按 path 去重只增不删，旧版本种子行需靠本方法清理。
     */
    public static void resetToDefaults() {
        try (Connection connection = DbUtils.getConnection();
             java.sql.Statement statement = connection.createStatement()) {
            statement.execute("DELETE FROM route");
        } catch (Exception e) {
            Utils.stderr.println("reset route rules failed: " + e.getMessage());
            return;
        }
        ensureDefaultRules();
    }

    /**
     * 按 path 去重补齐默认规则：某 path 不存在则插入；已存在（含用户自定义）则保留不动。
     * 幂等，每次加载规则前调用安全；init.sql 不再内置 route 数据，新老用户均由此补齐。
     */
    public static void ensureDefaultRules() {
        String checkSql = "SELECT COUNT(*) FROM route WHERE path = ?";
        String insertSql = "INSERT INTO route (enable, name, path, express) VALUES (?, ?, ?, ?)";
        try (Connection connection = DbUtils.getConnection()) {
            for (String[] r : DEFAULT_RULES) {
                boolean exists = false;
                try (PreparedStatement ps = connection.prepareStatement(checkSql)) {
                    ps.setString(1, r[1]);
                    try (ResultSet rs = ps.executeQuery()) {
                        if (rs.next()) exists = rs.getInt(1) > 0;
                    }
                }
                if (exists) continue;
                try (PreparedStatement ps = connection.prepareStatement(insertSql)) {
                    ps.setInt(1, 1);
                    ps.setString(2, r[0]);
                    ps.setString(3, r[1]);
                    ps.setString(4, r[2]);
                    ps.executeUpdate();
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("seed route rules failed: " + e.getMessage());
        }
    }
}