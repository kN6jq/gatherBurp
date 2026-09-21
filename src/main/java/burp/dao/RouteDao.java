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
     * 精选 Java 框架路由泄露默认规则：{name, path, express}。
     * 聚焦实战常见的 Spring Boot Actuator、Swagger/OpenAPI、Druid、Nacos、XXL-JOB、JeecgBoot，
     * 每条均以「状态码 + 响应特征」组合降低误报。去掉 heapdump(响应过大易卡死)等冷门项。
     */
    private static final String[][] DEFAULT_RULES = {
            // Spring Boot Actuator
            {"Actuator", "/actuator", "code=\"200\" && body=\"_links\""},
            {"Actuator Env", "/actuator/env", "code=\"200\" && body=\"propertySources\""},
            {"Actuator Loggers", "/actuator/loggers", "code=\"200\" && body=\"configuredLevel\""},
            // Druid 连接池监控未授权
            {"Druid Monitor", "/druid/index.html", "code=\"200\" && body=\"Druid Stat Index\""},
            // Swagger / OpenAPI：swagger/openapi 一词太泛，叠加 JSON 结构特征降误报
            {"Swagger v2", "/v2/api-docs", "code=\"200\" && body=\"swagger\" && body=\"paths\""},
            {"OpenAPI v3", "/v3/api-docs", "code=\"200\" && body=\"openapi\" && body=\"paths\""},
            // Nacos 未授权：列用户 / 读配置（分页壳字段 totalCount + 数据字段双特征）
            {"Nacos Users", "/nacos/v1/auth/users?pageNo=1&pageSize=10", "code=\"200\" && body=\"username\" && body=\"totalCount\""},
            {"Nacos Configs", "/nacos/v1/cs/configs?search=accurate&pageNo=1&pageSize=10", "code=\"200\" && body=\"dataId\" && body=\"totalCount\""},
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