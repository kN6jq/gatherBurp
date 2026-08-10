package burp.dao;

import burp.bean.RouteBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class RouteDao {
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
     * 聚焦 Spring Boot Actuator、Swagger/OpenAPI、Druid、Eureka、Nacos、JBoss 等高频端点，
     * 每条均以「状态码 + 响应特征」组合降低误报，精选而非堆量。
     */
    private static final String[][] DEFAULT_RULES = {
            {"Actuator", "/actuator", "code=\"200\" && body=\"_links\""},
            {"Actuator Env", "/actuator/env", "code=\"200\" && body=\"propertySources\""},
            {"Actuator Heapdump", "/actuator/heapdump", "code=\"200\" && headers=\"heapdump\""},
            {"Actuator Loggers", "/actuator/loggers", "code=\"200\" && body=\"configuredLevel\""},
            {"Swagger UI", "/swagger-ui.html", "code=\"302\" || (code=\"200\" && body=\"swagger-ui\")"},
            {"Swagger v2", "/v2/api-docs", "code=\"200\" && body=\"swagger\""},
            {"OpenAPI v3", "/v3/api-docs", "code=\"200\" && body=\"openapi\""},
            {"Druid Monitor", "/druid/index.html", "code=\"200\" && (body=\"Druid Stat Index\" || title=\"Druid Stat Index\")"},
            {"Eureka Apps", "/eureka/apps", "code=\"200\" && body=\"<applications>\""},
            {"Nacos Console", "/nacos/", "code=\"200\" && (title=\"Nacos\" || body=\"Nacos\")"},
            {"JBoss JMX Console", "/jmx-console", "code=\"200\" && body=\"JBoss\""},
    };

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