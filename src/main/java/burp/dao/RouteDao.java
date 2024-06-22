package burp.dao;

import burp.bean.RouteBean;
import burp.bean.SqlBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class RouteDao {
    // 获取所有规则
    public static List<RouteBean> getRouteLists(){
        String sql = "SELECT * FROM route";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<RouteBean> routeBeans = new ArrayList<>();
        try {
            ps = connection.prepareStatement(sql);
            rs = ps.executeQuery();
            while (rs.next()){
                RouteBean routeBean = new RouteBean();
                routeBean.setEnable(rs.getInt("enable"));
                routeBean.setName(rs.getString("name"));
                routeBean.setPath(rs.getString("path"));
                routeBean.setExpress(rs.getString("express"));
                routeBeans.add(routeBean);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return routeBeans;
    }
    // 通过id修改规则
    public static void updateRouteById(RouteBean routeBean){
        String sql = "UPDATE route SET enable = ?, name = ?, path = ?, express = ? WHERE id = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setInt(1, routeBean.getEnable());
            ps.setString(2, routeBean.getName());
            ps.setString(3, routeBean.getPath());
            ps.setString(4, routeBean.getExpress());
            ps.setInt(5, routeBean.getId());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }
    // 通过id修改enable
    public static void updateRouteEnable(RouteBean routeBean){
        String sql = "UPDATE route SET enable = ? WHERE name = ? and path = ? and express = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setInt(1, routeBean.getEnable());
            ps.setString(2, routeBean.getName());
            ps.setString(3, routeBean.getPath());
            ps.setString(4, routeBean.getExpress());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }

    }
    // 删除
    public static boolean deleteRoute(RouteBean routeBean){
        String sql = "DELETE FROM route WHERE name = ? and path = ? and express = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, routeBean.getName());
            ps.setString(2, routeBean.getPath());
            ps.setString(3, routeBean.getExpress());
            ps.executeUpdate();
            return true;
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
            return false;
        } finally {
            DbUtils.close(connection, ps, null);
        }

    }
    // 添加规则
    public static void addRoute(RouteBean routeBean){
        String sql = "INSERT INTO route (enable, name, path, express) VALUES (?, ?, ?, ?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setInt(1, routeBean.getEnable());
            ps.setString(2, routeBean.getName());
            ps.setString(3, routeBean.getPath());
            ps.setString(4, routeBean.getExpress());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }
}
