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
}