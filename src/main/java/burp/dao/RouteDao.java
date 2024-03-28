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

    // 获取所有路由
    public static List<RouteBean> getRouteList(){
        List<RouteBean> datas = new ArrayList<>();
        String routesql = "select * from route ";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(routesql);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                RouteBean route = new RouteBean();
                route.setEnable(resultSet.getInt("enable"));
                route.setName(resultSet.getString("name"));
                route.setPath(resultSet.getString("path"));
                route.setExpress(resultSet.getString("express"));
                datas.add(route);

            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return datas;
    }

    // 获取没有关闭的路由
    public static List<RouteBean> getRouteListNoClose(){
        List<RouteBean> datas = new ArrayList<>();
        String routesql = "select * from route where enable =1 ";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(routesql);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                RouteBean route = new RouteBean();
                route.setEnable(resultSet.getInt("enable"));
                route.setName(resultSet.getString("name"));
                route.setPath(resultSet.getString("path"));
                route.setExpress(resultSet.getString("express"));
                datas.add(route);

            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return datas;
    }

    // 关闭指定路由
    public static void closeOrOpenRoute(int enable, String name){
        String sql = "update route set enable = ? where name = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setInt(1, enable);
            ps.setString(2, name);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }
    // 添加路由
    public static void addRoute(RouteBean route){
        String sql = "insert into route (enable, name, path, express) values (?, ?, ?, ?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setInt(1, route.getEnable());
            ps.setString(2, route.getName());
            ps.setString(3, route.getPath());
            ps.setString(4, route.getExpress());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

}
