package burp.dao;

import burp.bean.Log4jBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class Log4jDao {
    public static List<Log4jBean> getPayloadList() {
        List<Log4jBean> datas = new ArrayList<>();
        String sql = "select * from log4j where type = 'payload'";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                Log4jBean config = new Log4jBean();
                config.setId(resultSet.getInt("id"));
                config.setType(resultSet.getString("type"));
                config.setValue(resultSet.getString("value"));
                datas.add(config);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return datas;
    }

    public static List<Log4jBean> getHeaderList() {
        List<Log4jBean> datas = new ArrayList<>();
        String sql = "select * from log4j where type = 'header'";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                Log4jBean config = new Log4jBean();
                config.setId(resultSet.getInt("id"));
                config.setType(resultSet.getString("type"));
                config.setValue(resultSet.getString("value"));
                datas.add(config);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return datas;
    }

    public static void deleteHeader() {
        String sql = "delete from log4j where type = 'header'";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.executeUpdate();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    public static void saveHeader(Log4jBean log4jBean) {
        String sql = "insert into log4j(type,value) values(?,?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, log4jBean.getType());
            ps.setString(2, log4jBean.getValue());
            ps.executeUpdate();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    public static void deletePayload() {
        String sql = "delete from log4j where type = 'payload'";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.executeUpdate();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    public static void savePayload(Log4jBean log4jBean) {
        String sql = "insert into log4j(type,value) values(?,?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, log4jBean.getType());
            ps.setString(2, log4jBean.getValue());
            ps.executeUpdate();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

}
