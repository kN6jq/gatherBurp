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
    // 获取多个
    public static List<Log4jBean> getLog4jListsByType(String type) {
        String sql = "SELECT * FROM log4j WHERE type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<Log4jBean> log4jBeans = new ArrayList<>();
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, type);
            rs = ps.executeQuery();
            while (rs.next()) {
                Log4jBean log4jBean = new Log4jBean();
                log4jBean.setId(rs.getInt("id"));
                log4jBean.setType(rs.getString("type"));
                log4jBean.setValue(rs.getString("value"));
                log4jBeans.add(log4jBean);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return log4jBeans;
    }
    // 获取一个
    public static Log4jBean getLog4jListByType(String type) {
        String sql = "SELECT * FROM log4j WHERE type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, type);
            rs = ps.executeQuery();
            while (rs.next()) {
                Log4jBean log4jBean = new Log4jBean();
                log4jBean.setId(rs.getInt("id"));
                log4jBean.setType(rs.getString("type"));
                log4jBean.setValue(rs.getString("value"));
                return log4jBean;
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return null;
    }
    // 保存
    public static void saveLog4j(Log4jBean log4jBean) {
        String sql = "INSERT INTO log4j(type, value) VALUES(?, ?)";
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
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }
    // 更新
    public static void updateLog4j(Log4jBean log4jBean) {
        String sql = "UPDATE log4j SET value = ? WHERE type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, log4jBean.getValue());
            ps.setString(2, log4jBean.getType());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }
    // 删除
    public static void deleteLog4jByType(String type) {
        String sql = "DELETE FROM log4j WHERE type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, type);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

}
