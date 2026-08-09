package burp.dao;

import burp.bean.Log4jBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class Log4jDao {
    public static List<Log4jBean> getLog4jListsByType(String type) {
        List<Log4jBean> log4jBeans = new ArrayList<>();
        String sql = "SELECT * FROM log4j WHERE type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, type);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setId(rs.getInt("id"));
                    log4jBean.setType(rs.getString("type"));
                    log4jBean.setValue(rs.getString("value"));
                    log4jBeans.add(log4jBean);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return log4jBeans;
    }

    public static Log4jBean getLog4jListByType(String type) {
        String sql = "SELECT * FROM log4j WHERE type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, type);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    Log4jBean log4jBean = new Log4jBean();
                    log4jBean.setId(rs.getInt("id"));
                    log4jBean.setType(rs.getString("type"));
                    log4jBean.setValue(rs.getString("value"));
                    return log4jBean;
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return null;
    }

    public static void saveLog4j(Log4jBean log4jBean) {
        String sql = "INSERT INTO log4j(type, value) VALUES(?, ?)";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, log4jBean.getType());
            ps.setString(2, log4jBean.getValue());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void updateLog4j(Log4jBean log4jBean) {
        String sql = "UPDATE log4j SET value = ? WHERE type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, log4jBean.getValue());
            ps.setString(2, log4jBean.getType());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void deleteLog4jByType(String type) {
        String sql = "DELETE FROM log4j WHERE type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, type);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

}