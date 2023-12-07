package burp.dao;

import burp.bean.ConfigBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;


public class ConfigDao {
    // 根据模块和类型获取配置
    public static ConfigBean getConfig(String module, String type) {
        ConfigBean config = new ConfigBean();
        String sql = "select value from config where module = ? and type = ? order by id desc limit 1";
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
            ps.setString(1, module);
            ps.setString(2, type);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                config.setValue(resultSet.getString("value"));
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return config;
    }

    // 删除配置
    public static void deleteConfig(String type) {
        String sql = "delete from config where type = ?";
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
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 根据id删除工具配置
    public static void deleteToolConfig(String type) {
        String sql = "delete from config where type = ?";
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
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 根据类型更新配置
    public static void updateConfig(ConfigBean config) {
        String sql = "update config set value = ? where type = ? and module = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, config.getValue());
            ps.setString(2, config.getType());
            ps.setString(3, config.getModule());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 保存配置
    public static void saveConfig(ConfigBean config) {
        String sql = "INSERT OR REPLACE INTO config (module, type, value) VALUES (?, ?, ?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, config.getModule());
            ps.setString(2, config.getType());
            ps.setString(3, config.getValue());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }

    }

    // 获取工具配置
    public static List<ConfigBean> getToolConfig() {
        List<ConfigBean> configs = new ArrayList<>();
        String sql = "select * from config where module = 'tool'";
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
                ConfigBean config = new ConfigBean();
                config.setId(resultSet.getInt("id"));
                config.setModule(resultSet.getString("module"));
                config.setType(resultSet.getString("type"));
                config.setValue(resultSet.getString("value"));
                configs.add(config);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return configs;
    }

}
