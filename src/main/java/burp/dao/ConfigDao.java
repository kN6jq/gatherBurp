package burp.dao;

import burp.bean.ConfigBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class ConfigDao {
    public static ConfigBean getConfig(String module, String type) {
        ConfigBean config = new ConfigBean();
        String sql = "select value from config where module = ? and type = ? order by id desc limit 1";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, module);
            ps.setString(2, type);
            try (ResultSet resultSet = ps.executeQuery()) {
                while (resultSet.next()) {
                    config.setValue(resultSet.getString("value"));
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return config;
    }

    public static void deleteConfig(String type) {
        deleteConfig(null, type);
    }

    public static void deleteConfig(String module, String type) {
        String sql = module == null
                ? "delete from config where type = ?"
                : "delete from config where module = ? and type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            if (module == null) {
                ps.setString(1, type);
            } else {
                ps.setString(1, module);
                ps.setString(2, type);
            }
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void updateConfig(ConfigBean config) {
        String sql = "update config set value = ? where type = ? and module = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, config.getValue());
            ps.setString(2, config.getType());
            ps.setString(3, config.getModule());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void saveConfig(ConfigBean config) {
        String sql = "INSERT INTO config (module, type, value) VALUES (?, ?, ?) " +
                "ON CONFLICT(module, type) DO UPDATE SET value = excluded.value";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, config.getModule());
            ps.setString(2, config.getType());
            ps.setString(3, config.getValue());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static List<ConfigBean> getToolConfig() {
        List<ConfigBean> configs = new ArrayList<>();
        String sql = "select * from config where module = 'tool'";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            try (ResultSet resultSet = ps.executeQuery()) {
                while (resultSet.next()) {
                    ConfigBean config = new ConfigBean();
                    config.setId(resultSet.getInt("id"));
                    config.setModule(resultSet.getString("module"));
                    config.setType(resultSet.getString("type"));
                    config.setValue(resultSet.getString("value"));
                    configs.add(config);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return configs;
    }
}
