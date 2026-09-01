package burp.dao;

import burp.bean.ConfigBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/** 通用配置（config 表，按 module+type 唯一）数据访问：异常统一打 stderr 并降级
 *  （读返回空对象/空列表，写静默失败）。getConfig 无匹配时返回 value 为 null 的空 ConfigBean，
 *  调用方需判空（参考各 UI 的 safeConfigValue）。 */
public class ConfigDao {
    /** 读取 (module, type) 的最新一行配置。无匹配时返回 value 为 null 的空对象。 */
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

    /** 删除某 type 下全部模块的配置（module=null 通配）。 */
    public static void deleteConfig(String type) {
        deleteConfig(null, type);
    }

    /** 删除指定 (module, type) 的配置。module 为 null 时按 type 通配全部模块。 */
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

    /** 更新 (module, type) 对应的 value。无匹配行时静默无效。 */
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

    /** upsert：(module, type) 冲突时覆盖 value。 */
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

    /** 读取 module='tool' 的全部配置行（右键菜单动态工具）。失败返回空列表。 */
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
