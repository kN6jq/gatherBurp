package burp.dao;

import burp.bean.*;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SimilarDomainConfigDao {
    // 保存域名配置
    public static void saveDomainConfig(SimilarDomainConfigBean config) {
        String sql = "INSERT INTO domain_configs (project_id, domain, create_time) VALUES (?, ?, datetime('now','localtime'))";
        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = DbUtils.getConnection();
            ps = connection.prepareStatement(sql);
            ps.setInt(1, config.getProjectId());
            ps.setString(2, config.getDomain());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 批量保存域名配置
    public static void saveDomainConfigs(int projectId, List<String> domains) {
        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = DbUtils.getConnection();
            connection.setAutoCommit(false);

            // 先删除旧的配置
            String deleteSql = "DELETE FROM domain_configs WHERE project_id = ?";
            ps = connection.prepareStatement(deleteSql);
            ps.setInt(1, projectId);
            ps.executeUpdate();

            // 插入新的配置
            String insertSql = "INSERT INTO domain_configs (project_id, domain, create_time) VALUES (?, ?, datetime('now','localtime'))";
            ps = connection.prepareStatement(insertSql);
            for (String domain : domains) {
                ps.setInt(1, projectId);
                ps.setString(2, domain.trim());
                ps.addBatch();
            }
            ps.executeBatch();
            connection.commit();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
            try {
                if (connection != null) {
                    connection.rollback();
                }
            } catch (SQLException ex) {
                Utils.stderr.println(ex.getMessage());
            }
        } finally {
            try {
                if (connection != null) {
                    connection.setAutoCommit(true);
                }
            } catch (SQLException e) {
                Utils.stderr.println(e.getMessage());
            }
            DbUtils.close(connection, ps, null);
        }
    }

    // 获取项目的域名配置
    public static List<String> getDomainConfigs(int projectId) {
        List<String> domains = new ArrayList<>();
        String sql = "SELECT domain FROM domain_configs WHERE project_id = ?";
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            connection = DbUtils.getConnection();
            ps = connection.prepareStatement(sql);
            ps.setInt(1, projectId);
            rs = ps.executeQuery();
            while (rs.next()) {
                domains.add(rs.getString("domain"));
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return domains;
    }
}
