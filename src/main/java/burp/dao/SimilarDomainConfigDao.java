package burp.dao;

import burp.bean.SimilarDomainConfigBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class SimilarDomainConfigDao {
    public static void saveDomainConfig(SimilarDomainConfigBean config) {
        String sql = "INSERT INTO domain_configs (project_id, domain, create_time) VALUES (?, ?, datetime('now','localtime'))";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, config.getProjectId());
            ps.setString(2, config.getDomain());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void saveDomainConfigs(int projectId, List<String> domains) {
        String deleteSql = "DELETE FROM domain_configs WHERE project_id = ?";
        String insertSql = "INSERT INTO domain_configs (project_id, domain, create_time) VALUES (?, ?, datetime('now','localtime'))";
        try (Connection connection = DbUtils.getConnection()) {
            connection.setAutoCommit(false);
            try (PreparedStatement ps = connection.prepareStatement(deleteSql)) {
                ps.setInt(1, projectId);
                ps.executeUpdate();
            }
            try (PreparedStatement ps = connection.prepareStatement(insertSql)) {
                for (String domain : domains) {
                    ps.setInt(1, projectId);
                    ps.setString(2, domain.trim());
                    ps.addBatch();
                }
                ps.executeBatch();
            }
            connection.commit();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static List<String> getDomainConfigs(int projectId) {
        List<String> domains = new ArrayList<>();
        String sql = "SELECT domain FROM domain_configs WHERE project_id = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, projectId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    domains.add(rs.getString("domain"));
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return domains;
    }
}
