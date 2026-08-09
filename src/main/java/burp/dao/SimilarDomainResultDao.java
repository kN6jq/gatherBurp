package burp.dao;

import burp.bean.SimilarDomainResultBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SimilarDomainResultDao {
    public static int saveDomainResult(SimilarDomainResultBean result) {
        String checkSql = "SELECT id FROM domain_results WHERE project_id = ? AND domain = ?";
        String updateSql = "UPDATE domain_results SET ip = ?, create_time = datetime('now','localtime') WHERE id = ?";
        String insertSql = "INSERT INTO domain_results (project_id, domain, ip, create_time) VALUES (?, ?, ?, datetime('now','localtime'))";

        try (Connection connection = DbUtils.getConnection()) {
            // First query: check existence
            try (PreparedStatement ps = connection.prepareStatement(checkSql)) {
                ps.setInt(1, result.getProjectId());
                ps.setString(2, result.getDomain());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        int existingId = rs.getInt("id");
                        try (PreparedStatement updatePs = connection.prepareStatement(updateSql)) {
                            updatePs.setString(1, result.getIp());
                            updatePs.setInt(2, existingId);
                            updatePs.executeUpdate();
                        }
                        return existingId;
                    }
                }
            }

            // Not exists: insert new record
            try (PreparedStatement ps = connection.prepareStatement(insertSql)) {
                ps.setInt(1, result.getProjectId());
                ps.setString(2, result.getDomain());
                ps.setString(3, result.getIp());
                ps.executeUpdate();
            }

            // Get last insert rowid
            try (PreparedStatement ps = connection.prepareStatement("SELECT last_insert_rowid()");
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (Exception e) {
            return -1;
        }
        return -1;
    }

    public static List<SimilarDomainResultBean> getDomainResults(int projectId) throws SQLException {
        List<SimilarDomainResultBean> results = new ArrayList<>();
        String sql = "SELECT id, project_id, domain, ip, create_time FROM domain_results WHERE project_id = ?";

        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, projectId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    SimilarDomainResultBean bean = new SimilarDomainResultBean(
                            rs.getInt("project_id"),
                            rs.getString("domain"),
                            rs.getString("ip")
                    );
                    bean.setId(rs.getInt("id"));
                    bean.setCreateTime(rs.getString("create_time"));
                    results.add(bean);
                }
            }
        }
        return results;
    }

    public static boolean isDomainExists(int id, String domain) {
        String sql = "SELECT id FROM domain_results WHERE id = ? AND domain = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, id);
            ps.setString(2, domain);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return true;
                }
            }
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        }
        return false;
    }

    public static void updateDomainResult(SimilarDomainResultBean result) {
        String sql = "UPDATE domain_results SET ip = ?, update_time = datetime('now','localtime') WHERE id = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, result.getIp());
            ps.setInt(2, result.getId());
            int updatedRows = ps.executeUpdate();
            if (updatedRows == 0) {
                Utils.stderr.println("更新域名结果失败: 记录不存在 (ID: " + result.getId() + ")");
            }
        } catch (Exception e) {
            Utils.stderr.println("更新域名结果失败: " + e.getMessage());
        }
    }
}