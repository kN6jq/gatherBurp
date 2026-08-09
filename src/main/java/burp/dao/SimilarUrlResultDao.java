package burp.dao;

import burp.bean.SimilarUrlResultBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class SimilarUrlResultDao {
    public static int saveUrlResult(SimilarUrlResultBean result) {
        String checkSql = "SELECT id FROM url_results WHERE project_id = ? AND url = ?";
        String updateSql = "UPDATE url_results SET create_time = datetime('now','localtime') WHERE id = ?";
        String insertSql = "INSERT INTO url_results (project_id, url, create_time) VALUES (?, ?, datetime('now','localtime'))";

        try (Connection connection = DbUtils.getConnection()) {
            // First query: check existence
            try (PreparedStatement ps = connection.prepareStatement(checkSql)) {
                ps.setInt(1, result.getProjectId());
                ps.setString(2, result.getUrl());
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        int existingId = rs.getInt("id");
                        try (PreparedStatement updatePs = connection.prepareStatement(updateSql)) {
                            updatePs.setInt(1, existingId);
                            updatePs.executeUpdate();
                        }
                        return existingId;
                    }
                }
            }

            // Not exists: insert new record
            try (PreparedStatement ps = connection.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                ps.setInt(1, result.getProjectId());
                ps.setString(2, result.getUrl());
                ps.executeUpdate();

                try (ResultSet rs = ps.getGeneratedKeys()) {
                    if (rs.next()) {
                        return rs.getInt(1);
                    }
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
            return -1;
        }
        return -1;
    }

    public static List<SimilarUrlResultBean> getUrlResults(int projectId) {
        List<SimilarUrlResultBean> results = new ArrayList<>();
        String sql = "SELECT id, project_id, url, create_time FROM url_results WHERE project_id = ? ORDER BY create_time DESC";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, projectId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    SimilarUrlResultBean urlResult = new SimilarUrlResultBean();
                    urlResult.setId(rs.getInt("id"));
                    urlResult.setProjectId(rs.getInt("project_id"));
                    urlResult.setUrl(rs.getString("url"));
                    urlResult.setCreateTime(rs.getString("create_time"));
                    results.add(urlResult);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("获取URL结果失败: " + e.getMessage());
            return null;
        }
        return results;
    }

    public static boolean isUrlExists(int projectId, String url) {
        String sql = "SELECT COUNT(*) as count FROM url_results WHERE project_id = ? AND url = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, projectId);
            ps.setString(2, url);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt("count") > 0;
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("检查URL是否存在失败: " + e.getMessage());
        }
        return false;
    }
}