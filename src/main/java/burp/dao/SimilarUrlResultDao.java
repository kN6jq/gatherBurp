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
    // 保存URL结果
    public static int saveUrlResult(SimilarUrlResultBean result) {
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            connection = DbUtils.getConnection();

            // 先检查是否存在相同记录
            String checkSql = "SELECT id FROM url_results WHERE project_id = ? AND url = ?";
            ps = connection.prepareStatement(checkSql);
            ps.setInt(1, result.getProjectId());
            ps.setString(2, result.getUrl());
            rs = ps.executeQuery();

            if (rs.next()) {
                // 如果存在，更新时间
                int existingId = rs.getInt("id");
                DbUtils.close(null, ps, rs); // 关闭旧的PreparedStatement和ResultSet

                String updateSql = "UPDATE url_results SET create_time = datetime('now','localtime') WHERE id = ?";
                ps = connection.prepareStatement(updateSql);
                ps.setInt(1, existingId);
                ps.executeUpdate();

                return existingId;
            } else {
                // 不存在则插入新记录
                DbUtils.close(null, ps, rs); // 关闭旧的PreparedStatement和ResultSet

                String insertSql = "INSERT INTO url_results (project_id, url, create_time) VALUES (?, ?, datetime('now','localtime'))";
                ps = connection.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS);
                ps.setInt(1, result.getProjectId());
                ps.setString(2, result.getUrl());
                ps.executeUpdate();

                // 获取新插入记录的ID
                rs = ps.getGeneratedKeys();
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }

            return -1;
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
            return -1;
        } finally {
            DbUtils.close(connection, ps, rs);
        }
    }

    // 获取项目的URL结果
    public static List<SimilarUrlResultBean> getUrlResults(int projectId) {
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<SimilarUrlResultBean> results = new ArrayList<>();

        try {
            connection = DbUtils.getConnection();

            // 按创建时间降序排列，获取最新的记录
            String sql = "SELECT id, project_id, url, create_time FROM url_results WHERE project_id = ? ORDER BY create_time DESC";
            ps = connection.prepareStatement(sql);
            ps.setInt(1, projectId);
            rs = ps.executeQuery();

            while (rs.next()) {
                SimilarUrlResultBean result = new SimilarUrlResultBean();
                result.setId(rs.getInt("id"));
                result.setProjectId(rs.getInt("project_id"));
                result.setUrl(rs.getString("url"));
                result.setCreateTime(rs.getString("create_time"));
                results.add(result);
            }

            return results;
        } catch (Exception e) {
            Utils.stderr.println("获取URL结果失败: " + e.getMessage());
            return null;
        } finally {
            DbUtils.close(connection, ps, rs);
        }
    }

    // 检查URL是否存在
    public static boolean isUrlExists(int projectId, String url) {
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            connection = DbUtils.getConnection();

            // 查询是否存在相同URL记录
            String sql = "SELECT COUNT(*) as count FROM url_results WHERE project_id = ? AND url = ?";
            ps = connection.prepareStatement(sql);
            ps.setInt(1, projectId);
            ps.setString(2, url);
            rs = ps.executeQuery();

            if (rs.next()) {
                return rs.getInt("count") > 0;
            }

            return false;
        } catch (Exception e) {
            Utils.stderr.println("检查URL是否存在失败: " + e.getMessage());
            return false;
        } finally {
            DbUtils.close(connection, ps, rs);
        }
    }
}
