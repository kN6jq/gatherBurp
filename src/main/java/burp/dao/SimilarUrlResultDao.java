package burp.dao;


import burp.bean.*;
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
        List<SimilarUrlResultBean> results = new ArrayList<>();
        String sql = "SELECT * FROM url_results WHERE project_id = ? ORDER BY create_time DESC";
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            connection = DbUtils.getConnection();
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
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return results;
    }
}
