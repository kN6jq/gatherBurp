package burp.dao;

import burp.bean.*;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class SimilarDomainResultDao {
    // 保存域名结果
    public static int saveDomainResult(SimilarDomainResultBean result) {
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            connection = DbUtils.getConnection();

            // 先检查是否存在相同记录
            String checkSql = "SELECT id FROM domain_results WHERE project_id = ? AND domain = ?";
            ps = connection.prepareStatement(checkSql);
            ps.setInt(1, result.getProjectId());
            ps.setString(2, result.getDomain());
            rs = ps.executeQuery();

            if (rs.next()) {
                // 如果存在，更新IP和时间
                int existingId = rs.getInt("id");
                DbUtils.close(null, ps, rs); // 关闭旧的PreparedStatement和ResultSet

                String updateSql = "UPDATE domain_results SET ip = ?, create_time = datetime('now','localtime') WHERE id = ?";
                ps = connection.prepareStatement(updateSql);
                ps.setString(1, result.getIp());
                ps.setInt(2, existingId);
                ps.executeUpdate();

                return existingId;
            } else {
                // 不存在则插入新记录
                DbUtils.close(null, ps, rs); // 关闭旧的PreparedStatement和ResultSet

                String insertSql = "INSERT INTO domain_results (project_id, domain, ip, create_time) VALUES (?, ?, ?, datetime('now','localtime'))";
                // 移除 Statement.RETURN_GENERATED_KEYS
                ps = connection.prepareStatement(insertSql);
                ps.setInt(1, result.getProjectId());
                ps.setString(2, result.getDomain());
                ps.setString(3, result.getIp());
                ps.executeUpdate();

                // 使用 last_insert_rowid() 获取最后插入的ID
                ps = connection.prepareStatement("SELECT last_insert_rowid()");
                rs = ps.executeQuery();
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }

            return -1;
        } catch (SQLException e) {
            return -1;
        } catch (Exception e) {
            return -1;
        } finally {
            DbUtils.close(connection, ps, rs);
        }
    }

    // 获取项目的域名结果
    public static List<SimilarDomainResultBean> getDomainResults(int projectId) throws SQLException {
        List<SimilarDomainResultBean> results = new ArrayList<>();
        String sql = "SELECT id, project_id, domain, ip, create_time FROM domain_results WHERE project_id = ?";

        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        try {
            connection = DbUtils.getConnection();
            ps = connection.prepareStatement(sql);
            ps.setInt(1, projectId);
            rs = ps.executeQuery();

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

            return results;
        } finally {
            DbUtils.close(connection, ps, rs);
        }
    }
}