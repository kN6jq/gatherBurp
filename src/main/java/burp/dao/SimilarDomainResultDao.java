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

/** Similar 模块域名解析结果（domain_results 表）数据访问。 */
public class SimilarDomainResultDao {
    /** upsert：(project_id, domain) 已存在则更新 ip 并返回已有 id，否则插入并返回新 rowid；失败返回 -1。
     *  注意：本方法在扫描线程并发调用，依赖 SQLite 单写者串行化。 */
    public static int saveDomainResult(SimilarDomainResultBean result) {
        String checkSql = "SELECT id FROM domain_results WHERE project_id = ? AND domain = ?";
        String updateSql = "UPDATE domain_results SET ip = ? WHERE id = ?";
        String insertSql = "INSERT INTO domain_results (project_id, domain, ip, create_time) VALUES (?, ?, ?, datetime('now','localtime'))";

        try (Connection connection = DbUtils.getConnection()) {
            // 检查是否已存在
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

            // 不存在则插入新记录
            try (PreparedStatement ps = connection.prepareStatement(insertSql)) {
                ps.setInt(1, result.getProjectId());
                ps.setString(2, result.getDomain());
                ps.setString(3, result.getIp());
                ps.executeUpdate();
            }

            // 获取新插入行 id
            try (PreparedStatement ps = connection.prepareStatement("SELECT last_insert_rowid()");
                 ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("保存域名结果失败: " + e.getMessage());
            return -1;
        }
        return -1;
    }

    /** 读取项目全部域名结果；数据库异常向调用方抛出（由 SimilarUI 的 CompletionException 链路处理）。 */
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

    /** 判断指定 id+domain 是否已存在。失败返回 false。 */
    public static boolean isDomainExists(int id, String domain) {
        String sql = "SELECT id FROM domain_results WHERE id = ? AND domain = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, id);
            ps.setString(2, domain);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return false;
    }

    /** 更新指定 id 的域名解析 IP。记录不存在时打 stderr。 */
    public static void updateDomainResult(SimilarDomainResultBean result) {
        String sql = "UPDATE domain_results SET ip = ? WHERE id = ?";
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
