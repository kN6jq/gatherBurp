package burp.dao;

import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/** Similar 模块项目域名配置（domain_configs 表）数据访问：saveDomainConfigs 为"全删全插"的整体替换，
 *  事务内执行；异常打 stderr 并降级。 */
public class SimilarDomainConfigDao {
    /** 全删全插的整体替换：事务内先删除项目下全部域名再批量插入。失败回滚。 */
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

    /** 读取项目下全部主域名。失败返回空列表。 */
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
