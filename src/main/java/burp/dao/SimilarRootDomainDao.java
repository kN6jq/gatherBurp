package burp.dao;

import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;

public class SimilarRootDomainDao {
    // 根据项目获取所有的根域名
    public static HashSet<String> getRootDomainNameByProjectName(String projectName) {
        String sql = "SELECT * FROM similarRootDomain WHERE projectName = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet rs = null;
        HashSet<String> similarRootDomainBeans = new HashSet<>();
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, projectName);
            rs = ps.executeQuery();
            while (rs.next()) {
                similarRootDomainBeans.add(rs.getString("rootDomainName"));
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return similarRootDomainBeans;
    }

    // 根据项目名删除
    public static void deleteByProjectName(String projectName, String rootDomain) {
        String sql = "DELETE FROM similarRootDomain WHERE projectName = ? AND rootDomainName = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, projectName);
            ps.setString(2, rootDomain);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 插入
    public static void addRootDomain(String projectName, String rootDomainName) {
        String sql = "INSERT INTO similarRootDomain (projectName,rootDomainName) VALUES (?,?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, projectName);
            ps.setString(2, rootDomainName);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

}
