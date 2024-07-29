package burp.dao;

import burp.bean.SimilarSubDomainBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

public class SimilarSubDomainDao {
    /**
     * 根据主域名添加子域名及相关数据
     * @param rootDomain
     * @param subDomain
     * @param ip
     * @param time
     */
    public static void addByRootDomain(String rootDomain, String subDomain,String ip,String time) {
        String sql = "INSERT OR IGNORE INTO similarSubDomain (rootDomainName, subDomainName,ipAddress,createTime) VALUES (?, ?, ?, ?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, rootDomain);
            ps.setString(2, subDomain);
            ps.setString(3, ip);
            ps.setString(4, time);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    /**
     * 根据主域名获取子域名
     * @param rootDomain
     * @return
     */
    public static List<SimilarSubDomainBean> getByRootDomain(String rootDomain) {
        String sql = "SELECT * FROM similarSubDomain WHERE rootDomainName = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<SimilarSubDomainBean> similarSubDomainBeans = new ArrayList<>();
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, rootDomain);
            rs = ps.executeQuery();
            while (rs.next()) {
                SimilarSubDomainBean similarSubDomainBean = new SimilarSubDomainBean();
                similarSubDomainBean.setRootDomainName(rs.getString("rootDomainName"));
                similarSubDomainBean.setSubDomainName(rs.getString("subDomainName"));
                similarSubDomainBean.setIpAddress(rs.getString("ipAddress"));
                similarSubDomainBean.setCreateTime(rs.getString("createTime"));
                similarSubDomainBeans.add(similarSubDomainBean);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return similarSubDomainBeans;
    }
}
