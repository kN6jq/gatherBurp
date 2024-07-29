package burp.dao;

import burp.bean.SimilarSimilarSubDomainBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SimilarSimilarSubDomainDao {

    /**
     * 添加
     * @param projectName
     * @param subDomain
     * @param ip
     * @param time
     */
    public static void addSimilarByRootDomain(String projectName, String subDomain, String ip, String time) {
        String sql = "INSERT OR IGNORE INTO similarSimilarSubDomain (projectName, subDomainName,ipAddress,createTime) VALUES (?, ?, ?, ?)";
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
     * 获取
     * @param projectName
     * @return
     */
    public static List<SimilarSimilarSubDomainBean> getSimilarBypProjectName(String projectName) {
        String sql = "SELECT * FROM similarSimilarSubDomain WHERE projectName = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<SimilarSimilarSubDomainBean> similarSimilarSubDomainBeans = new ArrayList<>();
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, projectName);
            rs = ps.executeQuery();
            while (rs.next()) {
                SimilarSimilarSubDomainBean similarSimilarSubDomainBean = new SimilarSimilarSubDomainBean();
                similarSimilarSubDomainBean.setProjectName(rs.getString("projectName"));
                similarSimilarSubDomainBean.setSubDomainName(rs.getString("subDomainName"));
                similarSimilarSubDomainBean.setIpAddress(rs.getString("ipAddress"));
                similarSimilarSubDomainBean.setCreateTime(rs.getString("createTime"));
                similarSimilarSubDomainBeans.add(similarSimilarSubDomainBean);
            }
        }catch(Exception e){
            Utils.stderr.println(e.getMessage());
        } finally{
            DbUtils.close(connection, ps, rs);
        }
        return similarSimilarSubDomainBeans;

    }
}
