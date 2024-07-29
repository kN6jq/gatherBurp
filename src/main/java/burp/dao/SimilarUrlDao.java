package burp.dao;

import burp.bean.SimilarUrlBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SimilarUrlDao {
    /**
     * 根据项目名添加url
     * @param projectName
     * @param url
     * @param time
     */
    public static void addUrlByProjectName(String projectName, String url,String time) {
        String sql = "INSERT OR IGNORE INTO similarUrl (projectName, url,createTime) VALUES (?, ?, ?)";
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
            ps.setString(2, url);
            ps.setString(3, time);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    /**
     * 根据项目名获取url
     * @param projectName
     * @return
     */
    public static List<SimilarUrlBean> getUrlByProjectName(String projectName) {
        String sql = "SELECT * FROM similarUrl WHERE projectName = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<SimilarUrlBean> similarUrlBeans = new ArrayList<>();
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, projectName);
            rs = ps.executeQuery();
            while (rs.next()) {
                SimilarUrlBean similarUrlBean = new SimilarUrlBean();
                similarUrlBean.setProjectName(rs.getString("projectName"));
                similarUrlBean.setUrl(rs.getString("url"));
                similarUrlBean.setCreateTime(rs.getString("createTime"));
                similarUrlBeans.add(similarUrlBean);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return similarUrlBeans;
    }
}
