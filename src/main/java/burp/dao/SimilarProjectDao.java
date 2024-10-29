package burp.dao;

import burp.bean.*;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class SimilarProjectDao {
    // 保存项目
    public static void saveProject(SimilarProjectBean project) {
        String sql = "INSERT INTO projects (name, create_time) VALUES (?, datetime('now','localtime'))";
        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = DbUtils.getConnection();
            ps = connection.prepareStatement(sql);
            ps.setString(1, project.getName());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }

    // 获取所有项目
    public static List<SimilarProjectBean> getAllProjects() {
        List<SimilarProjectBean> projects = new ArrayList<>();
        String sql = "SELECT * FROM projects ORDER BY create_time DESC";
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            connection = DbUtils.getConnection();
            ps = connection.prepareStatement(sql);
            rs = ps.executeQuery();
            while (rs.next()) {
                SimilarProjectBean project = new SimilarProjectBean();
                project.setId(rs.getInt("id"));
                project.setName(rs.getString("name"));
                project.setCreateTime(rs.getString("create_time"));
                projects.add(project);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, rs);
        }
        return projects;
    }

    // 删除项目
    public static void deleteProject(int projectId) {
        String sql = "DELETE FROM projects WHERE id = ?";
        Connection connection = null;
        PreparedStatement ps = null;
        try {
            connection = DbUtils.getConnection();
            ps = connection.prepareStatement(sql);
            ps.setInt(1, projectId);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }
}
