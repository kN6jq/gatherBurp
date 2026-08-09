package burp.dao;

import burp.bean.SimilarProjectBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class SimilarProjectDao {
    public static void saveProject(SimilarProjectBean project) {
        String sql = "INSERT INTO projects (name, create_time) VALUES (?, datetime('now','localtime'))";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, project.getName());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static List<SimilarProjectBean> getAllProjects() {
        List<SimilarProjectBean> projects = new ArrayList<>();
        String sql = "SELECT * FROM projects ORDER BY create_time DESC";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    SimilarProjectBean project = new SimilarProjectBean();
                    project.setId(rs.getInt("id"));
                    project.setName(rs.getString("name"));
                    project.setCreateTime(rs.getString("create_time"));
                    projects.add(project);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return projects;
    }

    public static void deleteProject(int projectId) {
        String sql = "DELETE FROM projects WHERE id = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setInt(1, projectId);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }
}