package burp.dao;

import burp.bean.Perm;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

/**
 * @Author Xm17
 * @Date 2024-06-22 10:48
 */
public class PermDao {
    // 保存
    public static void savePerm(Perm perm){
        String sql = "INSERT OR REPLACE INTO perm (type, value) VALUES (?, ?)";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, perm.getType());
            ps.setString(2, perm.getValue());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, null);
        }

    }
    // 更新
    public static void updatePerm(Perm perm){
        String sql = "update perm set value = ? where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, perm.getValue());
            ps.setString(2, perm.getType());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
    }
    // 删除
    public static void deletePerm(String type){
        String sql = "delete from perm where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, type);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }

    }
    // 查询一个
    public static Perm getPermListByType(String type) {
        Perm perm = new Perm();
        String routesql = "select * from perm where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(routesql);
            ps.setString(1, type);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                perm.setId(resultSet.getInt("id"));
                perm.setType(resultSet.getString("type"));
                perm.setValue(resultSet.getString("value"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
        return perm;

    }
    // 查询所有
    public static List<Perm> getPermListsByType(String type){
        List<Perm> permLists = new ArrayList<>();
        String routesql = "select * from perm where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(routesql);
            ps.setString(1, type);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                Perm perm = new Perm();
                perm.setId(resultSet.getInt("id"));
                perm.setType(resultSet.getString("type"));
                perm.setValue(resultSet.getString("value"));
                permLists.add(perm);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DbUtils.close(connection, ps, null);
        }
        return permLists;
    }

}
