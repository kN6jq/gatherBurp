package burp.dao;

import burp.bean.SqlBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class SqlDao {

    public static void saveSql(SqlBean sqlBean){
        String sql = "INSERT OR REPLACE INTO sqli (type, value) VALUES (?, ?)";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, sqlBean.getType());
            ps.setString(2, sqlBean.getValue());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void updateSql(SqlBean sqlBean){
        String sql = "update sqli set value = ? where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, sqlBean.getValue());
            ps.setString(2, sqlBean.getType());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static List<SqlBean> getSqlListsByType(String type){
        List<SqlBean> sqlLists = new ArrayList<>();
        String routesql = "select * from sqli where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(routesql)) {
            ps.setString(1, type);
            try (ResultSet resultSet = ps.executeQuery()) {
                while (resultSet.next()) {
                    SqlBean sqlBean = new SqlBean();
                    sqlBean.setId(resultSet.getInt("id"));
                    sqlBean.setType(resultSet.getString("type"));
                    sqlBean.setValue(resultSet.getString("value"));
                    sqlLists.add(sqlBean);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return sqlLists;
    }

    public static SqlBean getSqlListByType(String type){
        String routesql = "select * from sqli where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(routesql)) {
            ps.setString(1, type);
            try (ResultSet resultSet = ps.executeQuery()) {
                while (resultSet.next()) {
                    SqlBean sqlBean = new SqlBean();
                    sqlBean.setId(resultSet.getInt("id"));
                    sqlBean.setType(resultSet.getString("type"));
                    sqlBean.setValue(resultSet.getString("value"));
                    return sqlBean;
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return null;
    }

    public static void deleteSqlByType(String type){
        String sql = "delete from sqli where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, type);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public static void deleteSqlByTypeAndValue(String type, String value){
        String sql = "delete from sqli where type = ? and value = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, type);
            ps.setString(2, value);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }
}
