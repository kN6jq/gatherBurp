package burp.dao;

import burp.bean.SqlBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/** SQL 模块配置（sqli 表）数据访问：按 type 分组存储 payload/header/domain/sqlErrorKey 配置行；
 *  异常统一打 stderr，读方法降级为空列表或 null。 */
public class SqlDao {

    /** upsert：(type, value) 已存在则替换 value。 */
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

    /** 更新指定 type 的 value。无匹配行时静默无效。 */
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

    /** 读取指定 type 的全部配置行。失败返回空列表。 */
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

    /** 读取指定 type 的第一行配置；无匹配或失败返回 null（调用方按未配置处理）。 */
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

    /** 删除指定 type 下全部配置。 */
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

    /** 删除指定 type + value 的单行配置。 */
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
