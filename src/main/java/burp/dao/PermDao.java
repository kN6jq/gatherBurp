package burp.dao;

import burp.bean.PermBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/** 越权模块配置（perm 表，type: domain/permLowAuth/permNoAuth）数据访问：
 *  异常统一打 stderr，读方法降级为空列表。 */
public class PermDao {
    /** upsert：(type, value) 已存在则替换 value。 */
    public static void savePerm(PermBean permBean){
        String sql = "INSERT OR REPLACE INTO perm (type, value) VALUES (?, ?)";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, permBean.getType());
            ps.setString(2, permBean.getValue());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    /** 更新指定 type 的 value。 */
    public static void updatePerm(PermBean permBean){
        String sql = "update perm set value = ? where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, permBean.getValue());
            ps.setString(2, permBean.getType());
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    /** 删除指定 type 下全部配置。 */
    public static void deletePerm(String type){
        String sql = "delete from perm where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, type);
            ps.executeUpdate();
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    /** 读取指定 type 的首行配置（覆盖式读取，取最后一条）。失败返回空对象。 */
    public static PermBean getPermListByType(String type) {
        PermBean permBean = new PermBean();
        String routesql = "select * from perm where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(routesql)) {
            ps.setString(1, type);
            try (ResultSet resultSet = ps.executeQuery()) {
                while (resultSet.next()) {
                    permBean.setId(resultSet.getInt("id"));
                    permBean.setType(resultSet.getString("type"));
                    permBean.setValue(resultSet.getString("value"));
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return permBean;
    }

    /** 读取指定 type 的全部配置行。失败返回空列表。 */
    public static List<PermBean> getPermListsByType(String type){
        List<PermBean> permBeanLists = new ArrayList<>();
        String routesql = "select * from perm where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(routesql)) {
            ps.setString(1, type);
            try (ResultSet resultSet = ps.executeQuery()) {
                while (resultSet.next()) {
                    PermBean permBean = new PermBean();
                    permBean.setId(resultSet.getInt("id"));
                    permBean.setType(resultSet.getString("type"));
                    permBean.setValue(resultSet.getString("value"));
                    permBeanLists.add(permBean);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return permBeanLists;
    }
}