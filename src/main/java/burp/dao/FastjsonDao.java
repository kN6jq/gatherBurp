package burp.dao;

import burp.bean.FastjsonBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class FastjsonDao {
    public static List<FastjsonBean> getFastjsonListsByType(String type) {
        List<FastjsonBean> fastjsons = new ArrayList<>();

        String sql = "select * from fastjson where type = ?";
        Connection connection = null;
        try {
            connection = DbUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, type);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                FastjsonBean fastjson = new FastjsonBean();
                fastjson.setId(resultSet.getInt("id"));
                fastjson.setType(resultSet.getString("type"));
                fastjson.setValue(resultSet.getString("url"));
                fastjsons.add(fastjson);
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        } finally {
            DbUtils.close(connection, ps, resultSet);
        }
        return fastjsons;

    }

}
