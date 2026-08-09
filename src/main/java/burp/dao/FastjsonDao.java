package burp.dao;

import burp.bean.FastjsonBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

public class FastjsonDao {
    public static List<FastjsonBean> getFastjsonListsByType(String type) {
        List<FastjsonBean> fastjsons = new ArrayList<>();

        String sql = "select * from fastjson where type = ?";
        try (Connection connection = DbUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, type);
            try (ResultSet resultSet = ps.executeQuery()) {
                while (resultSet.next()) {
                    FastjsonBean fastjson = new FastjsonBean();
                    fastjson.setId(resultSet.getInt("id"));
                    fastjson.setType(resultSet.getString("type"));
                    fastjson.setValue(resultSet.getString("url"));
                    fastjsons.add(fastjson);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
        return fastjsons;

    }

}
