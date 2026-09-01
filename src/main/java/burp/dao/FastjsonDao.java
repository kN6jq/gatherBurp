package burp.dao;

import burp.bean.FastjsonBean;
import burp.utils.DbUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/** Fastjson 模块配置（fastjson 表，type: jndi/version/dns/echo）数据访问：
 *  表列名为 url，实际存放含 FUZZ 占位的 payload 模板，读入 value 字段；异常打 stderr 并降级空列表。 */
public class FastjsonDao {
    /** 读取指定 type 的全部 payload 配置行。失败返回空列表。 */
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
