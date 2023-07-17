package burp.dao;

import burp.bean.Sql;
import burp.utils.DBUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class SqlDAO {
    public static List<Sql> getSqliList() {
        List<Sql> sqlis = new ArrayList<>();
        String sql = "select * from sqli";
        Connection connection = null;
        try {
            connection = DBUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()) {
                Sql sqli = new Sql();
                sqli.setId(resultSet.getInt("id"));
                sqli.setSql(resultSet.getString("sql"));
                sqlis.add(sqli);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            DBUtils.close(connection, ps, resultSet);
        }
        return sqlis;
    }

    public static void addSqli(Sql sqli) {
        deleteSqli(); // 先清空表

        String sql = "insert into sqli(sql) values(?)";
        try (Connection connection = DBUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {

            if (sqli.getSql().contains("\n")) {
                String[] sqls = sqli.getSql().split("\n");
                for (String s : sqls) {
                    ps.setString(1, s);
                    ps.addBatch();
                }
            } else {
                ps.setString(1, sqli.getSql());
                ps.addBatch();
            }

            ps.executeBatch();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        }
    }


    public static void deleteSqli() {
        String sql = "delete from sqli";
        Connection connection = null;
        try {
            connection = DBUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            DBUtils.close(connection, ps, null);
        }

    }
}
