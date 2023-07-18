package burp.dao;

import burp.bean.Log4j;
import burp.bean.Sql;
import burp.utils.DBUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

public class Log4jDAO {
    public static void saveHeader(Log4j log4j){
        deleteHeader();
        String sql = "insert into log4j(header) values(?)";
        try (Connection connection = DBUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {

            if (log4j.getHeader().contains("\n")) {
                String[] sqls = log4j.getHeader().split("\n");
                for (String s : sqls) {
                    ps.setString(1, s);
                    ps.addBatch();
                }
            } else {
                ps.setString(1, log4j.getHeader());
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        }
    }
    public static void savePayload(Log4j log4j){
        deletePayload();
        String sql = "insert into log4j(payload) values(?)";
        try (Connection connection = DBUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {

            if (log4j.getPayload().contains("\n")) {
                String[] sqls = log4j.getPayload().split("\n");
                for (String s : sqls) {
                    ps.setString(1, s);
                    ps.addBatch();
                }
            } else {
                ps.setString(1, log4j.getPayload());
                ps.addBatch();
            }
            ps.executeBatch();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        }
    }
    public static List<Log4j> getHeaderList(){
        List<Log4j> log4js = new ArrayList<>();
        String sql = "select header from log4j where header is not null";
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
                Log4j log4j = new Log4j();
                log4j.setHeader(resultSet.getString("header"));
                log4js.add(log4j);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            DBUtils.close(connection, ps, resultSet);
        }
        return log4js;

    }
    public static List<Log4j> getPayloadList(){
        List<Log4j> log4js = new ArrayList<>();
        String sql = "select payload from log4j where payload is not null";
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
                Log4j log4j = new Log4j();
                log4j.setPayload(resultSet.getString("payload"));
                log4js.add(log4j);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        } finally {
            DBUtils.close(connection, ps, resultSet);
        }
        return log4js;

    }

    public static void deleteHeader(){
        String sql = "delete from log4j where header is not null";
        try (Connection connection = DBUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.execute();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        }
    }
    public static void deletePayload(){
        String sql = "delete from log4j where payload is not null";
        try (Connection connection = DBUtils.getConnection();
             PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.execute();
        } catch (SQLException e) {
            Utils.stderr.println(e.getMessage());
        }
    }

}
