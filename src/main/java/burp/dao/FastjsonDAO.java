package burp.dao;

import burp.bean.Fastjson;
import burp.utils.DBUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class FastjsonDAO {
    public static List<Fastjson> getFastjsonListByDnsLog() throws SQLException {
        List<Fastjson> fastjsons = new ArrayList<>();

        String sql = "select * from fastjson where type = 'dns'";
        Connection connection = DBUtils.getConnection();
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()){
                Fastjson fastjson = new Fastjson();
                fastjson.setId(resultSet.getInt("id"));
                fastjson.setType(resultSet.getString("type"));
                fastjson.setUrl(resultSet.getString("url"));
                fastjsons.add(fastjson);
            }
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return fastjsons;
    }

    public static List<Fastjson> getFastjsonListByJNDI() throws SQLException{
        List<Fastjson> fastjsons = new ArrayList<>();

        String sql = "select * from fastjson where type = 'jndi'";
        Connection connection = DBUtils.getConnection();
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()){
                Fastjson fastjson = new Fastjson();
                fastjson.setId(resultSet.getInt("id"));
                fastjson.setType(resultSet.getString("type"));
                fastjson.setUrl(resultSet.getString("url"));
                fastjsons.add(fastjson);
            }
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return fastjsons;
    }

    public static List<Fastjson> getFastjsonListByEchoVul() throws SQLException{
        List<Fastjson> fastjsons = new ArrayList<>();

        String sql = "select * from fastjson where type = 'echo'";
        Connection connection = DBUtils.getConnection();
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()){
                Fastjson fastjson = new Fastjson();
                fastjson.setId(resultSet.getInt("id"));
                fastjson.setType(resultSet.getString("type"));
                fastjson.setUrl(resultSet.getString("url"));
                fastjsons.add(fastjson);
            }
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return fastjsons;
    }

}
