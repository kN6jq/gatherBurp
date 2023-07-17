package burp.dao;

import burp.bean.Fastjson;
import burp.bean.Perm;
import burp.utils.DBUtils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class PermDAO {
    public static int savePerm(Perm perm) {
        String sql = "insert into perm(domain,low,no) values(?,?,?)";
        Connection connection = null;
        int i = 0;
        try {
            connection = DBUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, perm.getDomain());
            ps.setString(2, perm.getLow());
            ps.setString(3, perm.getNo());
            i = ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            DBUtils.close(connection, ps, resultSet);
        }
        return i;
    }
    public static Perm getPerm(){
        Perm perm = new Perm();
        String sql = "select * from perm ORDER BY id desc limit 1";
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
            while (resultSet.next()){
                perm.setId(resultSet.getInt("id"));
                perm.setDomain(resultSet.getString("domain"));
                perm.setLow(resultSet.getString("low"));
                perm.setNo(resultSet.getString("no"));
            }
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return perm;
    }
    public static int deletePerm(){
        String sql = "delete from perm";
        Connection connection = null;
        int i = 0;
        try {
            connection = DBUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            i = ps.executeUpdate();
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return i;
    }

}
