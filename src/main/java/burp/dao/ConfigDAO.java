package burp.dao;

import burp.bean.Config;
import burp.bean.Fastjson;
import burp.utils.DBUtils;
import burp.utils.Utils;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class ConfigDAO {

    // 获取配置的所有数据
    public static List<Config> getConfigList() throws SQLException {
        List<Config> configs = new ArrayList<>();
        String sql = "select * from config";
        Connection connection = DBUtils.getConnection();
        PreparedStatement ps = null;
        ResultSet resultSet = null;
        try {
            ps = connection.prepareStatement(sql);
            resultSet = ps.executeQuery();
            while (resultSet.next()){
                Config config = new Config();
                config.setId(resultSet.getInt("id"));
                config.setValue(resultSet.getString("key"));
                config.setValue(resultSet.getString("value"));
                configs.add(config);
            }
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return configs;
    }

    // 根据模块和类型获取配置
    public static Config getValueByModuleAndType(String module,String type){
        Config config = new Config();
        String sql = "select value from config where module = ? and type = ? order by id desc limit 1";
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
            ps.setString(1, module);
            ps.setString(2, type);
            resultSet = ps.executeQuery();
            while (resultSet.next()){
                config.setValue(resultSet.getString("value"));
            }
        }catch (Exception e){
            Utils.stderr.println(e.getMessage());
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return config;
    }
    // 根据类型更新配置
    public static void updateConfigSetting(Config config){
        String sql = "update config set value = ? where type = ? and module = ?";
        Connection connection = null;
        try {
            connection = DBUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, config.getValue());
            ps.setString(2, config.getType());
            ps.setString(3, config.getModule());
            ps.executeUpdate();
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,null);
        }
    }

    // 保存配置
    public static void saveConfigSetting(Config config){
        String sql  = "insert into config(module,type,value) values(?,?,?)";
        Connection connection = null;
        try {
            connection = DBUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, config.getModule());
            ps.setString(2, config.getType());
            ps.setString(3, config.getValue());
            ps.executeUpdate();
        }catch (Exception e){
            Utils.stderr.println(e.getMessage());
        }finally {
            DBUtils.close(connection,ps,null);
        }

    }
    // 获取工具配置
    public static List<Config> getToolConfig(){
        List<Config> configs = new ArrayList<>();
        String sql = "select * from config where module = 'tool'";
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
                Config config = new Config();
                config.setId(resultSet.getInt("id"));
                config.setModule(resultSet.getString("module"));
                config.setType(resultSet.getString("type"));
                config.setValue(resultSet.getString("value"));
                configs.add(config);
            }
        }catch (Exception e){
            Utils.stderr.println(e.getMessage());
        }finally {
            DBUtils.close(connection,ps,resultSet);
        }
        return configs;
    }
    // 删除配置
    public static void deleteConfig(Config config){
        String sql = "delete from config where type = ?";
        Connection connection = null;
        try {
            connection = DBUtils.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        PreparedStatement ps = null;
        try {
            ps = connection.prepareStatement(sql);
            ps.setString(1, config.getType());
            ps.executeUpdate();
        }catch (Exception e){
            e.printStackTrace();
        }finally {
            DBUtils.close(connection,ps,null);
        }

    }
}
