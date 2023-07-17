package burp.utils;

import java.sql.*;

public class DBUtils {
    public static String DB_NAME = "gather.db";
    public static String DB_PATH = System.getProperty("user.home") + "/.gather/" + DB_NAME;
    public static String DB_URL = "jdbc:sqlite:" + DB_PATH;
    public static String DB_DRIVER = "org.sqlite.JDBC";

    static {
        try {
            Class.forName(DB_DRIVER);
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL);
    }
    public static void close(Connection connection, PreparedStatement preparedStatement, ResultSet resultSet){
        try{
            if(connection != null){
                connection.close();
            }
            if (preparedStatement != null){
                preparedStatement.close();
            }
            if (resultSet != null){
                resultSet.close();
            }
        } catch (Exception e ){
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws SQLException {
        System.out.println(getConnection());
    }


}
