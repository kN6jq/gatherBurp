package burp.bean;

public class SqlBean {
    private int id;
    private String sql;

    public SqlBean() {
    }

    public SqlBean(String sql) {
        this.sql = sql;
    }

    public SqlBean(int id, String sql) {
        this.id = id;
        this.sql = sql;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getSql() {
        return sql;
    }

    public void setSql(String sql) {
        this.sql = sql;
    }
}
