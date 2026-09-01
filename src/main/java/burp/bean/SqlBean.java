package burp.bean;

/** SQL 模块配置行：type 取值 payload（注入载荷）/ header（Header 检测位置）/ domain（白名单）/ sqlErrorKey（错误特征）。 */
public class SqlBean {
    private int id;
    private String type;
    private String value;

    public SqlBean() {
    }

    public SqlBean(String type, String value) {
        this.type = type;
        this.value = value;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
