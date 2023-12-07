package burp.bean;

public class Log4jBean {
    private Integer id;
    private String type;
    private String value;

    public Log4jBean() {
    }

    public Log4jBean(String type, String value) {
        this.type = type;
        this.value = value;
    }

    public Log4jBean(Integer id, String type, String value) {
        this.id = id;
        this.type = type;
        this.value = value;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
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
