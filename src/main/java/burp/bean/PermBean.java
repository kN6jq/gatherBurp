package burp.bean;

/** 越权模块配置行：type 取值 domain（白名单）/ permLowAuth（低权限头）/ permNoAuth（待移除的鉴权头）；
 *  permLowAuth/permNoAuth 的 value 为完整 HTTP 头（"Header-Name: value"）。 */
public class PermBean {
    private int id;
    private String type;
    private String value;

    public PermBean() {
    }

    public PermBean(String type, String value) {
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
