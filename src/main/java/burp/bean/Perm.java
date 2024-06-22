package burp.bean;

/**
 * @Author Xm17
 * @Date 2024-06-22 10:47
 */
public class Perm {
    private int id;
    private String type;
    private String value;

    public Perm() {
    }

    public Perm(String type, String value) {
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
