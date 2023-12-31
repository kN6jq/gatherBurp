package burp.bean;

public class FastjsonBean {
    private Integer id;
    private String type;
    private String url;

    public FastjsonBean() {
    }

    public FastjsonBean(Integer id, String type, String url) {
        this.id = id;
        this.type = type;
        this.url = url;
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

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }
}
