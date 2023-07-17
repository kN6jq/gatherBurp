package burp.bean;

public class Config {
    private Integer id;
    private String module;
    private String type;
    private String value;

    public Config() {
    }

    public Config(String module, String type, String value) {
        this.module = module;
        this.type = type;
        this.value = value;
    }

    public Config(String type, String value) {
        this.type = type;
        this.value = value;
    }

    public Config(Integer id, String module, String type, String value) {
        this.id = id;
        this.module = module;
        this.type = type;
        this.value = value;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getModule() {
        return module;
    }

    public void setModule(String module) {
        this.module = module;
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
