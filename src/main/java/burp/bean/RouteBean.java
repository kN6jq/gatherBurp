package burp.bean;

public class RouteBean {
    private int enable;
    private String name;
    private String path;
    private String express;

    public RouteBean() {
    }

    public RouteBean(int enable, String name, String path, String express) {
        this.enable = enable;
        this.name = name;
        this.path = path;
        this.express = express;
    }

    public int getEnable() {
        return enable;
    }

    public void setEnable(int enable) {
        this.enable = enable;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getExpress() {
        return express;
    }

    public void setExpress(String express) {
        this.express = express;
    }
}
