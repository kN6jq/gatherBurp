package burp.bean;

public class SimilarUrlBean {


    private int id;
    private String url;
    private String projectName;
    private String createTime;

    public SimilarUrlBean() {
    }

    public SimilarUrlBean(int id, String url, String projectName, String createTime) {
        this.id = id;
        this.url = url;
        this.projectName = projectName;
        this.createTime = createTime;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getCreateTime() {
        return createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
}
