package burp.bean;

public class SimilarUrlResultBean {
    private int id;
    private int projectId;
    private String url;
    private String createTime;

    public SimilarUrlResultBean() {
    }

    public SimilarUrlResultBean(int projectId, String url) {
        this.projectId = projectId;
        this.url = url;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getProjectId() {
        return projectId;
    }

    public void setProjectId(int projectId) {
        this.projectId = projectId;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getCreateTime() {
        return createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
}
