package burp.bean;

public class SimilarDomainResultBean {
    private int id;
    private int projectId;
    private String domain;
    private String ip;
    private String createTime;

    public SimilarDomainResultBean() {
    }

    public SimilarDomainResultBean(int projectId, String domain, String ip) {
        this.projectId = projectId;
        this.domain = domain;
        this.ip = ip;
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

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getCreateTime() {
        return createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
}
