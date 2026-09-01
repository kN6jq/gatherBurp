package burp.bean;

/** Similar 模块项目域名配置（项目关注的核心/主域名清单）。 */
public class SimilarDomainConfigBean {
    private int id;
    private int projectId;
    private String domain;
    private String createTime;

    public SimilarDomainConfigBean() {
    }

    public SimilarDomainConfigBean(int projectId, String domain) {
        this.projectId = projectId;
        this.domain = domain;
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

    public String getCreateTime() {
        return createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
}
