package burp.bean;

public class SimilarSimilarSubDomainBean {

    private int id;
    private String subDomainName;
    private String projectName;
    private String ipAddress;
    private String createTime;

    public SimilarSimilarSubDomainBean() {
    }

    public SimilarSimilarSubDomainBean(int id, String subDomainName, String projectName, String ipAddress, String createTime) {
        this.id = id;
        this.subDomainName = subDomainName;
        this.projectName = projectName;
        this.ipAddress = ipAddress;
        this.createTime = createTime;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getSubDomainName() {
        return subDomainName;
    }

    public void setSubDomainName(String subDomainName) {
        this.subDomainName = subDomainName;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getCreateTime() {
        return createTime;
    }

    public void setCreateTime(String createTime) {
        this.createTime = createTime;
    }
}
