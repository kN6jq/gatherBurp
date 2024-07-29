package burp.bean;

public class SimilarSubDomainBean {
    private int id;
    private String subDomainName;
    private String rootDomainName;
    private String ipAddress;
    private String createTime;

    public SimilarSubDomainBean() {
    }

    public SimilarSubDomainBean(int id, String subDomainName, String rootDomainName, String ipAddress, String createTime) {
        this.id = id;
        this.subDomainName = subDomainName;
        this.rootDomainName = rootDomainName;
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

    public String getRootDomainName() {
        return rootDomainName;
    }

    public void setRootDomainName(String rootDomainName) {
        this.rootDomainName = rootDomainName;
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
