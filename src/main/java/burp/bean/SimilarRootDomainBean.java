package burp.bean;

public class SimilarRootDomainBean {
    private int id;
    private String rootDomainName;
    private String projectName;

    public SimilarRootDomainBean() {
    }

    public SimilarRootDomainBean(int id, String rootDomainName, String projectName) {
        this.id = id;
        this.rootDomainName = rootDomainName;
        this.projectName = projectName;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getRootDomainName() {
        return rootDomainName;
    }

    public void setRootDomainName(String rootDomainName) {
        this.rootDomainName = rootDomainName;
    }

    public String getProjectName() {
        return projectName;
    }

    public void setProjectName(String projectName) {
        this.projectName = projectName;
    }
}
