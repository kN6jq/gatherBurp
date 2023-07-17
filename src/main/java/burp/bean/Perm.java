package burp.bean;

public class Perm {
    private int id;
    private String domain;
    private String low;
    private String no;

    public Perm() {
    }

    public Perm(String domain, String low, String no) {
        this.domain = domain;
        this.low = low;
        this.no = no;
    }

    public Perm(int id, String domain, String low, String no) {
        this.id = id;
        this.domain = domain;
        this.low = low;
        this.no = no;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getDomain() {
        return domain;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public String getLow() {
        return low;
    }

    public void setLow(String low) {
        this.low = low;
    }

    public String getNo() {
        return no;
    }

    public void setNo(String no) {
        this.no = no;
    }
}
