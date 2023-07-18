package burp.bean;

public class Log4j {
    private Integer id;
    private String header;
    private String payload;

    public Log4j() {
    }

    public Log4j(String header, String payload) {
        this.header = header;
        this.payload = payload;
    }

    public Log4j(Integer id, String header, String payload) {
        this.id = id;
        this.header = header;
        this.payload = payload;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getHeader() {
        return header;
    }

    public void setHeader(String header) {
        this.header = header;
    }

    public String getPayload() {
        return payload;
    }

    public void setPayload(String payload) {
        this.payload = payload;
    }
}
