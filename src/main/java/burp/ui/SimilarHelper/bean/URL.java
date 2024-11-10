package burp.ui.SimilarHelper.bean;

import java.text.SimpleDateFormat;
import java.util.Date;

public class URL {
    private static int counter = 0;
    private int id;
    private String url;
    private String timestamp;

    public URL(String url) {
        this.id = ++counter;
        this.url = url;
        this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                .format(new Date());
    }
    public int getId() {
        return id;
    }

    public String getUrl() {
        return url;
    }

    public String getTimestamp() {
        return timestamp;
    }
}
