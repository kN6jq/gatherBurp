package burp.ui.SimilarHelper;

import java.text.SimpleDateFormat;
import java.util.Date;

public class URLEntry {
    private static int counter = 0;
    private int id;
    private String url;
    private String timestamp;

    public URLEntry(String url) {
        this.id = ++counter;
        this.url = url;
        this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                .format(new Date());
    }

    public static int getCounter() {
        return counter;
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
