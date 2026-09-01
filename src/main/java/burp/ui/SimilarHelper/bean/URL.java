package burp.ui.SimilarHelper.bean;

import java.text.SimpleDateFormat;
import java.util.Date;

/** Similar 模块 URL 条目（表格展示对象）。 */
public class URL {
    // 展示用自增 ID（扫描线程递增，仅用于表格首列，非数据库主键）
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
