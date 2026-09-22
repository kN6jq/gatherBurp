package burp.ui.SimilarHelper.bean;

import burp.bean.SimilarDomainResultBean;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Objects;

/** Similar 模块域名条目（表格展示对象）：equals/hashCode 仅按 domain 判定，便于按域名去重。 */
public class Domain {
    // 展示用自增 ID（扫描线程递增，仅用于表格首列，非数据库主键）
    private static int counter = 0;
    private int id;
    private final String domain;
    private final String ip;
    private final String timestamp;

    public Domain(String domain, String ip) {
        this.id = ++counter;  // 使用临时ID
        this.domain = domain;
        this.ip = ip;
        this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
                .format(new Date());
    }

    public Domain(SimilarDomainResultBean bean) {
        this.id = bean.getId();
        this.domain = bean.getDomain();
        this.ip = bean.getIp();
        this.timestamp = formatTimestamp(bean.getCreateTime());
    }

    /** 数据库 create_time 为空时回退为当前时间。 */
    private String formatTimestamp(String timestamp) {
        if (timestamp == null || timestamp.trim().isEmpty()) {
            return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        }
        return timestamp;
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

    public String getIp() {
        return ip;
    }

    public String getTimestamp() {
        return timestamp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Domain that = (Domain) o;
        return domain.equals(that.domain);
    }

    @Override
    public int hashCode() {
        return Objects.hash(domain);
    }
}
