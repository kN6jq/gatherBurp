package burp.bean;

/** DropPack 丢弃规则：action 取值 drop/forward，matchType 取值 host/url/keyword/regex，
 *  pattern 为匹配串，整体经 fastjson 序列化后存 config 表（module='droppack'）。 */
public class DropPackRule {
    // ================ 动作与匹配方式的取值常量 ================
    /** 动作：丢弃请求（不发给服务端）。 */
    public static final String ACTION_DROP = "drop";
    /** 动作：自动放行（不进拦截，直接转发）。 */
    public static final String ACTION_FORWARD = "forward";
    /** 匹配方式：主机名精确匹配，支持 *.example.com 通配子域名。 */
    public static final String MATCH_HOST = "host";
    /** 匹配方式：完整 URL 前缀匹配。 */
    public static final String MATCH_URL = "url";
    /** 匹配方式：URL 包含关键字。 */
    public static final String MATCH_KEYWORD = "keyword";
    /** 匹配方式：URL 正则匹配。 */
    public static final String MATCH_REGEX = "regex";

    private long id;
    private String action = ACTION_DROP;
    private String matchType = MATCH_KEYWORD;
    private String pattern = "";
    private boolean enabled = true;
    private String comment = "";

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getMatchType() {
        return matchType;
    }

    public void setMatchType(String matchType) {
        this.matchType = matchType;
    }

    public String getPattern() {
        return pattern;
    }

    public void setPattern(String pattern) {
        this.pattern = pattern;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }
}
