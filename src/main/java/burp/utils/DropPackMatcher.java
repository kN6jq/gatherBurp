package burp.utils;

import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.bean.DropPackRule;
import burp.dao.DropPackDao;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.regex.Pattern;

/**
 * DropPack 丢弃数据包匹配核心：无状态纯匹配逻辑 + 不可变规则快照 + 命中计数。
 *
 * <p>线程模型：EDT（UI/右键菜单保存时 rebuild）写快照，Burp 代理监听线程读；
 * 快照为 volatile 不可变列表，读取无锁。命中计数用 LongAdder 跨线程累加。</p>
 *
 * <p>匹配语义（按规则列表顺序，首条命中即返回）：host 精确相等或 *.example.com
 * 通配子域名；url 为完整 URL 前缀匹配；keyword 为 URL 包含；regex 为 URL 正则 find。
 * host/url/keyword 忽略大小写，regex 的大小写语义由用户在表达式里自控。</p>
 *
 * <p>丢弃动作通过 IInterceptedProxyMessage.ACTION_DROP 实现，仅对经过 Proxy 的流量
 * 生效（legacy API 无其他工具的丢弃入口）；插件自身扫描走 makeHttpRequest，不经
 * Proxy 监听器，不会被自身规则误伤。</p>
 */
public final class DropPackMatcher {
    // ================ 运行状态 ================
    /** 模块总开关（EDT/菜单写、代理监听线程读，volatile 保证可见性）。 */
    private static volatile boolean enabled = false;
    /** 不可变规则快照：rebuild 整体替换，代理监听线程只读无锁。 */
    private static volatile List<CompiledRule> rules = Collections.emptyList();
    /** 按规则 id 的命中计数，rebuild 不清零——调规则时历史计数仍有参考价值。 */
    private static final ConcurrentHashMap<Long, LongAdder> HIT_COUNTS = new ConcurrentHashMap<>();
    /** 丢弃动作总命中数（UI 展示用）。 */
    private static final LongAdder TOTAL_DROPPED = new LongAdder();
    /** 自动放行动作总命中数（UI 展示用）。 */
    private static final LongAdder TOTAL_FORWARDED = new LongAdder();

    private DropPackMatcher() {
        throw new AssertionError("No DropPackMatcher instances for you!");
    }

    /** 插件加载时执行：从 config 表恢复总开关与规则快照。 */
    public static void loadConfig() {
        enabled = DropPackDao.isEnabled();
        rebuild(DropPackDao.loadRules());
    }

    /** 更新总开关（不落库，落库由调用方经 DropPackDao.saveEnabled 完成）。 */
    public static void setEnabled(boolean value) {
        enabled = value;
    }

    public static boolean isEnabled() {
        return enabled;
    }

    /** 重建规则快照：正则在此预编译，非法正则跳过并打 stderr，不影响其余规则。 */
    public static void rebuild(List<DropPackRule> ruleList) {
        List<CompiledRule> compiled = new ArrayList<>();
        if (ruleList != null) {
            for (DropPackRule rule : ruleList) {
                if (rule == null || !rule.isEnabled() || rule.getPattern() == null
                        || rule.getPattern().trim().isEmpty()) {
                    continue;
                }
                try {
                    compiled.add(new CompiledRule(rule));
                } catch (Exception e) {
                    // Utils.stderr 由 BurpExtender 注入，单测环境为 null，降级到 System.err
                    if (Utils.stderr != null) {
                        Utils.stderr.println("DropPack rule skipped (bad regex): " + rule.getPattern()
                                + " -> " + e.getMessage());
                    } else {
                        System.err.println("DropPack rule skipped (bad regex): " + rule.getPattern()
                                + " -> " + e.getMessage());
                    }
                }
            }
        }
        rules = Collections.unmodifiableList(compiled);
    }

    /**
     * 纯匹配判定：模块总开关关闭或无命中返回 null，否则返回首条命中的规则。
     * 不依赖 Burp 运行时，可单测。
     */
    public static CompiledRule firstMatch(String host, String url) {
        if (!enabled) {
            return null;
        }
        List<CompiledRule> snapshot = rules;
        for (CompiledRule rule : snapshot) {
            if (matches(rule, host, url)) {
                return rule;
            }
        }
        return null;
    }

    /**
     * 单条规则条件判定（不含启用开关与总开关）：右键菜单"取消命中此包的规则"用，
     * 非法正则视为不匹配。
     */
    public static boolean matchesRule(DropPackRule rule, String host, String url) {
        if (rule == null || rule.getPattern() == null || rule.getPattern().trim().isEmpty()) {
            return false;
        }
        try {
            return matches(new CompiledRule(rule), host, url);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Proxy 消息回调入口（Burp 代理监听线程）：仅处理请求方向，命中后设置
     * ACTION_DROP / ACTION_DONT_INTERCEPT 并做灰色标记。异常只跳过本条，不中断代理。
     */
    public static void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        try {
            if (!enabled || !messageIsRequest) {
                return;
            }
            IHttpRequestResponse messageInfo = message.getMessageInfo();
            if (messageInfo == null || messageInfo.getHttpService() == null) {
                return;
            }
            String host = messageInfo.getHttpService().getHost();
            String url = Utils.helpers.analyzeRequest(messageInfo).getUrl().toString();
            CompiledRule hit = firstMatch(host, url);
            if (hit == null) {
                return;
            }
            message.setInterceptAction(hit.drop
                    ? IInterceptedProxyMessage.ACTION_DROP
                    : IInterceptedProxyMessage.ACTION_DONT_INTERCEPT);
            messageInfo.setHighlight("gray");
            messageInfo.setComment((hit.drop ? "Dropped by GatherBurp: " : "Forwarded by GatherBurp: ")
                    + hit.pattern);
            recordHit(hit);
        } catch (Exception e) {
            if (Utils.stderr != null) {
                Utils.stderr.println("DropPack processProxyMessage failed: " + e.getMessage());
            }
        }
    }

    /** 读取单条规则的累计命中次数（展示用）。 */
    public static long getHitCount(long ruleId) {
        LongAdder counter = HIT_COUNTS.get(ruleId);
        return counter == null ? 0 : counter.sum();
    }

    /** 读取丢弃动作总命中数。 */
    public static long getTotalDropped() {
        return TOTAL_DROPPED.sum();
    }

    /** 读取自动放行动作总命中数。 */
    public static long getTotalForwarded() {
        return TOTAL_FORWARDED.sum();
    }

    /** 单条规则与 host/url 的条件匹配：host/url/keyword 忽略大小写，regex 保持原语义。 */
    private static boolean matches(CompiledRule rule, String host, String url) {
        String hostLower = host == null ? "" : host.toLowerCase(Locale.ROOT);
        String urlLower = url == null ? "" : url.toLowerCase(Locale.ROOT);
        String matchType = rule.matchType;
        if (DropPackRule.MATCH_HOST.equals(matchType)) {
            // *.example.com 通配：去掉 * 保留前导点，要求子域名必然带点，根域名不误命中
            if (rule.lowerPattern.startsWith("*.")) {
                return hostLower.endsWith(rule.lowerPattern.substring(1));
            }
            return hostLower.equals(rule.lowerPattern);
        }
        if (DropPackRule.MATCH_URL.equals(matchType)) {
            // 前缀匹配要求边界（'/'、'?'、':' 或结尾），避免 /api 前缀误命中 /apix
            if (!urlLower.startsWith(rule.lowerPattern)) {
                return false;
            }
            if (urlLower.length() == rule.lowerPattern.length()) {
                return true;
            }
            char next = urlLower.charAt(rule.lowerPattern.length());
            return next == '/' || next == '?' || next == ':';
        }
        if (DropPackRule.MATCH_KEYWORD.equals(matchType)) {
            return urlLower.contains(rule.lowerPattern);
        }
        if (DropPackRule.MATCH_REGEX.equals(matchType)) {
            return rule.compiled != null
                    && rule.compiled.matcher(url == null ? "" : url).find();
        }
        return false;
    }

    /** 累加命中计数：drop/forward 分别进各自总数，单条规则计数按 id 累积。
     *  正常入口是 processProxyMessage；开放 public 供单测/冒烟直接打点验证计数逻辑。 */
    public static void recordHit(CompiledRule hit) {
        HIT_COUNTS.computeIfAbsent(hit.id, k -> new LongAdder()).increment();
        if (hit.drop) {
            TOTAL_DROPPED.increment();
        } else {
            TOTAL_FORWARDED.increment();
        }
    }

    /** 匹配用的编译后规则，不可变：regex 预编译、host/url/keyword 预转小写，避免逐包重复计算。 */
    public static final class CompiledRule {
        private final long id;
        private final boolean drop;
        private final String matchType;
        private final String pattern;
        private final String lowerPattern;
        private final Pattern compiled;

        private CompiledRule(DropPackRule rule) {
            this.id = rule.getId();
            this.drop = DropPackRule.ACTION_DROP.equals(rule.getAction());
            this.matchType = rule.getMatchType();
            this.pattern = rule.getPattern();
            this.lowerPattern = pattern.toLowerCase(Locale.ROOT);
            this.compiled = DropPackRule.MATCH_REGEX.equals(matchType)
                    ? Pattern.compile(pattern) : null;
        }

        public long getId() {
            return id;
        }

        public boolean isDrop() {
            return drop;
        }

        public String getMatchType() {
            return matchType;
        }

        public String getPattern() {
            return pattern;
        }
    }
}
