package burp.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * SQL 注入检测中的无状态纯判定逻辑。该类不发送请求，也不依赖 SqlUI 的可变状态。
 */
public final class SqlInjectionDetector {
    public enum DatabaseType { MYSQL, MSSQL, ORACLE, POSTGRESQL, SQLITE, DB2, UNKNOWN }

    private static final Pattern DEFAULT_ERROR_PAGE = Pattern.compile(
            "(?:whitelabel error page|internal server error|\\bserver error\\b|\\bapplication error\\b|" +
                    "stack trace|traceback \\(most recent call last\\)|iis 7\\.5 detailed error|" +
                    "apache tomcat[/ ]\\d|nginx[/ ]\\d)", Pattern.CASE_INSENSITIVE);
    private static final Pattern[] WAF_BODY_PATTERNS = new Pattern[]{
            Pattern.compile("access denied|request blocked|request rejected|security policy|web application firewall", Pattern.CASE_INSENSITIVE),
            Pattern.compile("cloudflare ray id|attention required.*cloudflare|cf-chl-", Pattern.CASE_INSENSITIVE),
            Pattern.compile("mod_security|modsecurity|imperva|incapsula|akamai ghost|aws waf|sucuri", Pattern.CASE_INSENSITIVE),
            Pattern.compile("请求已被拦截|被安全策略拦截|恶意请求", Pattern.CASE_INSENSITIVE)
    };
    private static final Pattern DELAY_FUNCTION_PATTERN = Pattern.compile(
            "(?i)(sleep|pg_sleep)(\\s*(?:\\(|%28)\\s*)(\\d+)(?:\\.0+)?(\\s*(?:\\)|%29))");
    private static final Pattern WAITFOR_DELAY_PATTERN = Pattern.compile(
            "(?i)(waitfor\\s+delay\\s+(?:\\'|%27)?0:0:)(\\d+)((?:\\'|%27)?)");
    private static final Pattern DBMS_PIPE_PATTERN = Pattern.compile(
            "(?i)(dbms_pipe\\.receive_message\\s*\\(\\s*(?:'|%27)?[^,')]*(?:'|%27)?\\s*,\\s*)(\\d+)(\\s*\\))");

    /** 布尔盲注长度差异的最小绝对阈值：基线波动极小的动态页面不再被 10 字节级别差异触发。 */
    public static final int MIN_BOOLEAN_LENGTH_THRESHOLD = 20;
    /** 布尔盲注长度差异相对基线长度的最小比例约束。 */
    public static final double BOOLEAN_LENGTH_RATIO = 0.02d;

    private static final Pattern[] WAF_HEADER_PATTERNS = new Pattern[]{
            Pattern.compile("(?:^|:)\\s*cloudflare", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:^|:)\\s*(?:akamai|imperva|incapsula|sucuri|mod_security)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:^|:)\\s*(?:aws\\s*waf|f5|big-ip)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?im)^(?:cf-ray|x-cdn|x-sucuri-id)\\s*:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?:^|:)\\s*cloudfront", Pattern.CASE_INSENSITIVE)
    };

    private SqlInjectionDetector() { }

    /** 格式化 SQL payload 表格中的响应体长度差值（候选 - 基线），不可用时显示 N/A。 */
    public static String formatSignedLengthChange(int originalLength, int candidateLength) {
        if (originalLength < 0 || candidateLength < 0) {
            return "N/A";
        }
        int delta = candidateLength - originalLength;
        return delta > 0 ? "+" + delta : String.valueOf(delta);
    }

    /** 判断 payload 是否包含支持的延时原语（sleep/waitfor/dbms_pipe）。 */
    public static boolean containsDelayPayload(String payload) {
        return payload != null && (DELAY_FUNCTION_PATTERN.matcher(payload).find()
                || WAITFOR_DELAY_PATTERN.matcher(payload).find()
                || DBMS_PIPE_PATTERN.matcher(payload).find());
    }

    /** 重写首个延时原语中的秒数，保持原编码与语法不变。 */
    public static String changeDelaySeconds(String payload, int seconds) {
        if (payload == null) return null;
        int safeSeconds = Math.max(1, seconds);
        java.util.regex.Matcher function = DELAY_FUNCTION_PATTERN.matcher(payload);
        if (function.find()) {
            return function.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    function.group(1) + function.group(2) + safeSeconds + function.group(4)));
        }
        java.util.regex.Matcher waitfor = WAITFOR_DELAY_PATTERN.matcher(payload);
        if (waitfor.find()) {
            return waitfor.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    waitfor.group(1) + safeSeconds + waitfor.group(3)));
        }
        java.util.regex.Matcher pipe = DBMS_PIPE_PATTERN.matcher(payload);
        if (pipe.find()) {
            return pipe.replaceFirst(java.util.regex.Matcher.quoteReplacement(
                    pipe.group(1) + safeSeconds + pipe.group(3)));
        }
        return payload;
    }

    /** 提取首个延时原语的秒数；非延时 payload 返回 0。 */
    public static int extractDelaySeconds(String payload) {
        if (payload == null || payload.isEmpty()) return 0;
        java.util.regex.Matcher function = DELAY_FUNCTION_PATTERN.matcher(payload);
        if (function.find()) {
            try { return Integer.parseInt(function.group(3)); } catch (NumberFormatException ignored) { return 0; }
        }
        java.util.regex.Matcher waitfor = WAITFOR_DELAY_PATTERN.matcher(payload);
        if (waitfor.find()) {
            try { return Integer.parseInt(waitfor.group(2)); } catch (NumberFormatException ignored) { return 0; }
        }
        java.util.regex.Matcher pipe = DBMS_PIPE_PATTERN.matcher(payload);
        if (pipe.find()) {
            try { return Integer.parseInt(pipe.group(2)); } catch (NumberFormatException ignored) { return 0; }
        }
        return 0;
    }

    /** 判断方法是否参与注入探测（GET/POST/PUT/PATCH/DELETE，忽略大小写）。 */
    public static boolean isSupportedMethod(String method) {
        if (method == null) return false;
        String normalized = method.trim().toUpperCase(Locale.ROOT);
        return "GET".equals(normalized) || "POST".equals(normalized)
                || "PUT".equals(normalized) || "PATCH".equals(normalized)
                || "DELETE".equals(normalized);
    }

    /** 判断请求是否存在可注入的检测输入（URL/Body/JSON 参数，或按开关计 Cookie/自定义头）。 */
    public static boolean hasDetectableInput(List<Integer> parameterTypes,
                                              boolean checkCookie,
                                              boolean checkHeader,
                                              boolean hasConfiguredHeaders) {
        if (parameterTypes != null) {
            for (Integer type : parameterTypes) {
                if (type == null) continue;
                if (type == burp.IParameter.PARAM_URL || type == burp.IParameter.PARAM_BODY
                        || type == burp.IParameter.PARAM_JSON
                        || (checkCookie && type == burp.IParameter.PARAM_COOKIE)) return true;
            }
        }
        return checkHeader && hasConfiguredHeaders;
    }

    /** 实际响应体字节数（无响应或偏移非法返回 0）。 */
    public static int actualBodyLength(byte[] response, int bodyOffset) {
        if (response == null || bodyOffset < 0 || bodyOffset > response.length) return 0;
        return response.length - bodyOffset;
    }

    /** 提取响应体中命中的错误签名集合（自定义关键字 + 规则，带来源前缀）。 */
    public static Set<String> findErrorSignatures(String responseBody,
                                                   List<Pattern> rules,
                                                   List<String> customKeys) {
        if (responseBody == null || responseBody.isEmpty()) return Collections.emptySet();
        Set<String> signatures = new LinkedHashSet<>();
        String lower = responseBody.toLowerCase(Locale.ROOT);
        if (customKeys != null) {
            for (String key : customKeys) {
                if (key != null && !key.trim().isEmpty() && lower.contains(key.toLowerCase(Locale.ROOT))) {
                    signatures.add("custom:" + key.trim().toLowerCase(Locale.ROOT));
                }
            }
        }
        if (rules != null) {
            for (Pattern rule : rules) {
                if (rule != null && rule.matcher(responseBody).find()) signatures.add("rule:" + rule.pattern());
            }
        }
        return signatures;
    }

    /** 候选响应是否出现基线中不存在的错误签名（错误注入判定的核心条件）。 */
    public static boolean hasNewErrorSignature(String baselineBody, String candidateBody,
                                                List<Pattern> rules, List<String> customKeys) {
        Set<String> baseline = findErrorSignatures(baselineBody, rules, customKeys);
        Set<String> candidate = new LinkedHashSet<>(findErrorSignatures(candidateBody, rules, customKeys));
        candidate.removeAll(baseline);
        return !candidate.isEmpty();
    }

    /** 分级分析错误签名；候选中已存在于基线的签名不会产生分数。 */
    public static SqlErrorEvidence analyzeSqlError(String baselineBody, String candidateBody,
                                                    List<SqlErrorRule> rules, List<String> customKeys) {
        if (candidateBody == null || candidateBody.trim().isEmpty()) return SqlErrorEvidence.empty();
        String baseline = baselineBody == null ? "" : baselineBody;
        Set<String> high = new LinkedHashSet<>();
        Set<String> medium = new LinkedHashSet<>();
        Set<String> low = new LinkedHashSet<>();
        DatabaseType db = DatabaseType.UNKNOWN;
        if (rules != null) {
            for (SqlErrorRule rule : rules) {
                if (rule == null || !rule.getPattern().matcher(candidateBody).find()) continue;
                if (rule.getPattern().matcher(baseline).find()) continue;
                String id = rule.getId();
                if (rule.getConfidence() == SqlErrorRule.Confidence.HIGH) {
                    high.add(id);
                } else if (rule.getConfidence() == SqlErrorRule.Confidence.MEDIUM) {
                    medium.add(id);
                } else {
                    low.add(id);
                }
                if (db == DatabaseType.UNKNOWN && rule.getDatabaseType() != DatabaseType.UNKNOWN) {
                    db = rule.getDatabaseType();
                }
            }
        }
        if (customKeys != null) {
            String candidateLower = candidateBody.toLowerCase(Locale.ROOT);
            String baselineLower = baseline.toLowerCase(Locale.ROOT);
            for (String key : customKeys) {
                if (key == null || key.trim().isEmpty()) continue;
                String normalized = key.trim().toLowerCase(Locale.ROOT);
                if (candidateLower.contains(normalized) && !baselineLower.contains(normalized)) {
                    low.add("custom:" + normalized);
                }
            }
        }
        int score = (!high.isEmpty() ? 40 : 0)
                + (!medium.isEmpty() ? 30 : 0)
                + (!low.isEmpty() ? 15 : 0);
        if (high.isEmpty() && medium.isEmpty()) score = Math.min(49, score);
        return new SqlErrorEvidence(high, medium, low, db, Math.min(100, score));
    }

    /**
     * 判断响应本身是否泄露了数据库/SQL 错误信息。
     *
     * <p>这与 SQL 注入判定不同：这里不要求候选响应相对基线出现“新”错误，
     * 适用于 Burp 被动收到的原始响应。为降低误报，低置信通用词不能单独触发；
     * 至少需要高置信异常类名，或中置信数据库查询错误与 SQL 语句上下文。</p>
     */
    public static boolean isLikelySqlErrorDisclosure(String responseBody,
                                                       List<SqlErrorRule> rules,
                                                       List<String> customKeys) {
        SqlErrorEvidence evidence = analyzeSqlError("", responseBody, rules, customKeys);
        if (evidence.isEmpty() || evidence.isLowConfidenceOnly()) {
            return false;
        }
        return evidence.hasHighConfidenceSignature()
                || (!evidence.getMediumConfidenceSignatures().isEmpty()
                && responseBody != null
                && responseBody.matches("(?is).*\\b(?:select|insert|update|delete)\\b.*"));
    }

    /** 内置 SQL 错误特征规则集（按 HIGH/MEDIUM/LOW 分级，覆盖各数据库厂商特征）。 */
    public static List<SqlErrorRule> defaultErrorRules() {
        List<SqlErrorRule> rules = new ArrayList<>();
        addRules(rules, SqlErrorRule.Confidence.HIGH, 40, DatabaseType.UNKNOWN,
                new String[]{"java\\.sql\\.SQLException", "java\\.sql\\.SQLSyntaxErrorException", "MySQLSyntaxErrorException",
                        "\\bDBException\\b", "\\bSQLSyntaxErrorException\\b"});
        addRules(rules, SqlErrorRule.Confidence.HIGH, 40, DatabaseType.MYSQL,
                new String[]{"MySQL\\s+server\\s+version", "You\\s+have\\s+an\\s+error\\s+in\\s+your\\s+SQL\\s+syntax", "mysql_fetch_array\\s*\\("});
        addRules(rules, SqlErrorRule.Confidence.HIGH, 40, DatabaseType.ORACLE,
                new String[]{"ORA-\\d{5}", "PLS-\\d{4,5}"});
        addRules(rules, SqlErrorRule.Confidence.HIGH, 40, DatabaseType.POSTGRESQL,
                new String[]{"PG::SyntaxError", "PSQLException", "org\\.postgresql\\.(?:util\\.)?PSQLException"});
        addRules(rules, SqlErrorRule.Confidence.HIGH, 40, DatabaseType.MSSQL,
                new String[]{"System\\.Data\\.SqlClient\\.SqlException", "SQLServerException", "Microsoft\\s+SQL\\s+Server", "Incorrect\\s+syntax\\s+near"});
        addRules(rules, SqlErrorRule.Confidence.HIGH, 40, DatabaseType.SQLITE,
                new String[]{"SQLite(?:3)?\\s+error"});
        addRules(rules, SqlErrorRule.Confidence.MEDIUM, 30, DatabaseType.UNKNOWN,
                new String[]{"Unclosed\\s+quotation\\s+mark", "Unknown\\s+column", "Column\\s+count\\s+doesn.t\\s+match", "DB2\\s+SQL\\s+error", "Microsoft\\s+OLE\\s+DB",
                        "(?:执行(?:本地)?sql|数据库查询|查询语句).{0,40}(?:出错|错误|失败)",
                        "查询语句\\s*[:：]\\s*(?:select|insert|update|delete)\\b"});
        addRules(rules, SqlErrorRule.Confidence.LOW, 15, DatabaseType.UNKNOWN,
                new String[]{"syntax\\s+error", "sql\\s+error", "database\\s+error", "where\\s+clause", "sql\\s+syntax", "数据库出错", "引号不完整"});
        return rules;
    }

    private static void addRules(List<SqlErrorRule> target, SqlErrorRule.Confidence confidence,
                                 int score, DatabaseType db, String[] regexes) {
        for (String regex : regexes) {
            target.add(new SqlErrorRule(regex, regex, confidence, db, score));
        }
    }

    /** 大小写不敏感地替换已有 header（不修改原列表），找不到返回空列表。 */
    public static List<String> replaceHeader(List<String> headers, String headerName, String value) {
        if (headers == null || headerName == null || headerName.trim().isEmpty()) {
            return Collections.emptyList();
        }
        String expected = headerName.trim();
        List<String> result = new ArrayList<>(headers);
        for (int i = 1; i < result.size(); i++) {
            String header = result.get(i);
            int separator = header.indexOf(':');
            if (separator <= 0) continue;
            String actualName = header.substring(0, separator).trim();
            if (actualName.equalsIgnoreCase(expected)) {
                result.set(i, actualName + ": " + (value == null ? "" : value));
                return result;
            }
        }
        return Collections.emptyList();
    }

    /** 把 payload 作为新 Header 追加到请求头列表末尾（用于探测原请求不存在的 Header）。 */
    public static List<String> insertHeader(List<String> headers, String headerName, String value) {
        if (headers == null || headers.isEmpty() || headerName == null || headerName.trim().isEmpty()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>(headers);
        result.add(headerName.trim() + ": " + (value == null ? "" : value));
        return result;
    }

    /**
     * 在 form 编码串（a=1&b=2）中原地替换第一个同名参数的值为已编码值。
     * 只做原始文本替换，不做任何编码——调用方负责传入恰好编码一次的值。
     * 找不到同名参数时返回 null。
     */
    public static String replaceFormParamValue(String rawPairs, String paraName, String encodedValue) {
        if (rawPairs == null || paraName == null || paraName.isEmpty() || encodedValue == null) {
            return null;
        }
        String[] pairs = rawPairs.split("&", -1);
        StringBuilder rebuilt = new StringBuilder(rawPairs.length() + encodedValue.length());
        boolean replaced = false;
        for (int i = 0; i < pairs.length; i++) {
            if (i > 0) rebuilt.append('&');
            String pair = pairs[i];
            int separator = pair.indexOf('=');
            String rawName = separator < 0 ? pair : pair.substring(0, separator);
            if (!replaced && rawParameterNameMatches(rawName, paraName)) {
                rebuilt.append(rawName).append('=').append(encodedValue);
                replaced = true;
            } else {
                rebuilt.append(pair);
            }
        }
        return replaced ? rebuilt.toString() : null;
    }

    /**
     * 在请求行（如 "GET /a?b=1&amp;c=2 HTTP/1.1"）中替换第一个同名 query 参数的值。
     * 只做原始文本替换，不做任何编码；找不到同名参数时返回 null。
     */
    public static String replaceUrlParamInRequestLine(String requestLine, String paraName, String encodedValue) {
        if (requestLine == null || paraName == null || paraName.isEmpty() || encodedValue == null) {
            return null;
        }
        int firstSpace = requestLine.indexOf(' ');
        int lastSpace = requestLine.lastIndexOf(' ');
        if (firstSpace < 0 || lastSpace <= firstSpace) {
            return null;
        }
        String method = requestLine.substring(0, firstSpace);
        String target = requestLine.substring(firstSpace + 1, lastSpace);
        String version = requestLine.substring(lastSpace + 1);
        int queryStart = target.indexOf('?');
        if (queryStart < 0) {
            return null;
        }
        String newQuery = replaceFormParamValue(target.substring(queryStart + 1), paraName, encodedValue);
        if (newQuery == null) {
            return null;
        }
        return method + " " + target.substring(0, queryStart + 1) + newQuery + " " + version;
    }

    /** 原始参数名匹配：先按原文比较，再按 URL 解码后比较（query 中参数名可能已编码）。 */
    private static boolean rawParameterNameMatches(String rawName, String paraName) {
        if (rawName.equals(paraName)) {
            return true;
        }
        try {
            return java.net.URLDecoder.decode(rawName, "UTF-8").equals(paraName);
        } catch (Exception e) {
            return false;
        }
    }

    /** 综合判定响应是否被 WAF 拦截（连接重置/状态码+指纹组合），返回证据与置信分。 */
    public static WafEvidence detectWaf(int statusCode, List<String> responseHeaders,
                                        String responseBody, boolean connectionReset) {
        if (connectionReset) return new WafEvidence(true, "", 40, "connection reset", true);
        String body = responseBody == null ? "" : responseBody;
        String headerText = responseHeaders == null ? "" : join(responseHeaders);
        String provider = findWafProvider(headerText + " " + body);
        boolean bodyMatch = matchesAny(body, WAF_BODY_PATTERNS);
        boolean headerMatch = matchesAny(headerText, WAF_HEADER_PATTERNS);
        // X-CDN 等辅助头不能单独把普通 CDN/业务 403 判为 WAF；强指纹头才可与状态码关联。
        boolean strongHeaderMatch = matchesAny(headerText, new Pattern[]{
                WAF_HEADER_PATTERNS[0], WAF_HEADER_PATTERNS[1], WAF_HEADER_PATTERNS[2], WAF_HEADER_PATTERNS[4]
        });
        boolean statusMatch = statusCode == 403 || statusCode == 406 || statusCode == 429;
        boolean blocked = (statusMatch && (bodyMatch || strongHeaderMatch))
                || (bodyMatch && (strongHeaderMatch || headerMatch));
        if (!blocked) return WafEvidence.none();
        String reason = statusMatch ? "blocked status" : "waf response signature";
        return new WafEvidence(true, provider, 40, reason, false);
    }

    private static String findWafProvider(String value) {
        String lower = value == null ? "" : value.toLowerCase(Locale.ROOT);
        if (lower.contains("cloudflare") || lower.contains("cf-ray")) return "Cloudflare";
        if (lower.contains("akamai")) return "Akamai";
        if (lower.contains("imperva") || lower.contains("incapsula")) return "Imperva";
        if (lower.contains("modsecurity") || lower.contains("mod_security")) return "ModSecurity";
        if (lower.contains("aws waf")) return "AWS WAF";
        if (lower.contains("sucuri") || lower.contains("x-sucuri-id")) return "Sucuri";
        if (lower.contains("cf-ray")) return "Cloudflare";
        if (lower.contains("x-cdn")) return "CDN/WAF";
        return "WAF";
    }

    private static String join(List<String> values) {
        StringBuilder builder = new StringBuilder();
        if (values != null) for (String value : values) if (value != null) builder.append(value).append('\n');
        return builder.toString();
    }

    private static boolean matchesAny(String value, Pattern[] patterns) {
        if (value == null) return false;
        for (Pattern pattern : patterns) if (pattern.matcher(value).find()) return true;
        return false;
    }

    /** 依据错误特征识别数据库类型（命中首个厂商特征即返回，否则 UNKNOWN）。 */
    public static DatabaseType identifyDatabase(String responseBody, List<String> responseHeaders) {
        String text = (responseBody == null ? "" : responseBody) + "\n" + join(responseHeaders);
        for (SqlErrorRule rule : defaultErrorRules()) {
            if (rule.getDatabaseType() != DatabaseType.UNKNOWN && rule.getPattern().matcher(text).find()) {
                return rule.getDatabaseType();
            }
        }
        return DatabaseType.UNKNOWN;
    }

    /** 判断 5xx 响应是否为框架默认错误页（白标/服务器错误等，非 SQL 错误证据）。 */
    public static boolean isDefaultErrorPage(int statusCode, List<String> headers, String body) {
        if (statusCode < 500) return false;
        return body != null && DEFAULT_ERROR_PAGE.matcher(body).find();
    }

    /** 布尔盲注差异评估：长度差（自适应阈值）+ 相似度差双通道，输出证据与置信分。 */
    public static BooleanEvidence evaluateBooleanDifference(ResponseSnapshot original,
                                                             ResponseSnapshot abnormal,
                                                             ResponseSnapshot normal,
                                                             BaselineStats baseline,
                                                             int configuredLengthThreshold,
                                                             double similarityThreshold) {
        if (original == null || abnormal == null || normal == null) return BooleanEvidence.empty();
        if (original.isWafBlocked() || abnormal.isWafBlocked() || normal.isWafBlocked()) return BooleanEvidence.empty();
        if (baseline != null && !baseline.isStatusStable()) return new BooleanEvidence(false, false, false, true, 0);
        if (abnormal.isDefaultErrorPage() && abnormal.getStatusCode() >= 500) return BooleanEvidence.empty();
        boolean statusSafe = isBooleanStatusSafe(original.getStatusCode(), abnormal.getStatusCode(), normal.getStatusCode());
        if (!statusSafe) return new BooleanEvidence(false, false, false, true, 0);
        // 长度阈值 = max(配置值, 20, 基线长度×2%, 基线长度标准差×3)。
        // 基线缺失时（测试工具/遗留封装/缓存淘汰边界）退回旧语义：完全信任调用方配置的阈值。
        int threshold = Math.max(0, configuredLengthThreshold);
        if (baseline != null) {
            threshold = Math.max(threshold, MIN_BOOLEAN_LENGTH_THRESHOLD);
            threshold = Math.max(threshold, baseline.getBodyLengthStandardDeviation() * 3);
            int referenceLength = Math.max(0, baseline.getMedianBodyLength());
            threshold = Math.max(threshold, (int) Math.round(referenceLength * BOOLEAN_LENGTH_RATIO));
        }
        int originalLength = cleanForLength(original.getBody()).length();
        int abnormalLength = cleanForLength(abnormal.getBody()).length();
        int normalLength = cleanForLength(normal.getBody()).length();
        boolean lengthMatched = Math.abs(originalLength - normalLength) <= threshold
                && Math.abs(originalLength - abnormalLength) > threshold
                && Math.abs(normalLength - abnormalLength) > threshold;
        double limit = Math.max(0.0d, Math.min(1.0d, similarityThreshold));
        double originalNormal = ResponseSimilarityMatcher.calculateSimilarity(original.getBody(), normal.getBody());
        double originalAbnormal = ResponseSimilarityMatcher.calculateSimilarity(original.getBody(), abnormal.getBody());
        double normalAbnormal = ResponseSimilarityMatcher.calculateSimilarity(normal.getBody(), abnormal.getBody());
        boolean similarityMatched = originalNormal >= limit && originalAbnormal < limit && normalAbnormal < limit;
        int score = lengthMatched && similarityMatched ? 35 : (lengthMatched || similarityMatched ? 10 : 0);
        return new BooleanEvidence(lengthMatched, similarityMatched, true, false, score);
    }

    private static boolean isBooleanStatusSafe(int original, int abnormal, int normal) {
        if (original >= 500 || normal >= 500) return false;
        // 200 -> 500 这类状态码跃迁优先视为应用异常，而不是布尔条件差异。
        if (abnormal >= 500 && abnormal != original) return false;
        return true;
    }

    /**
     * 重放一致性校验：abnormal/normal 的重放响应必须与首次探测的响应保持同类
     * （abnormal 重放 ≈ abnormal 首测，normal 重放 ≈ normal 首测），
     * 排除随机动态页面两次探测恰好"互异"造成的假布尔模式。
     */
    public static boolean isBooleanReplayConsistent(String firstAbnormalBody, String replayAbnormalBody,
                                                    String firstNormalBody, String replayNormalBody,
                                                    double similarityThreshold) {
        if (firstAbnormalBody == null || replayAbnormalBody == null
                || firstNormalBody == null || replayNormalBody == null) {
            return false;
        }
        return ResponseSimilarityMatcher.calculateSimilarity(firstAbnormalBody, replayAbnormalBody) >= similarityThreshold
                && ResponseSimilarityMatcher.calculateSimilarity(firstNormalBody, replayNormalBody) >= similarityThreshold;
    }

    /** 布尔盲注差异的字符串级封装（无基线/快照上下文，固定 200 状态码）。 */
    public static boolean isBooleanDifference(String original, String abnormal, String normal,
                                               int lengthThreshold, double similarityThreshold) {
        BooleanEvidence evidence = evaluateBooleanDifference(
                new ResponseSnapshot(200, Collections.<String>emptyList(), original, cleanForLength(original).length(), 0, false, false),
                new ResponseSnapshot(200, Collections.<String>emptyList(), abnormal, cleanForLength(abnormal).length(), 0, false, false),
                new ResponseSnapshot(200, Collections.<String>emptyList(), normal, cleanForLength(normal).length(), 0, false, false),
                null, lengthThreshold, similarityThreshold);
        return evidence.isConfirmedPattern();
    }

    /** 单次时间延迟判定：候选耗时需同时超过配置阈值与基线+最小增量。 */
    public static boolean isLikelyTimeDelay(long baselineMs, long candidateMs,
                                             long configuredThresholdMs, long minimumDeltaMs) {
        if (candidateMs < 0) return false;
        long configured = Math.max(0L, configuredThresholdMs);
        long delta = Math.max(0L, minimumDeltaMs);
        long baselineThreshold = baselineMs < 0 ? 0L : baselineMs + delta;
        return candidateMs >= Math.max(configured, baselineThreshold);
    }

    /** 时间延迟的重复确认判定：两次探测（首测+确认）都需达到延迟阈值。 */
    public static boolean isRepeatedTimeDelay(long baselineMs, long firstCandidateMs,
                                               long confirmationMs, long configuredThresholdMs,
                                               long minimumDeltaMs) {
        return isLikelyTimeDelay(baselineMs, firstCandidateMs, configuredThresholdMs, minimumDeltaMs)
                && isLikelyTimeDelay(baselineMs, confirmationMs, configuredThresholdMs, minimumDeltaMs);
    }

    /** 时间延迟综合评估（短/长延时相关性 + 单调性），高方差基线直接判不稳定。 */
    public static TimeDelayEvidence evaluateTimeDelay(BaselineStats baseline,
                                                       long shortResponseMs,
                                                       long longResponseMs,
                                                       long shortSleepMs,
                                                       long longSleepMs,
                                                       long configuredThresholdMs,
                                                       long minimumDeltaMs) {
        if (baseline == null || baseline.isHighVariance()) return new TimeDelayEvidence(false, false, false, true, 0);
        long base = baseline.getMedianResponseTimeMs();
        // 短延时用于建立相关性，不应被全局绝对阈值直接淘汰；长延时仍需同时满足配置阈值。
        boolean shortMatched = isLikelyExpectedTimeDelay(base, shortResponseMs, shortSleepMs, false,
                configuredThresholdMs, minimumDeltaMs);
        boolean longMatched = isLikelyExpectedTimeDelay(base, longResponseMs, longSleepMs, true,
                configuredThresholdMs, minimumDeltaMs);
        long expectedDelta = Math.max(1L, longSleepMs - shortSleepMs);
        boolean monotonic = longResponseMs > shortResponseMs
                && longResponseMs - shortResponseMs >= Math.max(250L, expectedDelta / 2L);
        int score = shortMatched && longMatched && monotonic ? 40 : (shortMatched || longMatched ? 20 : 0);
        return new TimeDelayEvidence(shortMatched, longMatched, monotonic, false, score);
    }

    /** 期望延迟判定：候选耗时需超过基线 + max(500ms, 期望sleep×60%)，长延时另需配置阈值。 */
    public static boolean isLikelyExpectedTimeDelay(long baselineMs, long candidateMs,
                                                    long expectedSleepMs, boolean requireConfiguredThreshold,
                                                    long configuredThresholdMs, long minimumDeltaMs) {
        if (candidateMs < 0L || expectedSleepMs <= 0L) return false;
        long base = Math.max(0L, baselineMs);
        long expectedDelta = Math.max(500L, Math.round(expectedSleepMs * 0.60d));
        long required = base + expectedDelta;
        if (requireConfiguredThreshold) {
            required = Math.max(required, Math.max(0L, configuredThresholdMs));
        } else if (minimumDeltaMs > 0L) {
            required = Math.max(required, base + Math.min(minimumDeltaMs, expectedDelta));
        }
        return candidateMs >= required;
    }

    private static String cleanForLength(String value) {
        return value == null ? "" : value.replaceAll("\\s+", "");
    }

    /** 默认错误规则的只读视图。 */
    public static List<SqlErrorRule> immutableDefaultErrorRules() {
        return Collections.unmodifiableList(defaultErrorRules());
    }

    /** 支持的数据库显示名列表（只读）。 */
    public static List<String> supportedDatabaseNames() {
        return Collections.unmodifiableList(Arrays.asList("mysql", "mssql", "oracle", "postgresql", "sqlite", "db2"));
    }
}

