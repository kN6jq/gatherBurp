package burp.ui;

import burp.*;
import burp.bean.SqlBean;
import burp.utils.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.security.MessageDigest;
import java.util.regex.Pattern;

import static burp.IParameter.*;
import static burp.dao.ConfigDao.getConfig;
import static burp.dao.SqlDao.*;

/** SQL 注入检测面板：错误回显 / 布尔盲注 / 时间盲注 / 被动错误泄露四类检测。
 *  纯判定逻辑收口在 SqlInjectionDetector（无状态），本类持有扫描状态——
 *  按 logid 索引的基线/证据/预算均为有界 LRU（扫描线程池多线程读写），
 *  探测请求经 HostThrottle 限速；结果入 urldata/payloaddata 静态列表。 */
public class SqlUI extends AbstractScanUI {
    private JTable payloadtable; // payload 表格
    private JScrollPane payloadtablescrollpane; // payload 表格滚动
    private JCheckBox deleteOriginalValueCheckBox; // 删除原始值选择框
    private JCheckBox checkCookieCheckBox; // 检测cookie选择框
    private JCheckBox checkHeaderCheckBox; // 检测header选择框
    private JCheckBox checkWhiteListCheckBox; // 白名单域名检测选择框
    private JCheckBox urlEncodeCheckBox; // 是否对参数进行url编码
    private JButton saveWhiteListButton; // 白名单域名保存按钮
    private JButton saveHeaderListButton; // 保存header按钮
    private JTextArea whiteListTextArea; // 白名单域名输入框列表
    private JTextArea headerTextArea; // header检测数据框列表
    private JButton refreshTableButton; // 刷新表格按钮
    private JButton clearTableButton; // 清空表格按钮
    private JTextArea sqlPayloadTextArea; // sqlpayload输入框
    private JTextArea sqlErrorKeyTextArea; // sqlerrkey输入框
    private JButton saveSqlPayloadButton; // sqlpayload保存按钮
    private JButton saveSqlErrorKeyButton; // sqlerrkey保存按钮

    private static final List<SqlUIEntry> urldata = new ArrayList<>();  // urldata
    private static final List<SqlPayloadEntry> payloaddata = new ArrayList<>(); // payload
    private static final List<SqlPayloadEntry> payloaddata2 = new ArrayList<>(); // payload
    private static boolean isPassiveScan; // 是否被动扫描
    private static boolean isCheckCookie; // 是否检测cookie
    private static boolean isCheckHeader; // 是否检测header
    private static boolean isWhiteDomain; // 是否白名单域名
    private static boolean isDeleteOrgin; // 是否删除原始值
    private static boolean isUrlEncode; // 是否进行URL编码
    private static boolean isInsertMissingHeader; // Header探测是否允许新增原请求不存在的头
    private static volatile List<String> listErrorKey = new ArrayList<>(); // // 存放错误key
    private static volatile List<SqlBean> sqliPayload = new ArrayList<>(); // 存放sql关键字
    private static volatile List<SqlBean> headerList = new ArrayList<>(); // 存放header白名单
    private static volatile List<String> domainList = new ArrayList<>(); // 存放域名白名单
    // 以下按 logid/位置 索引的状态统一改为容量上限的 LRU 缓存（扫描线程池多线程读写），
    // 防止长时间被动扫描内存无限增长；容量远大于线程池并发在检 URL 数，活动条目不会被误淘汰。
    private static final int MAX_TRACKED_URL_STATE = 500;
    private static final int MAX_TRACKED_ISSUE_KEYS = 5000;
    private static final LruCache<Integer, Set<String>> vul = new LruCache<>(MAX_TRACKED_URL_STATE);// 防止插入重复
    private static final LruCache<Integer, Set<String>> reportedIssues = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final LruCache<Integer, Set<String>> confirmedLocations = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final LruCache<Integer, String> baselineResponseBodies = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final LruCache<Integer, Long> baselineResponseTimes = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final LruCache<Integer, BaselineStats> baselineStatsMap = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final LruCache<Integer, IHttpRequestResponse> baselineRequestResponses = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final LruCache<Integer, SqlInjectionDetector.DatabaseType> databaseFingerprints = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final LruCache<String, AtomicInteger> wafBlockCounters = new LruCache<>(2048);
    /** 被动 SQL 错误泄露按 URL + 指纹去重，不受注入 URL 缓存影响。 */
    private static final LruSet<String> passiveErrorIssueKeys = new LruSet<>(MAX_TRACKED_ISSUE_KEYS);
    private static final LruCache<String, ScanBudget> parameterBudgets = new LruCache<>(MAX_TRACKED_URL_STATE * 8);
    private static final LruCache<String, TimeCandidateState> timeCandidates = new LruCache<>(MAX_TRACKED_URL_STATE * 4);
    private JCheckBox booleanBlindCheckBox; // 布尔盲注选择框
    private static boolean isBooleanBlind;  // 是否进行布尔盲注
    private JCheckBox insertMissingHeaderCheckBox; // Header缺失时新增探测选择框
    private static int timeBlindThreshold = 6000; // 延时注入阈值(ms)
    private static int lengthThreshold = 10; // 响应长度差异阈值
    private static int similarityThreshold = 85; // 相似度阈值(百分比)
    private static final long MIN_TIME_DELAY_DELTA = 2500L; // 相对基线的最小延时差(ms)
    private static final int BASELINE_SAMPLE_COUNT = 3;
    private static final double BASELINE_HIGH_VARIANCE_RATIO = 0.5d;
    private static final int MAX_CUSTOM_PAYLOADS_PER_PARAMETER = 6;
    /** 结果列表容量上限，超限淘汰最旧条目（与其他扫描模块口径一致）。 */
    private static final int MAX_LOG_ENTRIES = 2000;
    private static final List<SqlErrorRule> SQL_ERROR_RULES = SqlInjectionDetector.immutableDefaultErrorRules();
    // 当前面板实例：静态入口（dispatchPassiveHttpMessage 等）经此定位到实例
    private static volatile SqlUI instance;
    private static final LruCache<Integer, List<SqlPayloadEntry>> urlPayloadMapping = new LruCache<>(MAX_TRACKED_URL_STATE);
    private static final AtomicInteger urlIdCounter = new AtomicInteger(0);

    /** 清空全部扫描状态（基线/证据/预算/去重键），并同步重置共享节流器与 URL 缓存。 */
    public static void resetAllCaches() {
        urlPayloadMapping.clear();
        vul.clear();
        reportedIssues.clear();
        passiveErrorIssueKeys.clear();
        confirmedLocations.clear();
        baselineResponseBodies.clear();
        baselineResponseTimes.clear();
        baselineStatsMap.clear();
        baselineRequestResponses.clear();
        databaseFingerprints.clear();
        wafBlockCounters.clear();
        // WAF 慢速主机标记与最后请求时间已收口到共享节流器
        HostThrottle.reset();
        parameterBudgets.clear();
        timeCandidates.clear();
        UrlCacheUtil.resetCache("sqli");
    }

    // 预编译响应清理规则，供历史 UI 对比逻辑使用；核心证据判定在 SqlInjectionDetector 中。
    private static final Pattern CLEAN_LONG_TOKEN = Pattern.compile("[a-zA-Z0-9]{32,}");
    private static final Pattern CLEAN_TOKEN_PARAM = Pattern.compile("token=([^&\\s\"']+)");
    private static final Pattern CLEAN_TIMESTAMP = Pattern.compile("\\d{10,13}");
    private static final Pattern CLEAN_DATETIME = Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T\\s]\\d{2}:\\d{2}:\\d{2}");
    private static final Pattern CLEAN_ID = Pattern.compile("id=\"?\\d+\"?");
    private static final Pattern CLEAN_CSRF = Pattern.compile("csrf[^=]+=([^&\\s\"']+)");
    private static final Pattern CLEAN_JSESSIONID = Pattern.compile("JSESSIONID=([^;\\s\"']+)");
    private static final Pattern CLEAN_SESSION = Pattern.compile("session[^=]+=([^&\\s\"']+)");
    private static final Pattern CLEAN_TMP_PATH = Pattern.compile("/tmp/[^\\s\"']+");
    private static final Pattern CLEAN_FILENAME = Pattern.compile("filename=\"[^\"]+\"");
    private static final Pattern CLEAN_HTML_COMMENT = Pattern.compile("<!--[\\s\\S]*?-->");
    private static final Pattern CLEAN_VERSION = Pattern.compile("v\\d+\\.\\d+\\.\\d+");
    private static final Pattern CLEAN_UUID = Pattern.compile("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}");
    private static final Pattern CLEAN_WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern CLEAN_HTML_TAGS = Pattern.compile("<[^>]+>");

    /** SQL 检测核心（ScanTaskExecutor 池线程）：被动入口先记录再过滤，
     *  基线采样后按参数位置执行错误/布尔/时间三类探测。isSend=手动扫描，false=被动。 */
    public static void Check(IHttpRequestResponse[] requestResponses, boolean isSend) {
        if (requestResponses == null || requestResponses.length == 0
                || requestResponses[0] == null || Utils.helpers == null) {
            if (Utils.stderr != null) {
                Utils.stderr.println("[SQL] scan skipped: request/response or Burp helpers unavailable");
            }
            return;
        }
        IHttpRequestResponse baseRequestResponse = requestResponses[0];
        if (baseRequestResponse.getRequest() == null || baseRequestResponse.getHttpService() == null) {
            if (Utils.stderr != null) {
                Utils.stderr.println("[SQL] scan skipped: request or HTTP service unavailable");
            }
            return;
        }
        IRequestInfo analyzeRequest;
        try {
            analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        } catch (Exception e) {
            logScanMessage("request analysis failed: " + e.getMessage());
            return;
        }
        if (analyzeRequest == null) {
            logScanMessage("request analysis returned null");
            return;
        }
        List<String> reqheaders = analyzeRequest.getHeaders() == null
                ? Collections.emptyList() : analyzeRequest.getHeaders();
        String host = baseRequestResponse.getHttpService().getHost();
        String method = analyzeRequest.getMethod();
        URL rdurlURL = analyzeRequest.getUrl();
        String url = rdurlURL == null ? "" : rdurlURL.toString();
        List<IParameter> paraLists = analyzeRequest.getParameters() == null
                ? Collections.emptyList() : analyzeRequest.getParameters();

        // 被动入口先落一条记录，避免前置过滤造成“插件没有流量”的假象。
        int logid = isSend ? -1 : addUrl(method, url, 0, baseRequestResponse);
        if (!SqlInjectionDetector.isSupportedMethod(method)) {
            updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_method"));
            return;
        }
        if (Utils.isUrlBlackListSuffix(url)) {
            updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_blacklist"));
            return;
        }

        // 检查是否存在实际可检测的输入点，Cookie/Header 开关只作用于对应位置。
        List<Integer> parameterTypes = new ArrayList<>();
        for (IParameter para : paraLists) {
            parameterTypes.add((int) para.getType());
        }

        if (!isSend && isWhiteDomain && !Utils.isMatchDomainName(host, domainList)) {
            updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_whitelist"));
            return;
        }

        /*
         * 被动响应中的 SQL/数据库错误泄露是独立于“参数可变异性”的被动问题。
         * 必须在 URL 去重和 hasDetectableInput 之前识别，否则无参数 GET、已被注入
         * URL 缓存命中的接口响应会被提前删除，用户只能看到“没有流量/没有报错”。
         */
        boolean passiveErrorDisclosure = false;
        if (!isSend && baseRequestResponse.getResponse() != null) {
            String passiveBody = getResponseBody(baseRequestResponse);
            passiveErrorDisclosure = SqlInjectionDetector.isLikelySqlErrorDisclosure(
                    passiveBody, SQL_ERROR_RULES, listErrorKey);
            if (passiveErrorDisclosure) {
                String passiveKey = buildPassiveErrorIssueKey(url, passiveBody);
                if (!passiveErrorIssueKeys.add(passiveKey)) {
                    updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_error_reported"));
                    return;
                }
                int passiveLength = getResponseLength(baseRequestResponse);
                updateUrl(logid, method, url, passiveLength,
                        I18nUtils.get("sql.detection.in_progress"), baseRequestResponse);
                reportPassiveSqlErrorDisclosure(logid, url, baseRequestResponse);
                addToVulStr(logid, I18nUtils.get("sql.detection.complete"));
                updateUrl(logid, method, url, passiveLength,
                        getVulnerabilityMessage(logid), baseRequestResponse);
                // 错误信息泄露不需要再对同一被动响应发送注入 payload，避免无效流量。
                return;
            }
        }

        if (!isSend) {
            if (!UrlCacheUtil.checkUrlUnique("sqli", method, rdurlURL, paraLists)) {
                updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_duplicate"));
                return;
            }
        }

        // 没有可检测参数时才按普通跳过项处理；被动错误泄露已在上面直接完成。
        if (!SqlInjectionDetector.hasDetectableInput(parameterTypes, isCheckCookie, isCheckHeader, !headerList.isEmpty())) {
            updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_no_params"));
            return;
        }

        // 发送原始请求用于对比
        byte[] request = baseRequestResponse.getRequest();
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
        BaselineSample baselineSample = sampleBaseline(
                baseRequestResponse.getHttpService(),
                Utils.helpers.buildHttpMessage(reqheaders, body),
                BASELINE_SAMPLE_COUNT);
        if (baselineSample == null || baselineSample.representative == null
                || baselineSample.representative.getResponse() == null) {
            if (passiveErrorDisclosure) {
                finishPassiveOnly(logid, method, url, getResponseLength(baseRequestResponse), baseRequestResponse);
            } else {
                updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_baseline_failed"));
            }
            return;
        }
        IHttpRequestResponse originalRequestResponse = baselineSample.representative;
        BaselineStats baselineStats = baselineSample.stats;
        try {
            IResponseInfo baselineInfo = Utils.helpers.analyzeResponse(originalRequestResponse.getResponse());
            WafEvidence baselineWaf = SqlInjectionDetector.detectWaf(
                    baselineInfo.getStatusCode(), baselineInfo.getHeaders(),
                    getResponseBody(originalRequestResponse), false);
            if (baselineWaf.isBlocked()) {
                if (passiveErrorDisclosure) {
                    finishPassiveOnly(logid, method, url, getResponseLength(baseRequestResponse), baseRequestResponse);
                } else {
                    updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_baseline_waf"));
                }
                return;
            }
        } catch (Exception ignored) {
            // 解析失败时交给后续保守逻辑处理。
        }
        long baselineResponseTime = baselineStats.getMedianResponseTimeMs();
        byte[] origResponseBody = originalRequestResponse.getResponse();
        IResponseInfo originalResponseInfo = Utils.helpers.analyzeResponse(origResponseBody);
        int originalLength = baselineStats.getMedianBodyLength();
        if (originalLength == 0) {
            if (passiveErrorDisclosure) {
                finishPassiveOnly(logid, method, url, getResponseLength(baseRequestResponse), baseRequestResponse);
            } else {
                updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_empty_response"));
            }
            return;
        }
        if (originalResponseInfo.getStatusCode() == 404) {
            if (passiveErrorDisclosure) {
                finishPassiveOnly(logid, method, url, getResponseLength(baseRequestResponse), baseRequestResponse);
            } else {
                updatePassiveStatus(logid, I18nUtils.get("sql.status.skip_404"));
            }
            return;
        }

        if (logid < 0) {
            logid = addUrl(method, url, originalLength, baseRequestResponse);
        } else {
            updateUrl(logid, method, url, originalLength,
                    I18nUtils.get("sql.detection.in_progress"), baseRequestResponse);
        }
        baselineResponseBodies.put(logid, getResponseBody(originalRequestResponse));
        baselineResponseTimes.put(logid, baselineResponseTime);
        baselineStatsMap.put(logid, baselineStats);
        baselineRequestResponses.put(logid, originalRequestResponse);
        databaseFingerprints.put(logid, SqlInjectionDetector.identifyDatabase(
                getResponseBody(originalRequestResponse), originalResponseInfo.getHeaders()));

        // 被动流量中的原始响应可能已经泄露数据库异常。这里不能调用常规
        // reportSQLError：常规方法要求“payload 响应相对基线出现新错误”，
        // 而原始响应没有 payload，且错误可能在基线中稳定存在。
        if (!isSend) {
            reportPassiveSqlErrorDisclosure(logid, url, baseRequestResponse);
        }

        try {
            // 检测常规注入
            boolean jsonBodyProcessed = false;
            for (IParameter para : paraLists) {
                try {
            // 如果参数符合下面的类型，则进行检测
            if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_COOKIE || para.getType() == PARAM_JSON) {
                String paraName = para.getName();
                String paraValue = para.getValue();
                // 检测常规参数的注入
                if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
                    if (paraName == null || paraName.trim().isEmpty()) {
                        continue;
                    }
                    String parameterLocation = parameterLocation(para, paraName);
                    // 轻量盲注探测（与 Cookie 分支一致，受 isBooleanBlind 总开关控制）；
                    // 一旦该位置已经确认，跳过其它盲注形态和深度 payload。
                    if (isBooleanBlind && !isLocationConfirmed(logid, parameterLocation)) {
                        if (isIntegerParameter(paraValue)) {
                            checkNumberBasedBlind(logid, para, paraName, paraValue, url, originalLength, baselineResponseTime, originalRequestResponse);
                            if (!isLocationConfirmed(logid, parameterLocation)) {
                                checkQuoteBasedBlind(logid, para, paraName, paraValue, url, originalLength, baselineResponseTime, originalRequestResponse);
                            }
                        } else {
                            checkQuoteBasedBlind(logid, para, paraName, paraValue, url, originalLength, baselineResponseTime, originalRequestResponse);
                        }
                    }

                    // 正常的检测流程
                    // 使用payload进行检测
                    for (SqlBean sql : selectPayloads(logid, parameterLocation)) {
                        if (isLocationConfirmed(logid, parameterLocation)
                                || isWafProtected(logid, baseRequestResponse.getHttpService())) {
                            break;
                        }
                        String payload = Utils.ReplaceChar(sql.getValue());
                        // 如果sqlPayload是上面的 可以直接跳过
                        if (payload.equals("'") || payload.equals("''") || payload.equals("'''") || payload.isEmpty()) {
                            continue;
                        }
                        checkPayload(logid, para, paraName, paraValue, url, originalLength, baselineResponseTime, originalRequestResponse, baseRequestResponse, payload);
                    }

                }
                // 检测json类型的注入
                if (para.getType() == PARAM_JSON) {
                    // JSON 参数列表可能包含多个路径；整份 JSON 只处理一次，但不能跳过后续参数。
                    if (jsonBodyProcessed) {
                        continue;
                    }
                    jsonBodyProcessed = true;
                    // 获取JSON请求体
                    byte[] requestBytes = baseRequestResponse.getRequest();
                    int requestBodyOffset = analyzeRequest.getBodyOffset();
                    if (requestBytes == null || requestBodyOffset < 0 || requestBodyOffset > requestBytes.length) {
                        continue;
                    }
                    String request_data = Utils.helpers.bytesToString(Arrays.copyOfRange(requestBytes, requestBodyOffset, requestBytes.length));
                    if (request_data.trim().isEmpty()) {
                        continue;
                    }

                    // JSON 请求与当前请求共享三次采样后的稳定基线，避免重复发送原始请求。
                    long jsonBaselineTime = baselineResponseTime;
                    String originalResponse = getResponseBody(originalRequestResponse);
                    int jsonResponseLength = originalLength;
                    // 对每个JSON参数进行测试。相同 payload 的 JSON 变换只计算一次，避免每个路径重复解析。
                    Map<String, JsonProcessorUtil.ProcessResult> processResults = indexResultsByPath(
                            JsonProcessorUtil.processWithPath(request_data, "", isDeleteOrgin));
                    Map<String, JsonProcessorUtil.ProcessResult> singleQuoteResults = indexResultsByPath(
                            JsonProcessorUtil.processWithPath(request_data, "'", isDeleteOrgin));
                    Map<String, JsonProcessorUtil.ProcessResult> doubleQuoteResults = indexResultsByPath(
                            JsonProcessorUtil.processWithPath(request_data, "''", isDeleteOrgin));
                    Map<String, Map<String, JsonProcessorUtil.ProcessResult>> customPayloadResults = new LinkedHashMap<>();
                    for (SqlBean sql : selectPayloads(logid, "json")) {
                        String payload = Utils.ReplaceChar(sql.getValue());
                        if (payload == null || payload.isEmpty() || payload.equals("'") || payload.equals("''") || payload.equals("'''")) {
                            continue;
                        }
                        if (!customPayloadResults.containsKey(payload)) {
                            customPayloadResults.put(payload, indexResultsByPath(
                                    JsonProcessorUtil.processWithPath(request_data, payload, isDeleteOrgin)));
                        }
                    }
                    // 数字型盲注变异（-1/-0）：仅 isBooleanBlind 开启时构建，避免无谓解析与请求。
                    Map<String, JsonProcessorUtil.ProcessResult> numberMinusOneResults = Collections.emptyMap();
                    Map<String, JsonProcessorUtil.ProcessResult> numberMinusZeroResults = Collections.emptyMap();
                    if (isBooleanBlind) {
                        numberMinusOneResults = indexResultsByPath(
                                JsonProcessorUtil.processWithPath(request_data, "-1", isDeleteOrgin));
                        numberMinusZeroResults = indexResultsByPath(
                                JsonProcessorUtil.processWithPath(request_data, "-0", isDeleteOrgin));
                    }
                    for (JsonProcessorUtil.ProcessResult pathResult : processResults.values()) {
                        String jsonParam = pathResult.getParamPath();  // JSON参数路径
                        String jsonLocation = "json:" + jsonParam;
                        if (isLocationConfirmed(logid, jsonLocation)
                                || isWafProtected(logid, baseRequestResponse.getHttpService())) {
                            continue;
                        }

                        // 测试单引号响应
                        long singleQuoteStartTime = System.currentTimeMillis();
                        JsonProcessorUtil.ProcessResult singleQuoteResult = singleQuoteResults.get(jsonParam);
                        if (singleQuoteResult == null) {
                            continue;
                        }
                        byte[] singleQuoteBytes = Utils.helpers.buildHttpMessage(reqheaders, singleQuoteResult.getModifiedJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        if (!acquireBudget(logid, jsonLocation)) {
                            continue;
                        }
                        IHttpRequestResponse singleQuoteResponse = sendRequest(baseRequestResponse.getHttpService(), singleQuoteBytes);
                        long singleQuoteResponseTime = System.currentTimeMillis() - singleQuoteStartTime;
                        if (singleQuoteResponse == null || singleQuoteResponse.getResponse() == null) {
                            continue;
                        }
                        String singleQuoteBody = getResponseBody(singleQuoteResponse);

                        // 测试双引号响应
                        long doubleQuoteStartTime = System.currentTimeMillis();
                        JsonProcessorUtil.ProcessResult doubleQuoteResult = doubleQuoteResults.get(jsonParam);
                        if (doubleQuoteResult == null) {
                            continue;
                        }
                        byte[] doubleQuoteBytes = Utils.helpers.buildHttpMessage(reqheaders, doubleQuoteResult.getModifiedJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                        if (!acquireBudget(logid, jsonLocation)) {
                            continue;
                        }
                        IHttpRequestResponse doubleQuoteResponse = sendRequest(baseRequestResponse.getHttpService(), doubleQuoteBytes);
                        long doubleQuoteResponseTime = System.currentTimeMillis() - doubleQuoteStartTime;
                        if (doubleQuoteResponse == null || doubleQuoteResponse.getResponse() == null) {
                            continue;
                        }
                        String doubleQuoteBody = getResponseBody(doubleQuoteResponse);

                        int singleQuoteLength = getResponseLength(singleQuoteResponse);
                        int doubleQuoteLength = getResponseLength(doubleQuoteResponse);

                        // 检查是否存在盲注
                        BooleanEvidence jsonBooleanEvidence = evaluateBlindEvidence(logid,
                                originalRequestResponse, singleQuoteResponse, doubleQuoteResponse, jsonBaselineTime);
                        if (isBooleanBlind && jsonBooleanEvidence != null && jsonBooleanEvidence.isConfirmedPattern()
                                && validateBooleanCounterEvidence(logid, originalRequestResponse,
                                singleQuoteResponse, doubleQuoteResponse, jsonBaselineTime)) {
                            reportBlindInjection(logid, jsonLocation, jsonParam, url, singleQuoteResponse,
                                    doubleQuoteResponse, "JSON", jsonBooleanEvidence);
                        }

                        // 数字型盲注：仅对原始值为整数的叶子探测（变异保持 JSON 语法合法）。
                        // 引号型盲注已在上方复用单/双引号响应完成，不重复发请求。
                        if (isBooleanBlind && !isLocationConfirmed(logid, jsonLocation)
                                && pathResult.getOriginalValue() != null
                                && isIntegerParameter(pathResult.getOriginalValue())) {
                            IHttpRequestResponse minusOneResponse = acquireBudget(logid, jsonLocation)
                                    ? sendJsonProbe(baseRequestResponse.getHttpService(), reqheaders,
                                    numberMinusOneResults.get(jsonParam)) : null;
                            IHttpRequestResponse minusZeroResponse = minusOneResponse != null
                                    && acquireBudget(logid, jsonLocation)
                                    ? sendJsonProbe(baseRequestResponse.getHttpService(), reqheaders,
                                    numberMinusZeroResults.get(jsonParam)) : null;
                            evaluateBlindPairAndReport(logid, jsonLocation, jsonParam, url, originalRequestResponse,
                                    minusOneResponse, minusZeroResponse,
                                    I18nUtils.get("sql.blind.type.number"), jsonBaselineTime);
                        }

                        // 为单引号payload添加记录
                        String singleQuoteErrKey = "x";
                        // 检查报错
                        if (reportSQLError(logid, jsonLocation, originalResponse, singleQuoteBody, I18nUtils.format("sql.vuln.json_error", jsonParam), I18nUtils.format("sql.issue.json_error", jsonParam), url, singleQuoteResponse)) {
                            singleQuoteErrKey = I18nUtils.get("sql.vuln.error");
                        }

                        // 为双单引号payload添加记录
                        String doubleQuoteErrKey = "x";
                        // 检查报错
                        if (reportSQLError(logid, jsonLocation, originalResponse, doubleQuoteBody, I18nUtils.format("sql.vuln.json_error", jsonParam), I18nUtils.format("sql.issue.json_error", jsonParam), url, doubleQuoteResponse)) {
                            doubleQuoteErrKey = I18nUtils.get("sql.vuln.error");
                        }

                        // 记录单引号payload结果
                        addPayload(
                                logid,
                                jsonParam,
                                "'",
                                singleQuoteLength,
                                SqlInjectionDetector.formatSignedLengthChange(jsonResponseLength, singleQuoteLength),
                                singleQuoteErrKey,
                                String.valueOf(singleQuoteResponseTime),
                                String.valueOf(Utils.helpers.analyzeResponse(singleQuoteResponse.getResponse()).getStatusCode()),
                                singleQuoteResponse
                        );

                        // 记录双引号payload结果
                        addPayload(
                                logid,
                                jsonParam,
                                "''",
                                doubleQuoteLength,
                                SqlInjectionDetector.formatSignedLengthChange(jsonResponseLength, doubleQuoteLength),
                                doubleQuoteErrKey,
                                String.valueOf(doubleQuoteResponseTime),
                                String.valueOf(Utils.helpers.analyzeResponse(doubleQuoteResponse.getResponse()).getStatusCode()),
                                doubleQuoteResponse
                        );

                        for (Map.Entry<String, Map<String, JsonProcessorUtil.ProcessResult>> payloadEntry : customPayloadResults.entrySet()) {
                            String payload = payloadEntry.getKey();
                            if (isLocationConfirmed(logid, jsonLocation)
                                    || isWafProtected(logid, baseRequestResponse.getHttpService())) {
                                break;
                            }

                            // 测试当前payload
                            long startTime = System.currentTimeMillis();
                            JsonProcessorUtil.ProcessResult payloadResult = payloadEntry.getValue().get(jsonParam);
                            if (payloadResult == null) continue;

                            byte[] payloadBytes = Utils.helpers.buildHttpMessage(reqheaders, payloadResult.getModifiedJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                            if (!acquireBudget(logid, jsonLocation)) {
                                break;
                            }
                            IHttpRequestResponse payloadResponse = sendRequest(baseRequestResponse.getHttpService(), payloadBytes);
                            long responseTime = System.currentTimeMillis() - startTime;
                            if (payloadResponse == null || payloadResponse.getResponse() == null) {
                                continue;
                            }
                            String payloadBody = getResponseBody(payloadResponse);

                            String errkey = "x";

                            // 检查报错注入
                            if (reportSQLError(logid, jsonLocation, originalResponse, payloadBody, I18nUtils.format("sql.vuln.json_error", jsonParam), I18nUtils.format("sql.issue.json_error", jsonParam), url, payloadResponse)) {
                                errkey = I18nUtils.get("sql.vuln.error");
                            }

                            // 检查延时注入
                            if (!isLocationConfirmed(logid, jsonLocation)
                                    && reportTimeBlind(logid, jsonLocation, responseTime, I18nUtils.format("sql.vuln.json_time", jsonParam), I18nUtils.format("sql.issue.json_time", jsonParam), url, payloadResponse)) {
                                errkey = I18nUtils.get("sql.vuln.time");
                            }

                            // 记录payload测试结果
                            int payloadLength = getResponseLength(payloadResponse);
                            addPayload(
                                    logid,
                                    jsonParam,
                                    payload,
                                    payloadLength,
                                    SqlInjectionDetector.formatSignedLengthChange(jsonResponseLength, payloadLength),
                                    errkey,
                                    String.valueOf(responseTime),
                                    String.valueOf(Utils.helpers.analyzeResponse(payloadResponse.getResponse()).getStatusCode()),
                                    payloadResponse
                            );
                        }
                    }
                    continue;
                }
                // 检测cookie注入
                if (isCheckCookie && para.getType() == PARAM_COOKIE) {
                    if (paraName == null || paraName.trim().isEmpty()) {
                        continue;
                    }
                    // 布尔盲注探测（受 isBooleanBlind 总开关控制）：整数 Cookie 值先做数字型，再做引号型；
                    // 复用 URL/BODY 的两套盲注探测函数，预算与该 Cookie 位置的 payload 检测共享。
                    String cookieLocation = "cookie:" + paraName;
                    if (isBooleanBlind && !isLocationConfirmed(logid, cookieLocation)) {
                        if (isIntegerParameter(paraValue)) {
                            checkNumberBasedBlind(logid, para, paraName, paraValue, url, originalLength, baselineResponseTime, originalRequestResponse);
                        }
                        if (!isLocationConfirmed(logid, cookieLocation)) {
                            checkQuoteBasedBlind(logid, para, paraName, paraValue, url, originalLength, baselineResponseTime, originalRequestResponse);
                        }
                    }
                    for (SqlBean sql : selectPayloads(logid, "cookie:" + paraName)) {
                        if (isLocationConfirmed(logid, "cookie:" + paraName)
                                || isWafProtected(logid, baseRequestResponse.getHttpService())
                                || !acquireBudget(logid, "cookie:" + paraName)) {
                            break;
                        }
                        String errkey = "x";
                        String payload = "";
                        String sqlPayload = Utils.ReplaceChar(sql.getValue());
                        if (sqlPayload.isEmpty()) {
                            continue;
                        }
                        // 是否删除原始的参数值
                        if (isDeleteOrgin) {
                            payload = sqlPayload;
                        } else {
                            payload = paraValue + sqlPayload;
                        }
                        long startTime = System.currentTimeMillis();
                        IParameter iParameters = Utils.helpers.buildParameter(paraName, payload, para.getType());
                        byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters);
                        IHttpRequestResponse newRequestResponse = sendRequest(baseRequestResponse.getHttpService(), bytes);
                        long endTime = System.currentTimeMillis();
                        String responseTime = String.valueOf(endTime - startTime);
                        if (newRequestResponse == null || newRequestResponse.getResponse() == null) {
                            addPayload(logid, paraName, payload, 0, "N/A", errkey, responseTime, "", newRequestResponse);
                            continue;
                        }
                        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                        int statusCode = analyzeResponse.getStatusCode();
                        int sqlLength = getResponseLength(newRequestResponse);
                        String sqlResponseBody = getResponseBody(newRequestResponse);
                        if (reportSQLError(logid, "cookie:" + paraName, sqlResponseBody, I18nUtils.format("sql.vuln.cookie_error", paraName), I18nUtils.get("sql.issue.error"), url, newRequestResponse)) {
                            errkey = I18nUtils.get("sql.vuln.error");
                        }
                        long cookieResponseTime = Long.parseLong(responseTime);
                        if (!isLocationConfirmed(logid, "cookie:" + paraName)
                                && reportTimeBlind(logid, "cookie:" + paraName, cookieResponseTime, I18nUtils.format("sql.vuln.cookie_time", paraName), I18nUtils.get("sql.issue.time"), url, newRequestResponse)) {
                            errkey = I18nUtils.get("sql.vuln.time");
                        }
                        addPayload(logid, paraName, payload, sqlLength, SqlInjectionDetector.formatSignedLengthChange(originalLength, sqlLength), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }
                }
            }
                } catch (Exception parameterError) {
                    String parameterName = para == null ? "<unknown>" : String.valueOf(para.getName());
                    Utils.stderr.println(I18nUtils.get("sql.detection.error_prefix") + " [" + parameterName + "]: " + parameterError.getMessage());
                }
            }
        // 检测header注入
        if (isCheckHeader && !headerList.isEmpty()) {
            for (String configuredHeader : headerList.stream().map(SqlBean::getValue).filter(Objects::nonNull).collect(java.util.stream.Collectors.toList())) {
                String headerName = configuredHeader.trim();
                if (headerName.isEmpty() || "Cookie".equalsIgnoreCase(headerName)) {
                    continue;
                }
                String originalHeaderValue = null;
                String actualHeaderName = null;
                for (int i = 1; i < reqheaders.size(); i++) {
                    String requestHeader = reqheaders.get(i);
                    int separator = requestHeader.indexOf(':');
                    if (separator > 0 && requestHeader.substring(0, separator).trim().equalsIgnoreCase(headerName)) {
                        actualHeaderName = requestHeader.substring(0, separator).trim();
                        originalHeaderValue = requestHeader.substring(separator + 1).trim();
                        break;
                    }
                }
                // 原请求不存在该 Header：仅在开关允许时作为新增头探测，否则保持原有跳过行为。
                if (actualHeaderName == null && !isInsertMissingHeader) {
                    continue;
                }
                String effectiveHeaderName = actualHeaderName != null ? actualHeaderName : headerName;
                String headerLocation = "header:" + effectiveHeaderName;

                // 布尔盲注探测（受 isBooleanBlind 总开关控制），复用数字型/引号型证据链。
                checkHeaderBasedBlind(logid, reqheaders, body, headerLocation, effectiveHeaderName,
                        originalHeaderValue, url, baselineResponseTime, originalRequestResponse,
                        baseRequestResponse.getHttpService());

                for (SqlBean sql : selectPayloads(logid, headerLocation)) {
                    if (isLocationConfirmed(logid, headerLocation)
                            || isWafProtected(logid, baseRequestResponse.getHttpService())
                            || !acquireBudget(logid, headerLocation)) {
                        break;
                    }
                    String sqlPayload = Utils.ReplaceChar(sql.getValue());
                    if (sqlPayload == null || sqlPayload.isEmpty()) {
                        continue;
                    }
                    // Header 原本不存在时没有"原始值"，追加模式退化为直接放置 payload。
                    String payload = isDeleteOrgin || originalHeaderValue == null
                            ? sqlPayload : originalHeaderValue + sqlPayload;
                    List<String> mutatedHeaders = SqlInjectionDetector.replaceHeader(reqheaders, effectiveHeaderName, payload);
                    if (mutatedHeaders.isEmpty()) {
                        if (!isInsertMissingHeader) {
                            continue;
                        }
                        mutatedHeaders = SqlInjectionDetector.insertHeader(reqheaders, effectiveHeaderName, payload);
                        if (mutatedHeaders.isEmpty()) {
                            continue;
                        }
                    }
                    String errkey = "x";
                    long startTime = System.currentTimeMillis();
                    IHttpRequestResponse newRequestResponse = sendRequest(
                            baseRequestResponse.getHttpService(),
                            Utils.helpers.buildHttpMessage(mutatedHeaders, body));
                    long responseTimeMs = System.currentTimeMillis() - startTime;
                    if (newRequestResponse == null || newRequestResponse.getResponse() == null) {
                        addPayload(logid, effectiveHeaderName, payload, 0, "N/A", errkey, String.valueOf(responseTimeMs), "", null);
                        continue;
                    }
                    IResponseInfo responseInfo = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                    int sqlLength = getResponseLength(newRequestResponse);
                    if (reportSQLError(logid, headerLocation, getResponseBody(newRequestResponse), I18nUtils.format("sql.vuln.header_error", effectiveHeaderName), I18nUtils.get("sql.issue.error"), url, newRequestResponse)) {
                        errkey = I18nUtils.get("sql.vuln.error");
                    }
                    if (!isLocationConfirmed(logid, headerLocation)
                            && reportTimeBlind(logid, headerLocation, responseTimeMs, I18nUtils.format("sql.vuln.header_time", effectiveHeaderName), I18nUtils.get("sql.issue.time"), url, newRequestResponse)) {
                        errkey = I18nUtils.get("sql.vuln.time");
                    }
                    addPayload(logid, effectiveHeaderName, payload, sqlLength, SqlInjectionDetector.formatSignedLengthChange(originalLength, sqlLength), errkey, String.valueOf(responseTimeMs), String.valueOf(responseInfo.getStatusCode()), newRequestResponse);
                }
            }
        }
        } catch (Exception e) {
            // 检测过程中出现异常，记录错误信息
            addToVulStr(logid, I18nUtils.get("sql.detection.error") + " " + e.getMessage());
            Utils.stderr.println(I18nUtils.get("sql.detection.error_prefix") + " " + e.getMessage());
            if (Utils.stderr != null) {
                e.printStackTrace(Utils.stderr);
            }
        } finally {
            // 无论是否出现异常，都要更新最终状态
            // 如果没有异常且正常完成，添加检测完成状态
            if (!hasDetectionError(logid)) {
                addToVulStr(logid, I18nUtils.get("sql.detection.complete"));
            }
            // 更新数据
            updateUrl(logid, method, url, originalLength, getVulnerabilityMessage(logid), originalRequestResponse);
        }
    }
    /** 向扩展 stderr 输出带 [SQL] 前缀的扫描日志（stderr 可能未注入）。 */
    private static void logScanMessage(String message) {
        if (Utils.stderr != null) {
            Utils.stderr.println("[SQL] " + message);
        }
    }

    /** 被动错误泄露的去重键：URL + 清理后响应体的 SHA-256（摘要不可用时退回原文）。 */
    private static String buildPassiveErrorIssueKey(String url, String body) {
        String source = (url == null ? "" : url) + "|" + cleanResponse(body);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(source.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(hash.length * 2);
            for (byte value : hash) {
                result.append(String.format(Locale.ROOT, "%02x", value & 0xff));
            }
            return result.toString();
        } catch (Exception ignored) {
            return source;
        }
    }

    /** 基线采样失败的纯被动记录收尾：补完成标记并回写漏洞信息（无后续探测）。 */
    private static void finishPassiveOnly(int logid, String method, String url, int length,
                                          IHttpRequestResponse requestResponse) {
        if (logid < 0) return;
        addToVulStr(logid, I18nUtils.get("sql.detection.complete"));
        updateUrl(logid, method, url, length, getVulnerabilityMessage(logid), requestResponse);
    }

    /** 被动记录判为跳过时移除临时行。
     *  被动流量为让用户看到“确实进入了模块”会在前置检查前建临时行，
     *  跳过项不留在结果表中，只记日志。 */
    private static void updatePassiveStatus(int logid, String status) {
        if (logid < 0) {
            return;
        }
        removeUrlEntry(logid);
        logScanMessage("passive request skipped: " + status);
    }

    /** 删除该 logid 的全部记录与关联状态（结果行 + 各 LRU 缓存 + 预算/时间候选）。 */
    private static void removeUrlEntry(int logid) {
        synchronized (urldata) {
            urldata.removeIf(entry -> entry.id == logid);
        }
        urlPayloadMapping.remove(logid);
        vul.remove(logid);
        reportedIssues.remove(logid);
        confirmedLocations.remove(logid);
        baselineResponseBodies.remove(logid);
        baselineResponseTimes.remove(logid);
        baselineStatsMap.remove(logid);
        baselineRequestResponses.remove(logid);
        databaseFingerprints.remove(logid);
        parameterBudgets.removeKeys(key -> key.startsWith(logid + "|"));
        timeCandidates.removeKeys(key -> key.startsWith(logid + "|"));

        SqlUI ui = instance;
        if (ui != null) {
            refreshTableModel(ui.resultTable);
            refreshTableModel(ui.payloadtable);
        }
    }

    /** 为指定位置筛选探测 payload：按已识别数据库类型过滤兼容性、去重，
     *  正常 payload 截断到上限-2，延时 payload 改写为短/长两档且各限 2 条。 */
    private static List<SqlBean> selectPayloads(int logid, String location) {
        SqlInjectionDetector.DatabaseType db = databaseFingerprints.get(logid);
        LinkedHashMap<String, SqlBean> unique = new LinkedHashMap<>();
        List<SqlBean> normal = new ArrayList<>();
        List<SqlBean> delayed = new ArrayList<>();
        List<SqlBean> configured;
        synchronized (sqliPayload) {
            configured = new ArrayList<>(sqliPayload);
        }
        for (SqlBean bean : configured) {
            if (bean == null || bean.getValue() == null) continue;
            String value = Utils.ReplaceChar(bean.getValue());
            if (value == null || value.trim().isEmpty()
                    || "'".equals(value) || "''".equals(value) || "'''".equals(value)) continue;
            if (!isPayloadCompatible(value, db) || unique.containsKey(value)) continue;
            unique.put(value, bean);
            if (containsDelayPayload(value)) delayed.add(bean);
            else normal.add(bean);
        }
        List<SqlBean> result = new ArrayList<>();
        int normalLimit = Math.max(0, MAX_CUSTOM_PAYLOADS_PER_PARAMETER - 2);
        if (normal.size() > normalLimit) {
            // 不再静默截断：向扩展输出告警，并在该 URL 的结果行状态列附加提示。
            String hint = I18nUtils.format("sql.payload.truncated", normal.size(), normalLimit);
            Utils.stderr.println("[SQL] " + hint + " (urlId=" + logid + ", location=" + location + ")");
            addToVulStr(logid, hint);
        }
        for (SqlBean bean : normal) {
            if (result.size() >= normalLimit) break;
            result.add(bean);
        }
        // 延时检测最多保留两个候选，避免用户配置造成请求风暴。
        if (delayed.size() > 2) {
            Utils.stderr.println("[SQL] " + I18nUtils.format("sql.payload.delay_truncated", delayed.size())
                    + " (urlId=" + logid + ", location=" + location + ")");
        }
        for (SqlBean bean : delayed) {
            if (result.size() >= MAX_CUSTOM_PAYLOADS_PER_PARAMETER) break;
            String value = Utils.ReplaceChar(bean.getValue());
            String shortPayload = changeDelaySeconds(value, shortDelaySeconds());
            String longPayload = changeDelaySeconds(value, longDelaySeconds());
            if (shortPayload != null && !unique.containsKey(shortPayload)) {
                unique.put(shortPayload, bean);
                result.add(new SqlBean(bean.getType(), shortPayload));
            }
            if (result.size() < MAX_CUSTOM_PAYLOADS_PER_PARAMETER
                    && longPayload != null && !unique.containsKey(longPayload)) {
                unique.put(longPayload, bean);
                result.add(new SqlBean(bean.getType(), longPayload));
            }
        }
        return result;
    }

    /** 短延时秒数：阈值的一半（向上取整，最少 2s），用于建立相关性。 */
    private static int shortDelaySeconds() {
        return Math.max(2, (int) Math.ceil(timeBlindThreshold / 2000.0d));
    }

    /** 长延时秒数：阈值全量 +1（且比短延时多至少 2s），用于确认。 */
    private static int longDelaySeconds() {
        return Math.max(shortDelaySeconds() + 2, (int) Math.ceil(timeBlindThreshold / 1000.0d) + 1);
    }

    /** 是否包含时间延迟原语（sleep/pg_sleep/waitfor/dbms_pipe，委托 SqlInjectionDetector）。 */
    private static boolean containsDelayPayload(String value) {
        return SqlInjectionDetector.containsDelayPayload(value);
    }

    /** 判断 payload 与已识别数据库类型是否兼容（如 MSSQL 不跑 sleep()/pg_sleep）。 */
    private static boolean isPayloadCompatible(String payload, SqlInjectionDetector.DatabaseType db) {
        if (payload == null || db == null || db == SqlInjectionDetector.DatabaseType.UNKNOWN) return true;
        String lower = payload.toLowerCase(Locale.ROOT);
        if (db == SqlInjectionDetector.DatabaseType.MSSQL
                && (lower.contains("sleep(") || lower.contains("pg_sleep"))) return false;
        if (db == SqlInjectionDetector.DatabaseType.POSTGRESQL && lower.contains("waitfor delay")) return false;
        if (db == SqlInjectionDetector.DatabaseType.ORACLE
                && (lower.contains("waitfor delay") || lower.contains("pg_sleep"))) return false;
        if (db == SqlInjectionDetector.DatabaseType.MYSQL && lower.contains("waitfor delay")) return false;
        return true;
    }

    /** 改写 payload 中首个延迟原语的秒数（保留编码与语法，委托 SqlInjectionDetector）。 */
    private static String changeDelaySeconds(String payload, int seconds) {
        if (payload == null) return null;
        return SqlInjectionDetector.changeDelaySeconds(payload, seconds);
    }

    /** 参数预算键：logid|小写位置，同一参数跨探测共享 15 次预算。 */
    private static String budgetKey(int logid, String location) {
        return logid + "|" + (location == null ? "" : location.trim().toLowerCase(Locale.ROOT));
    }

    /** 参数位置的规范化描述（url/body/json/cookie:参数名），用于结果表与去重键。 */
    private static String parameterLocation(IParameter parameter, String name) {
        String type;
        if (parameter == null) {
            type = "unknown";
        } else if (parameter.getType() == PARAM_URL) {
            type = "url";
        } else if (parameter.getType() == PARAM_BODY) {
            type = "body";
        } else if (parameter.getType() == PARAM_JSON) {
            type = "json";
        } else if (parameter.getType() == PARAM_COOKIE) {
            type = "cookie";
        } else {
            type = "type" + parameter.getType();
        }
        return type + ":" + (name == null ? "" : name);
    }

    /** 目标主机是否已被标记为 WAF 慢速主机（查询共享节流器的 TTL 标记）。 */
    private static boolean isWafProtected(int logid, IHttpService service) {
        if (service == null) return false;
        // 慢速主机标记已收口到共享节流器（含 TTL 过期）
        return HostThrottle.isSlow(service.getProtocol() + "://" + service.getHost() + ":" + service.getPort());
    }

    /** 获取该参数位置的探测预算（每位置 15 次，跨探测共享，超限返回 false）。 */
    private static boolean acquireBudget(int logid, String location) {
        return parameterBudgets.computeIfAbsent(budgetKey(logid, location),
                key -> new ScanBudget(15)).tryAcquire();
    }

    /** 解析响应并做 WAF 判定；同主机连续 ≥2 次拦截标记慢速主机（共享节流器）。 */
    private static WafEvidence analyzeAndTrackWaf(int logid, IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) return WafEvidence.none();
        try {
            IResponseInfo info = Utils.helpers.analyzeResponse(response.getResponse());
            WafEvidence evidence = SqlInjectionDetector.detectWaf(
                    (int) info.getStatusCode(), info.getHeaders(), getResponseBody(response), false);
            if (evidence.isBlocked() && response.getHttpService() != null) {
                IHttpService service = response.getHttpService();
                String hostKey = service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
                // 同一主机连续 ≥2 次拦截即标记为慢速主机（共享节流器会放大后续间隔，并带 TTL 过期）
                if (wafBlockCounters.computeIfAbsent(hostKey, key -> new AtomicInteger())
                        .incrementAndGet() >= 2) HostThrottle.markSlow(hostKey);
            }
            return evidence;
        } catch (Exception ignored) {
            return WafEvidence.none();
        }
    }

    /** 构建响应快照（状态码/头/体/长度/耗时/WAF 与默认错误页标记），供盲注评估。 */
    private static ResponseSnapshot snapshot(int logid, IHttpRequestResponse response, long responseTimeMs) {
        if (response == null || response.getResponse() == null) return null;
        IResponseInfo info = Utils.helpers.analyzeResponse(response.getResponse());
        String responseBody = getResponseBody(response);
        WafEvidence waf = analyzeAndTrackWaf(logid, response);
        boolean defaultPage = SqlInjectionDetector.isDefaultErrorPage(
                (int) info.getStatusCode(), info.getHeaders(), responseBody);
        return new ResponseSnapshot((int) info.getStatusCode(), info.getHeaders(), responseBody,
                getResponseLength(response), responseTimeMs, waf.isBlocked(), defaultPage);
    }

    /** 时间盲注候选样本状态：按 sleep 秒数分短/长两档，各自保留响应最长的一次。 */
    private static final class TimeCandidateState {
        private TimeSample shortSample;
        private TimeSample longSample;

        private synchronized void put(TimeSample sample) {
            if (sample == null) return;
            if (sample.sleepSeconds <= shortDelaySeconds()) {
                if (shortSample == null || sample.responseTimeMs > shortSample.responseTimeMs) {
                    shortSample = sample;
                }
            } else {
                if (longSample == null || sample.responseTimeMs > longSample.responseTimeMs) {
                    longSample = sample;
                }
            }
        }

        private synchronized TimeSample getShortSample() { return shortSample; }
        private synchronized TimeSample getLongSample() { return longSample; }
    }

    /** 单次延时探测样本（sleep 秒数、响应耗时、首测与重放响应）。 */
    private static final class TimeSample {
        private final int sleepSeconds;
        private final long responseTimeMs;
        private final IHttpRequestResponse requestResponse;
        private final IHttpRequestResponse replayResponse;

        private TimeSample(int sleepSeconds, long responseTimeMs,
                           IHttpRequestResponse requestResponse,
                           IHttpRequestResponse replayResponse) {
            this.sleepSeconds = sleepSeconds;
            this.responseTimeMs = responseTimeMs;
            this.requestResponse = requestResponse;
            this.replayResponse = replayResponse;
        }

    }

    /** 基线采样结果：代表性响应（后续对比的原始请求）+ 基线统计。 */
    private static final class BaselineSample {
        private final IHttpRequestResponse representative;
        private final BaselineStats stats;

        private BaselineSample(IHttpRequestResponse representative, BaselineStats stats) {
            this.representative = representative;
            this.stats = stats;
        }
    }

    /**
     * 发送少量原始请求建立稳定基线。代表响应选择最接近中位响应时间的样本，
     * 统计信息保留全部有效样本，避免网络抖动污染后续判断。
     */
    private static BaselineSample sampleBaseline(IHttpService service, byte[] request, int sampleCount) {
        if (service == null || request == null || request.length == 0) {
            return null;
        }
        int count = Math.max(1, sampleCount);
        List<Long> times = new ArrayList<>();
        List<Integer> lengths = new ArrayList<>();
        List<String> hashes = new ArrayList<>();
        List<Integer> statuses = new ArrayList<>();
        List<IHttpRequestResponse> responses = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            long started = System.nanoTime();
            IHttpRequestResponse response;
            try {
                response = sendRequest(service, request);
            } catch (Exception e) {
                Utils.stderr.println("SQL baseline request failed: " + e.getMessage());
                continue;
            }
            long elapsed = Math.max(0L, (System.nanoTime() - started) / 1000000L);
            if (response == null || response.getResponse() == null) {
                continue;
            }
            try {
                IResponseInfo info = Utils.helpers.analyzeResponse(response.getResponse());
                String body = getResponseBody(response);
                times.add(elapsed);
                lengths.add(getResponseLength(response));
                hashes.add(sha256(body));
                statuses.add((int) info.getStatusCode());
                responses.add(response);
            } catch (Exception e) {
                Utils.stderr.println("SQL baseline response analysis failed: " + e.getMessage());
            }
        }
        if (responses.isEmpty()) {
            return null;
        }
        BaselineStats stats = BaselineStats.calculate(
                times, lengths, hashes, statuses, BASELINE_HIGH_VARIANCE_RATIO);
        long median = stats.getMedianResponseTimeMs();
        IHttpRequestResponse representative = responses.get(0);
        long closest = Math.abs(times.get(0) - median);
        for (int i = 1; i < responses.size(); i++) {
            long distance = Math.abs(times.get(i) - median);
            if (distance < closest) {
                closest = distance;
                representative = responses.get(i);
            }
        }
        return new BaselineSample(representative, stats);
    }

    /** 计算字符串的 SHA-256 十六进制摘要（异常时返回空串）。 */
    private static String sha256(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest((value == null ? "" : value)
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                result.append(String.format(Locale.ROOT, "%02x", b & 0xff));
            }
            return result.toString();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * 统一发送入口：按目标主机节流，WAF 保护（慢速）目标自动降低频率。
     * 节流实现与 Route 模块共用 {@link HostThrottle}（80ms 常规 / 300ms 慢速，带 TTL 过期）。
     */
    private static IHttpRequestResponse sendRequest(IHttpService service, byte[] request) {
        if (service == null || request == null) {
            return null;
        }
        String hostKey = service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
        HostThrottle.throttle(hostKey);
        return Utils.callbacks.makeHttpRequest(service, request);
    }

    /** 将 JSON 变异结果按参数路径索引（LinkedHashMap 保序），避免扫描中反复线性查找。 */
    private static Map<String, JsonProcessorUtil.ProcessResult> indexResultsByPath(List<JsonProcessorUtil.ProcessResult> results) {
        Map<String, JsonProcessorUtil.ProcessResult> indexed = new LinkedHashMap<>();
        if (results == null) {
            return indexed;
        }
        for (JsonProcessorUtil.ProcessResult result : results) {
            if (result != null && result.getParamPath() != null) {
                indexed.put(result.getParamPath(), result);
            }
        }
        return indexed;
    }

    /** 数字型盲注：-1/-0 两档探测，三响应交叉判定 + 独立重放复核后上报。 */
    private static void checkNumberBasedBlind(int logid, IParameter para, String paraName, String paraValue,
                                              String url, int originalLength, long baselineResponseTime,
                                              IHttpRequestResponse originalRequestResponse) {
        IHttpRequestResponse checkedPayload1 = checkPayload(logid, para, paraName, paraValue, url,
                originalLength, baselineResponseTime, originalRequestResponse, originalRequestResponse, "-1");
        IHttpRequestResponse checkedPayload0 = checkPayload(logid, para, paraName, paraValue, url,
                originalLength, baselineResponseTime, originalRequestResponse, originalRequestResponse, "-0");
        if (!isBooleanBlind) return;
        BooleanEvidence evidence = evaluateBlindEvidence(logid, originalRequestResponse,
                checkedPayload1, checkedPayload0, baselineResponseTime);
        if (evidence != null && evidence.isConfirmedPattern()
                && validateBooleanCounterEvidence(logid, originalRequestResponse, checkedPayload1, checkedPayload0,
                baselineResponseTime)) {
            reportBlindInjection(logid, parameterLocation(para, paraName), paraName, url, checkedPayload1,
                    checkedPayload0, I18nUtils.get("sql.blind.type.number"), evidence);
        }
    }

    /** 引号型盲注：'/'' 两档探测，三响应交叉判定 + 独立重放复核后上报。 */
    private static void checkQuoteBasedBlind(int logid, IParameter para, String paraName, String paraValue,
                                             String url, int originalLength, long baselineResponseTime,
                                             IHttpRequestResponse originalRequestResponse) {
        IHttpRequestResponse checkedPayloadQuote = checkPayload(logid, para, paraName, paraValue, url,
                originalLength, baselineResponseTime, originalRequestResponse, originalRequestResponse, "'");
        IHttpRequestResponse checkedPayloadQuotes = checkPayload(logid, para, paraName, paraValue, url,
                originalLength, baselineResponseTime, originalRequestResponse, originalRequestResponse, "''");
        if (!isBooleanBlind) return;
        BooleanEvidence evidence = evaluateBlindEvidence(logid, originalRequestResponse,
                checkedPayloadQuote, checkedPayloadQuotes, baselineResponseTime);
        if (evidence != null && evidence.isConfirmedPattern()
                && validateBooleanCounterEvidence(logid, originalRequestResponse, checkedPayloadQuote, checkedPayloadQuotes,
                baselineResponseTime)) {
            reportBlindInjection(logid, parameterLocation(para, paraName), paraName, url, checkedPayloadQuote,
                    checkedPayloadQuotes, I18nUtils.get("sql.blind.type.quote"), evidence);
        }
    }

    /** 构建三响应快照并委托 SqlInjectionDetector 做布尔差异评估（长度+相似度双通道）。 */
    private static BooleanEvidence evaluateBlindEvidence(int logid, IHttpRequestResponse original,
                                                         IHttpRequestResponse abnormal, IHttpRequestResponse normal,
                                                         long baselineTime) {
        ResponseSnapshot originalSnapshot = snapshot(logid, original, baselineTime);
        ResponseSnapshot abnormalSnapshot = snapshot(logid, abnormal, 0L);
        ResponseSnapshot normalSnapshot = snapshot(logid, normal, 0L);
        return SqlInjectionDetector.evaluateBooleanDifference(
                originalSnapshot, abnormalSnapshot, normalSnapshot,
                baselineStatsMap.get(logid), lengthThreshold, similarityThreshold / 100.0d);
    }

    /** 布尔盲注的反证复核：重放 abnormal/normal 请求，重放响应须与首测同类且差异仍确认。 */
    private static boolean validateBooleanCounterEvidence(int logid, IHttpRequestResponse original,
                                                           IHttpRequestResponse abnormal, IHttpRequestResponse normal,
                                                           long baselineTime) {
        if (abnormal == null || normal == null || abnormal.getRequest() == null || normal.getRequest() == null) {
            return false;
        }
        long started = System.currentTimeMillis();
        IHttpRequestResponse abnormalReplay = sendRequest(abnormal.getHttpService(), abnormal.getRequest());
        long abnormalElapsed = System.currentTimeMillis() - started;
        started = System.currentTimeMillis();
        IHttpRequestResponse normalReplay = sendRequest(normal.getHttpService(), normal.getRequest());
        long normalElapsed = System.currentTimeMillis() - started;
        BooleanEvidence replay = evaluateBlindEvidence(logid, original, abnormalReplay, normalReplay, baselineTime);
        // 重放一致性：abnormal/normal 的重放响应必须与首次探测同类，
        // 排除随机动态页面两次恰好"互异"造成的假布尔模式。
        boolean replayConsistent = SqlInjectionDetector.isBooleanReplayConsistent(
                getResponseBody(abnormal), getResponseBody(abnormalReplay),
                getResponseBody(normal), getResponseBody(normalReplay),
                similarityThreshold / 100.0d);
        return replay != null && replay.isConfirmedPattern() && replayConsistent;
    }

    /** 盲注三响应交叉判定：长度模式与相似度模式须同时成立（防随机内容误触发）。 */
    private static boolean checkBlindInjection(String originalResponse, String abnormalResponse, String normalResponse) {
        if (originalResponse == null || abnormalResponse == null || normalResponse == null
                || abnormalResponse.isEmpty() || normalResponse.isEmpty()) {
            return false;
        }
        // 长度差异 alone 容易被随机内容误触发；必须同时满足长度模式和相似度模式。
        boolean lengthBasedCheck = checkResponseLength(originalResponse, abnormalResponse, normalResponse);
        return lengthBasedCheck && checkResponseSimilarity(originalResponse, abnormalResponse, normalResponse);
    }

    /** 响应长度模式判定（清理动态内容后）：原≈正常、原/异常差异明显（使用配置阈值）。 */
    private static boolean checkResponseLength(String originalResponse, String abnormalResponse, String normalResponse) {

        // 获取处理后的响应长度
        int cleanOriginalLength = cleanResponse(originalResponse).length();
        int cleanAbnormalLength = cleanResponse(abnormalResponse).length();
        int cleanNormalLength = cleanResponse(normalResponse).length();

        // 计算长度差异
        int diffOriginalAbnormal = Math.abs(cleanOriginalLength - cleanAbnormalLength);
        int diffOriginalNormal = Math.abs(cleanOriginalLength - cleanNormalLength);
        int diffNormalAbnormal = Math.abs(cleanNormalLength - cleanAbnormalLength);

        // 判断长度模式（使用配置的阈值）
        return diffOriginalNormal <= lengthThreshold && // 原始响应和正常响应长度相近
                diffOriginalAbnormal > lengthThreshold && // 原始响应和异常响应长度差异明显
                diffNormalAbnormal > lengthThreshold;     // 正常响应和异常响应长度差异明显
    }

    /** 清理响应中的动态内容（token/时间戳/会话/HTML 标签等）并标准化，供长度与相似度比对。 */
    private static String cleanResponse(String response) {
        if (response == null || response.isEmpty()) {
            return "";
        }

        String cleanResponse = response;

        // 移除HTML标签（保留内容）
        cleanResponse = CLEAN_HTML_TAGS.matcher(cleanResponse).replaceAll(" ");

        // 移除动态内容
        cleanResponse = CLEAN_LONG_TOKEN.matcher(cleanResponse).replaceAll("TOKEN");
        cleanResponse = CLEAN_TOKEN_PARAM.matcher(cleanResponse).replaceAll("token=TOKEN");
        cleanResponse = CLEAN_TIMESTAMP.matcher(cleanResponse).replaceAll("TIMESTAMP");
        cleanResponse = CLEAN_DATETIME.matcher(cleanResponse).replaceAll("DATETIME");
        cleanResponse = CLEAN_ID.matcher(cleanResponse).replaceAll("id=\"ID\"");
        cleanResponse = CLEAN_CSRF.matcher(cleanResponse).replaceAll("csrf=TOKEN");
        cleanResponse = CLEAN_JSESSIONID.matcher(cleanResponse).replaceAll("JSESSIONID=TOKEN");
        cleanResponse = CLEAN_SESSION.matcher(cleanResponse).replaceAll("session=TOKEN");
        cleanResponse = CLEAN_TMP_PATH.matcher(cleanResponse).replaceAll("/tmp/FILE");
        cleanResponse = CLEAN_FILENAME.matcher(cleanResponse).replaceAll("filename=\"FILE\"");
        cleanResponse = CLEAN_HTML_COMMENT.matcher(cleanResponse).replaceAll("");
        cleanResponse = CLEAN_VERSION.matcher(cleanResponse).replaceAll("VERSION");
        cleanResponse = CLEAN_UUID.matcher(cleanResponse).replaceAll("UUID");

        // 标准化空白字符并转小写
        cleanResponse = CLEAN_WHITESPACE.matcher(cleanResponse).replaceAll(" ").trim().toLowerCase();

        return cleanResponse;
    }

    // 检查响应相似度模式
    private static boolean checkResponseSimilarity(String originalResponse, String abnormalResponse, String normalResponse) {
        // 使用统一的cleanResponse方法
        String cleanOriginal = cleanResponse(originalResponse);
        String cleanAbnormal = cleanResponse(abnormalResponse);
        String cleanNormal = cleanResponse(normalResponse);

        // 相似度比对（使用配置的阈值，百分比转小数）
        double simThreshold = similarityThreshold / 100.0;
        boolean originalVsNormalSimilar = !ResponseSimilarityMatcher.compareTwoResponses(
                cleanOriginal, cleanNormal, simThreshold);    // 相似
        boolean originalVsAbnormalDifferent = ResponseSimilarityMatcher.compareTwoResponses(
                cleanOriginal, cleanAbnormal, simThreshold);  // 不相似
        boolean normalVsAbnormalDifferent = ResponseSimilarityMatcher.compareTwoResponses(
                cleanNormal, cleanAbnormal, simThreshold);    // 不相似

        return originalVsNormalSimilar &&
                originalVsAbnormalDifferent &&
                normalVsAbnormalDifferent;
    }

    /** 只让同一请求、同一位置、同一类型的漏洞创建一次 Burp Issue。 */
    private static boolean markIssueReported(int logid, String issueType, String location) {
        String normalizedLocation = location == null ? "" : location.trim();
        String key = issueType + "|" + normalizedLocation;
        return reportedIssues.computeIfAbsent(logid, k -> ConcurrentHashMap.newKeySet()).add(key);
    }

    /** 标记该位置已确认注入（小写归一）。
     *  注：与 isLocationConfirmed 构成"查-改"两步，存在并发窗口；
     *  但上报由 reportedIssues 的 computeIfAbsent().add() 原子去重兜底，
     *  重复标记至多造成一次冗余探测，可接受。 */
    private static void markLocationConfirmed(int logid, String location) {
        if (location == null || location.trim().isEmpty()) return;
        confirmedLocations.computeIfAbsent(logid, k -> ConcurrentHashMap.newKeySet())
                .add(location.trim().toLowerCase(Locale.ROOT));
    }

    /** 该位置是否已确认注入（小写归一后查 LruCache）。 */
    private static boolean isLocationConfirmed(int logid, String location) {
        Set<String> locations = confirmedLocations.get(logid);
        return locations != null && location != null
                && locations.contains(location.trim().toLowerCase(Locale.ROOT));
    }

    /**
     * 报告被动响应中的 SQL/数据库错误信息泄露。
     *
     * <p>这不是 SQL 注入确认：请求没有经过 payload 变异，因此只记录为
     * “SQL错误信息泄露”，不标记参数位置为已注入，也不复用注入反证逻辑。</p>
     */
    private static boolean reportPassiveSqlErrorDisclosure(int logid, String url,
                                                            IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return false;
        }
        String responseBody;
        try {
            responseBody = getResponseBody(requestResponse);
        } catch (Exception e) {
            return false;
        }
        if (!SqlInjectionDetector.isLikelySqlErrorDisclosure(
                responseBody, SQL_ERROR_RULES, listErrorKey)) {
            return false;
        }

        SqlErrorEvidence evidence = SqlInjectionDetector.analyzeSqlError(
                "", responseBody, SQL_ERROR_RULES, listErrorKey);
        List<String> signatureList = new ArrayList<>();
        signatureList.addAll(evidence.getHighConfidenceSignatures());
        signatureList.addAll(evidence.getMediumConfidenceSignatures());
        String signatures = signatureList.toString();
        String confidence = evidence.hasHighConfidenceSignature() ? "Certain" : "Firm";
        String vulnDetail = I18nUtils.get("sql.vuln.passive_error")
                + " [" + confidence + ", score=" + evidence.getScore() + "]";
        addToVulStr(logid, vulnDetail);

        if (!markIssueReported(logid, "error-disclosure", "response")) {
            return true;
        }
        try {
            String detail = I18nUtils.get("sql.issue.passive_error")
                    + " (signatures=" + signatures + ")";
            IScanIssue issue = new CustomScanIssue(
                    requestResponse.getHttpService(), new URL(url),
                    new IHttpRequestResponse[]{requestResponse},
                    "SQL Error Information Disclosure", detail,
                    "Medium", confidence);
            if (Utils.callbacks != null) {
                Utils.callbacks.addScanIssue(issue);
            }
        } catch (Exception e) {
            if (Utils.stderr != null) {
                Utils.stderr.println("reportPassiveSqlErrorDisclosure: " + e.getMessage());
            }
        }
        return true;
    }

    /** 报错注入上报入口：基线取缓存值，委托重载版本。 */
    private static boolean reportSQLError(int logid, String location, String responseBody,
                                          String vulnDetail, String issueDetail, String url,
                                          IHttpRequestResponse requestResponse) {
        return reportSQLError(logid, location, baselineResponseBodies.get(logid), responseBody,
                vulnDetail, issueDetail, url, requestResponse);
    }

    /** 检测并报告 SQL 报错注入：候选响应须出现基线中不存在的新错误签名，
     *  WAF 拦截/低置信直接返回，通过后做置信度评分与反证验证。 */
    private static boolean reportSQLError(int logid, String location, String baselineBody, String responseBody,
                                          String vulnDetail, String issueDetail, String url,
                                          IHttpRequestResponse requestResponse) {
        if (requestResponse == null || responseBody == null || responseBody.trim().isEmpty()) {
            return false;
        }
        WafEvidence waf = analyzeAndTrackWaf(logid, requestResponse);
        if (waf.isBlocked()) {
            return false;
        }
        SqlErrorEvidence evidence = SqlInjectionDetector.analyzeSqlError(
                baselineBody, responseBody, SQL_ERROR_RULES, listErrorKey);
        if (evidence.isEmpty() || evidence.isLowConfidenceOnly()) {
            return false;
        }
        if (evidence.getDatabaseType() != SqlInjectionDetector.DatabaseType.UNKNOWN) {
            databaseFingerprints.put(logid, evidence.getDatabaseType());
        }
        boolean defaultPage = false;
        try {
            IResponseInfo info = Utils.helpers.analyzeResponse(requestResponse.getResponse());
            defaultPage = SqlInjectionDetector.isDefaultErrorPage(
                    (int) info.getStatusCode(), info.getHeaders(), responseBody);
        } catch (Exception ignored) {
            // Keep the conservative default.
        }
        BaselineStats stats = baselineStatsMap.get(logid);
        boolean counterValidated = validateErrorCounterEvidence(logid, evidence);
        SqlInjectionConfidenceScorer.Result score = SqlInjectionConfidenceScorer.score(
                evidence, null, null, waf, defaultPage,
                stats != null && stats.isHighVariance(), counterValidated);
        if (score.getLevel() == SqlInjectionConfidenceScorer.Level.NONE) {
            return false;
        }
        String confidence = score.getLevel() == SqlInjectionConfidenceScorer.Level.CERTAIN
                ? "Certain" : "Firm";
        String detail = issueDetail + " (SQL error evidence score=" + score.getScore() + ")";
        addToVulStr(logid, vulnDetail + " [" + confidence + ", score=" + score.getScore() + "]");
        if (score.getLevel() == SqlInjectionConfidenceScorer.Level.CERTAIN) {
            markLocationConfirmed(logid, location);
        }
        if (!markIssueReported(logid, "error", location)) {
            return true;
        }
        try {
            IScanIssue issues = new CustomScanIssue(
                    requestResponse.getHttpService(), new URL(url),
                    new IHttpRequestResponse[]{requestResponse}, "SqlInject Error",
                    detail, "High", confidence);
            Utils.callbacks.addScanIssue(issues);
        } catch (Exception e) {
            Utils.stderr.println("reportSQLError: " + e.getMessage());
        }
        return true;
    }

    /**
     * 后置安全控制：重放原始请求，若原始响应也出现同一新指纹，则候选差异不能归因于 payload。
     */
    private static boolean validateErrorCounterEvidence(int logid, SqlErrorEvidence candidate) {
        IHttpRequestResponse baseline = baselineRequestResponses.get(logid);
        if (baseline == null || baseline.getRequest() == null) {
            return false;
        }
        IHttpRequestResponse control = sendRequest(baseline.getHttpService(), baseline.getRequest());
        if (control == null || control.getResponse() == null) {
            return false;
        }
        SqlErrorEvidence controlEvidence = SqlInjectionDetector.analyzeSqlError(
                baselineResponseBodies.get(logid), getResponseBody(control), SQL_ERROR_RULES, listErrorKey);
        return controlEvidence.isEmpty() || !overlapErrorEvidence(candidate, controlEvidence);
    }

    /** 两份错误证据的高/中/低置信签名是否存在交集（用于反证验证的归因排除）。 */
    private static boolean overlapErrorEvidence(SqlErrorEvidence left, SqlErrorEvidence right) {
        Set<String> leftKeys = new HashSet<>();
        leftKeys.addAll(left.getHighConfidenceSignatures());
        leftKeys.addAll(left.getMediumConfidenceSignatures());
        leftKeys.addAll(left.getLowConfidenceSignatures());
        Set<String> rightKeys = new HashSet<>();
        rightKeys.addAll(right.getHighConfidenceSignatures());
        rightKeys.addAll(right.getMediumConfidenceSignatures());
        rightKeys.addAll(right.getLowConfidenceSignatures());
        leftKeys.retainAll(rightKeys);
        return !leftKeys.isEmpty();
    }

    /** 延时注入上报：单个高延迟只作候选，须重放确认 + 短/长两档样本齐备 + 单调性验证后上报。 */
    private static boolean reportTimeBlind(int logid, String location, long responseTime, String vulnDetail,
                                           String issueDetail, String url,
                                           IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return false;
        }
        BaselineStats baseline = baselineStatsMap.get(logid);
        if (baseline == null || baseline.isHighVariance() || !baseline.isStatusStable()) {
            return false;
        }
        WafEvidence waf = analyzeAndTrackWaf(logid, requestResponse);
        if (waf.isBlocked()) {
            return false;
        }
        ResponseSnapshot candidate = snapshot(logid, requestResponse, responseTime);
        if (candidate == null || candidate.isDefaultErrorPage() && candidate.getStatusCode() >= 500) {
            return false;
        }
        int sleepSeconds = extractDelaySeconds(requestResponse.getRequest());
        if (sleepSeconds <= 0) {
            // 普通报错/布尔 payload 的网络抖动不能进入时间盲注通道。
            return false;
        }
        long replayStart = System.currentTimeMillis();
        IHttpRequestResponse replay = sendRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        long replayTime = System.currentTimeMillis() - replayStart;
        if (replay == null || replay.getResponse() == null) {
            return false;
        }
        WafEvidence replayWaf = analyzeAndTrackWaf(logid, replay);
        if (replayWaf.isBlocked()) {
            return false;
        }
        boolean longDelay = sleepSeconds > shortDelaySeconds();
        long expectedSleepMs = sleepSeconds * 1000L;
        if (!SqlInjectionDetector.isLikelyExpectedTimeDelay(
                baseline.getMedianResponseTimeMs(), responseTime, expectedSleepMs, longDelay,
                timeBlindThreshold, MIN_TIME_DELAY_DELTA)
                || !SqlInjectionDetector.isLikelyExpectedTimeDelay(
                baseline.getMedianResponseTimeMs(), replayTime, expectedSleepMs, longDelay,
                timeBlindThreshold, MIN_TIME_DELAY_DELTA)) {
            return false;
        }

        String key = logid + "|time|" + (location == null ? "" : location.trim().toLowerCase(Locale.ROOT));
        TimeCandidateState state = timeCandidates.computeIfAbsent(key, k -> new TimeCandidateState());
        state.put(new TimeSample(sleepSeconds, Math.max(responseTime, replayTime), requestResponse, replay));
        TimeSample shortSample = state.getShortSample();
        TimeSample longSample = state.getLongSample();
        if (shortSample == null || longSample == null) {
            return false;
        }
        TimeDelayEvidence evidence = SqlInjectionDetector.evaluateTimeDelay(
                baseline, shortSample.responseTimeMs, longSample.responseTimeMs,
                shortSample.sleepSeconds * 1000L, longSample.sleepSeconds * 1000L,
                timeBlindThreshold, MIN_TIME_DELAY_DELTA);
        if (!evidence.isHighConfidence()) {
            return false;
        }
        SqlInjectionConfidenceScorer.Result score = SqlInjectionConfidenceScorer.score(
                null, null, evidence, WafEvidence.none(), false, baseline.isHighVariance(), true);
        if (score.getLevel() == SqlInjectionConfidenceScorer.Level.NONE) {
            return false;
        }
        String confidence = score.getLevel() == SqlInjectionConfidenceScorer.Level.CERTAIN ? "Certain" : "Firm";
        String detail = issueDetail + " (SQL time evidence score=" + score.getScore()
                + ", sleep=" + shortSample.sleepSeconds + "s/" + longSample.sleepSeconds + "s)";
        addToVulStr(logid, vulnDetail + " [" + confidence + ", score=" + score.getScore() + "]");
        if (score.getLevel() == SqlInjectionConfidenceScorer.Level.CERTAIN) {
            markLocationConfirmed(logid, location);
        }
        if (!markIssueReported(logid, "time", location)) {
            timeCandidates.remove(key);
            return true;
        }
        timeCandidates.remove(key);
        try {
            IHttpRequestResponse original = baselineRequestResponses.get(logid);
            IScanIssue issues = new CustomScanIssue(
                    requestResponse.getHttpService(), new URL(url),
                    original == null
                            ? new IHttpRequestResponse[]{shortSample.requestResponse, longSample.requestResponse,
                            shortSample.replayResponse, longSample.replayResponse}
                            : new IHttpRequestResponse[]{original, shortSample.requestResponse, longSample.requestResponse,
                            shortSample.replayResponse, longSample.replayResponse},
                    "SqlInject Time", detail, "High", confidence);
            Utils.callbacks.addScanIssue(issues);
        } catch (Exception e) {
            Utils.stderr.println("reportTimeBlind: " + e.getMessage());
        }
        return true;
    }

    /** 从请求字节中提取首个延迟原语的秒数（非延迟 payload 返回 0）。 */
    private static int extractDelaySeconds(byte[] request) {
        if (request == null || request.length == 0) return 0;
        return SqlInjectionDetector.extractDelaySeconds(Utils.helpers.bytesToString(request));
    }

    /** 盲注上报：长度+相似度交叉成立且置信度评分非 NONE 时才提交 Issue。 */
    private static boolean reportBlindInjection(int logid, String location, String paraName, String url,
                                                IHttpRequestResponse abnormalResponse,
                                                IHttpRequestResponse normalResponse,
                                                String type, BooleanEvidence evidence) {
        if (abnormalResponse == null || normalResponse == null || evidence == null || !evidence.isConfirmedPattern()) {
            return false;
        }
        SqlInjectionConfidenceScorer.Result score = SqlInjectionConfidenceScorer.score(
                null, evidence, null, WafEvidence.none(), false,
                baselineStatsMap.containsKey(logid) && baselineStatsMap.get(logid).isHighVariance(), true);
        if (score.getLevel() == SqlInjectionConfidenceScorer.Level.NONE) {
            return false;
        }
        String confidence = score.getLevel() == SqlInjectionConfidenceScorer.Level.CERTAIN ? "Certain" : "Firm";
        String detail = I18nUtils.format("sql.vuln.possible_blind", paraName, type)
                + " [" + confidence + ", score=" + score.getScore() + "]";
        addToVulStr(logid, detail);
        if (score.getLevel() == SqlInjectionConfidenceScorer.Level.CERTAIN) {
            markLocationConfirmed(logid, location);
        }
        if (!markIssueReported(logid, "blind", location + "|" + type)) {
            return true;
        }
        try {
            IHttpRequestResponse original = baselineRequestResponses.get(logid);
            IHttpRequestResponse[] messages = original == null
                    ? new IHttpRequestResponse[]{abnormalResponse, normalResponse}
                    : new IHttpRequestResponse[]{original, abnormalResponse, normalResponse};
            String issueDetail = I18nUtils.format("sql.issue.blind", type)
                    + " (evidence score=" + score.getScore() + ")";
            IScanIssue issues = new CustomScanIssue(abnormalResponse.getHttpService(), new URL(url),
                    messages, "SQL Injection Blind", issueDetail,
                    score.getLevel() == SqlInjectionConfidenceScorer.Level.CERTAIN ? "High" : "Medium",
                    confidence);
            Utils.callbacks.addScanIssue(issues);
        } catch (Exception e) {
            Utils.stderr.println("reportBlindInjection: " + e.getMessage());
        }
        return true;
    }

    /** 按 id 更新 URL 结果行（null/非正值保留旧字段），随后刷新两张表格。 */
    public static void updateUrl(int id, String method, String url, int length, String message, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            for (int row = 0; row < urldata.size(); row++) {
                if (urldata.get(row).id == id) {
                    SqlUIEntry oldEntry = urldata.get(row);
                    urldata.set(row, new SqlUIEntry(
                            id,
                            method == null ? oldEntry.method : method,
                            url == null ? oldEntry.url : url,
                            length <= 0 ? oldEntry.length : length,
                            message,
                            requestResponse == null ? oldEntry.requestResponse : requestResponse));
                    break;
                }
            }
        }
        SqlUI ui = instance;
        if (ui != null) {
            refreshTableModel(ui.resultTable);
            refreshTableModel(ui.payloadtable);
        }
    }

    /** 判断参数值是否为整数（含负号）。 */
    private static boolean isIntegerParameter(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        return value.matches("^-?\\d+$");
    }

    /** 获取响应体字符串（UTF-8，按 bodyOffset 截取头部之后）。 */
    public static String getResponseBody(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return "";
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();

        return new String(Arrays.copyOfRange(response, bodyOffset, response.length), java.nio.charset.StandardCharsets.UTF_8);
    }

    /** 获取响应体实际字节数（按 bodyOffset 计算，避免信任错误或缺失的 Content-Length）。 */
    private static int getResponseLength(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return 0;
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        return SqlInjectionDetector.actualBodyLength(response, responseInfo.getBodyOffset());
    }


    // 添加url数据到表格
    /** 新增 URL 结果行（自增 id），初始化该 id 的 payload 映射并刷新表格。 */
    public static int addUrl(String method, String url, int length, IHttpRequestResponse requestResponse) {
        int id = urlIdCounter.getAndIncrement();
        SqlUIEntry entry = new SqlUIEntry(id, method, url, length, I18nUtils.get("sql.detection.in_progress"), requestResponse);
        urlPayloadMapping.put(id, Collections.synchronizedList(new ArrayList<>()));

        synchronized (urldata) {
            urldata.add(entry);
            trimUrlDataOverflow();
        }
        SqlUI ui = instance;
        if (ui != null) {
            refreshTableModel(ui.resultTable);
        }
        return id;
    }

    /** 超限淘汰最旧 URL 结果（锁内调用），并同步清理被淘汰 id 的 payload 映射，防止映射泄漏。 */
    private static void trimUrlDataOverflow() {
        if (urldata.size() <= MAX_LOG_ENTRIES) {
            return;
        }
        int excess = urldata.size() - MAX_LOG_ENTRIES;
        for (int i = 0; i < excess; i++) {
            urlPayloadMapping.remove(((SqlUIEntry) urldata.get(i)).id);
        }
        urldata.subList(0, excess).clear();
    }

    /** 向该 id 的漏洞描述集合追加一条（去重，空值忽略）。 */
    public static void addToVulStr(int key, CharSequence value) {
        if (value == null || value.toString().trim().isEmpty()) {
            return;
        }
        vul.computeIfAbsent(key, k -> ConcurrentHashMap.newKeySet()).add(value.toString().trim());
    }

    /** 拼接该 id 的全部漏洞描述（逗号分隔，无则空串）。 */
    private static String getVulnerabilityMessage(int key) {
        Set<String> values = vul.get(key);
        if (values == null || values.isEmpty()) {
            return "";
        }
        return String.join(", ", values);
    }

    /** 该 id 的漏洞描述中是否含检测错误前缀。 */
    private static boolean hasDetectionError(int key) {
        Set<String> values = vul.get(key);
        if (values == null) {
            return false;
        }
        String errorPrefix = I18nUtils.get("sql.detection.error");
        for (String value : values) {
            if (value != null && value.contains(errorPrefix)) {
                return true;
            }
        }
        return false;
    }

    /** 追加 payload 探测结果到 urlPayloadMapping（供表格按 URL 过滤）与 payloaddata2（EDT 刷新，容量上限同 URL 列表）。 */
    public static void addPayload(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
        SqlPayloadEntry entry = new SqlPayloadEntry(selectId, key, value, length, change, errkey, time, status, requestResponse);
        urlPayloadMapping.computeIfAbsent(selectId,
                cacheKey -> Collections.synchronizedList(new ArrayList<>())).add(entry);

        SwingUtilities.invokeLater(() -> {
            synchronized (payloaddata2) {
                payloaddata2.add(entry);
                // 与 URL 列表同口径的容量上限，防长时间会话内存增长
                if (payloaddata2.size() > MAX_LOG_ENTRIES) {
                    payloaddata2.subList(0, payloaddata2.size() - MAX_LOG_ENTRIES).clear();
                }
            }
            SqlUI ui = instance;
            if (ui != null) {
                refreshTableModel(ui.payloadtable);
            }
        });
    }

    /** 发送单条 payload 探测并判定（错误/布尔/时间三通道），记录结果行并返回探测响应。 */
    public static IHttpRequestResponse checkPayload(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, long baselineResponseTime, IHttpRequestResponse originalRequestResponse, IHttpRequestResponse baseRequestResponse, String value) {

        String payload;
        String errkey = "x";

        // URL/POST表单参数在 isUrlEncode 开启时绕过 updateParameter 的自动编码：
        // 先按原始值组装 payload，统一只编码一次，再手工写入原始请求字节，
        // 避免出现 %27 → %2527 的双重编码导致 payload 失真。
        boolean manualRawEncode = isUrlEncode && para != null
                && (para.getType() == PARAM_URL || para.getType() == PARAM_BODY);

        // 构造payload
        if (manualRawEncode) {
            String rawPayload = isDeleteOrgin ? value : paraValue + value;
            payload = Utils.UrlEncode(rawPayload);
        } else {
            // 其他参数类型（cookie/json）updateParameter 不会再次编码，保持原有单次编码行为
            if (isUrlEncode) {
                value = Utils.UrlEncode(value);
            }
            payload = isDeleteOrgin ? value : paraValue + value;
        }

        // 发送请求并记录时间
        long startTime = System.currentTimeMillis();

        // 构造新的参数
        if (para == null || baseRequestResponse == null || baseRequestResponse.getRequest() == null
                || paraName == null || paraName.trim().isEmpty()) {
            return null;
        }
        byte[] paramByte;
        if (manualRawEncode) {
            paramByte = buildRequestWithSingleEncodedParam(
                    baseRequestResponse.getRequest(), para, paraName, payload);
            if (paramByte == null) {
                // 请求行/表单体不是标准 a=b&c=d 结构时回退旧行为，保证扫描不中断。
                IParameter iParameters = Utils.helpers.buildParameter(paraName, payload, para.getType());
                paramByte = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters);
            }
        } else {
            IParameter iParameters = Utils.helpers.buildParameter(paraName, payload, para.getType());
            paramByte = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters);
        }
        if (paramByte == null) {
            return null;
        }

        // 每个参数最多 15 个主检测请求；复核请求不占用此预算。
        if (!acquireBudget(logid, parameterLocation(para, paraName))) return null;
        // 发送请求
        IHttpRequestResponse newRequestResponses = sendRequest(baseRequestResponse.getHttpService(), paramByte);

        long endTime = System.currentTimeMillis();
        long responseTime = endTime - startTime;

        // 获取响应数据
        if (newRequestResponses == null || newRequestResponses.getResponse() == null) {
            return newRequestResponses;
        }
        byte[] responseBody = newRequestResponses.getResponse();
        if (responseBody != null) {
            // 分析响应
            IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(responseBody);
            int statusCode = analyzeResponse.getStatusCode();
            int length = getResponseLength(newRequestResponses);

            // 检查SQL错误
            String responseBodyStr = getResponseBody(newRequestResponses);
            String location = parameterLocation(para, paraName);
            if (reportSQLError(logid, location, responseBodyStr, I18nUtils.format("sql.vuln.param_error", paraName), I18nUtils.get("sql.issue.error"), url, newRequestResponses)) {
                errkey = I18nUtils.get("sql.vuln.error");
            }

            // 已确认的报错注入不再执行时间盲注阶段，避免无效请求和二次告警。
            if (!isLocationConfirmed(logid, location)
                    && reportTimeBlind(logid, location, responseTime, I18nUtils.format("sql.vuln.param_time", paraName), I18nUtils.get("sql.issue.time"), url, newRequestResponses)) {
                errkey = I18nUtils.get("sql.vuln.time");
            }

            // 记录payload结果
            addPayload(logid, paraName, payload, length, SqlInjectionDetector.formatSignedLengthChange(originalLength, length), errkey, String.valueOf(responseTime), String.valueOf(statusCode), newRequestResponses);
        }

        return newRequestResponses;
    }

    // ================ Fix2: 手工构造单次编码请求 ================

    /** 把恰好编码一次的参数值手工写入原始请求（URL query 或 form body），不做第二次编码。 */
    private static byte[] buildRequestWithSingleEncodedParam(byte[] originalRequest, IParameter para,
                                                             String paraName, String encodedValue) {
        try {
            if (para.getType() == PARAM_URL) {
                return replaceUrlParameterRaw(originalRequest, paraName, encodedValue);
            }
            if (para.getType() == PARAM_BODY) {
                return replaceBodyParameterRaw(originalRequest, paraName, encodedValue);
            }
        } catch (Exception e) {
            Utils.stderr.println("[SQL] manual single-encode rebuild failed: " + e.getMessage());
        }
        return null;
    }

    /** 只替换请求行中的 query 参数值，其余字节原样保留（避免字符集往返破坏报文）。 */
    private static byte[] replaceUrlParameterRaw(byte[] request, String paraName, String encodedValue) {
        int lineEnd = indexOfHeaderEnd(request);
        if (lineEnd < 0) {
            return null;
        }
        String requestLine = Utils.helpers.bytesToString(Arrays.copyOf(request, lineEnd));
        String newLine = SqlInjectionDetector.replaceUrlParamInRequestLine(requestLine, paraName, encodedValue);
        if (newLine == null) {
            return null;
        }
        byte[] newLineBytes = Utils.helpers.stringToBytes(newLine);
        byte[] result = new byte[newLineBytes.length + (request.length - lineEnd)];
        System.arraycopy(newLineBytes, 0, result, 0, newLineBytes.length);
        System.arraycopy(request, lineEnd, result, newLineBytes.length, request.length - lineEnd);
        return result;
    }

    /**
     * 只替换 form body 中的参数值，并同步修正 Content-Length。
     *
     * <p>两个边界：</p>
     * <ul>
     *   <li>chunked 编码（transfer-encoding）的 body 不是标准 a=b&c=d 结构，
     *       返回 null 交由调用方回退到 updateParameter，避免破坏 chunk 尺寸行；</li>
     *   <li>body 字符串往返统一用 ISO-8859-1（与 helpers.bytesToString 同一口径），
     *       保证原 body 中的非 ASCII 字节不被默认平台字符集破坏；
     *       encodedValue 本身是纯 ASCII 的百分号编码，同样安全。</li>
     * </ul>
     */
    private static byte[] replaceBodyParameterRaw(byte[] request, String paraName, String encodedValue) {
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(request);
        List<String> headers = new ArrayList<>(analyzeRequest.getHeaders());
        for (int i = 1; i < headers.size(); i++) {
            String header = headers.get(i);
            if (header != null && header.toLowerCase(Locale.ROOT).startsWith("transfer-encoding:")) {
                return null;
            }
        }
        int bodyOffset = analyzeRequest.getBodyOffset();
        if (bodyOffset < 0 || bodyOffset > request.length) {
            return null;
        }
        byte[] bodyBytes = Arrays.copyOfRange(request, bodyOffset, request.length);
        String newBody = SqlInjectionDetector.replaceFormParamValue(
                Utils.helpers.bytesToString(bodyBytes), paraName, encodedValue);
        if (newBody == null) {
            return null;
        }
        byte[] newBodyBytes = newBody.getBytes(java.nio.charset.StandardCharsets.ISO_8859_1);
        HttpMessageUtils.setContentLength(headers, newBodyBytes.length);
        return Utils.helpers.buildHttpMessage(headers, newBodyBytes);
    }

    /** 定位请求头与 body 的分界（首个 CRLF 的起始下标，无则 -1）。 */
    private static int indexOfHeaderEnd(byte[] request) {
        for (int i = 0; i + 1 < request.length; i++) {
            if (request[i] == '\r' && request[i + 1] == '\n') {
                return i;
            }
        }
        return -1;
    }

    // ================ Fix4: Cookie/Header/JSON 位置的布尔盲注探测 ================

    /**
     * 复用布尔盲注证据链评估一对探测响应（数字型 -1/-0 或引号型 '/''），
     * 命中且重放复核（含重放同类校验）通过后上报，受 isBooleanBlind 总开关控制。
     */
    private static void evaluateBlindPairAndReport(int logid, String location, String paramName, String url,
                                                   IHttpRequestResponse original, IHttpRequestResponse abnormal,
                                                   IHttpRequestResponse normal, String type, long baselineTime) {
        if (!isBooleanBlind || isLocationConfirmed(logid, location)
                || abnormal == null || normal == null
                || abnormal.getResponse() == null || normal.getResponse() == null
                || original == null) {
            return;
        }
        BooleanEvidence evidence = evaluateBlindEvidence(logid, original, abnormal, normal, baselineTime);
        if (evidence != null && evidence.isConfirmedPattern()
                && validateBooleanCounterEvidence(logid, original, abnormal, normal, baselineTime)) {
            reportBlindInjection(logid, location, paramName, url, abnormal, normal, type, evidence);
        }
    }

    /** 发送 JSON 叶子变异探测请求（变异结果已保证 JSON 语法合法）。 */
    private static IHttpRequestResponse sendJsonProbe(IHttpService service, List<String> reqheaders,
                                                      JsonProcessorUtil.ProcessResult result) {
        if (result == null || result.getModifiedJson() == null) {
            return null;
        }
        byte[] request = Utils.helpers.buildHttpMessage(reqheaders,
                result.getModifiedJson().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return sendRequest(service, request);
    }

    /** Header 位置的数字/引号盲注探测：payload 写入目标 Header（不存在且开关允许时新增）。 */
    private static void checkHeaderBasedBlind(int logid, List<String> reqheaders, byte[] body, String location,
                                              String headerName, String originalHeaderValue, String url,
                                              long baselineResponseTime, IHttpRequestResponse originalRequestResponse,
                                              IHttpService service) {
        if (!isBooleanBlind || isLocationConfirmed(logid, location) || isWafProtected(logid, service)) {
            return;
        }
        IHttpRequestResponse minusOne = sendHeaderProbe(logid, location, reqheaders, body,
                headerName, originalHeaderValue, service, "-1");
        IHttpRequestResponse minusZero = sendHeaderProbe(logid, location, reqheaders, body,
                headerName, originalHeaderValue, service, "-0");
        evaluateBlindPairAndReport(logid, location, headerName, url, originalRequestResponse,
                minusOne, minusZero, I18nUtils.get("sql.blind.type.number"), baselineResponseTime);
        if (isLocationConfirmed(logid, location)) {
            return;
        }
        IHttpRequestResponse quote = sendHeaderProbe(logid, location, reqheaders, body,
                headerName, originalHeaderValue, service, "'");
        IHttpRequestResponse doubleQuote = sendHeaderProbe(logid, location, reqheaders, body,
                headerName, originalHeaderValue, service, "''");
        evaluateBlindPairAndReport(logid, location, headerName, url, originalRequestResponse,
                quote, doubleQuote, I18nUtils.get("sql.blind.type.quote"), baselineResponseTime);
    }

    /** 构造并发送 Header 探测请求；预算与该 Header 位置的其它检测共享。 */
    private static IHttpRequestResponse sendHeaderProbe(int logid, String location, List<String> reqheaders,
                                                        byte[] body, String headerName,
                                                        String originalHeaderValue, IHttpService service,
                                                        String payload) {
        if (!acquireBudget(logid, location)) {
            return null;
        }
        String value = isDeleteOrgin || originalHeaderValue == null ? payload : originalHeaderValue + payload;
        List<String> mutatedHeaders = SqlInjectionDetector.replaceHeader(reqheaders, headerName, value);
        if (mutatedHeaders.isEmpty()) {
            if (!isInsertMissingHeader) {
                return null;
            }
            mutatedHeaders = SqlInjectionDetector.insertHeader(reqheaders, headerName, value);
            if (mutatedHeaders.isEmpty()) {
                return null;
            }
        }
        return sendRequest(service, Utils.helpers.buildHttpMessage(mutatedHeaders, body));
    }

    /** 初始化扫描 UI（EDT）：记录实例、建两张结果表与全部配置控件。 */
    @Override
    protected void setupScanUI() {
        instance = this;
        // SQL 被动流量由 BurpExtender 的唯一全局 IHttpListener 统一分发。
        // 不在此处重复注册，避免某些 Burp 版本/重载场景下出现漏回调或重复回调。

        resultTable = new URLTable(new SqlUrlModel());
        payloadtable = new PayloadTable(new SqlPayloadModel());

        passiveScanCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.passive"), isPassiveScan);
        passiveScanEnabled = isPassiveScan;
        deleteOriginalValueCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.delete_original"));
        checkCookieCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.check_cookie"));
        checkHeaderCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.check_header"));
        checkWhiteListCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.whitelist"));
        urlEncodeCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.url_encode"));
        booleanBlindCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.boolean_blind"));
        insertMissingHeaderCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.insert_header"));

        saveWhiteListButton = new JButton(I18nUtils.get("sql.button.save_whitelist"));
        saveHeaderListButton = new JButton(I18nUtils.get("sql.button.save_header"));
        whiteListTextArea = new JTextArea(5, 10);
        whiteListTextArea.setLineWrap(false);
        headerTextArea = new JTextArea(5, 10);
        headerTextArea.setLineWrap(true);
        headerTextArea.setWrapStyleWord(true);
        refreshTableButton = new JButton(I18nUtils.get("sql.button.refresh"));
        clearTableButton = new JButton(I18nUtils.get("sql.button.clear"));

        sqlPayloadTextArea = new JTextArea(5, 10);
        sqlPayloadTextArea.setLineWrap(false);
        sqlErrorKeyTextArea = new JTextArea(5, 10);
        sqlErrorKeyTextArea.setLineWrap(false);
        saveSqlPayloadButton = new JButton(I18nUtils.get("sql.button.save_payload"));
        saveSqlErrorKeyButton = new JButton(I18nUtils.get("sql.button.save_error_key"));
    }

    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        // 左半部分：上下分割
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 上方：URL表格 + Payload表格水平分割
        JSplitPane tablesSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        applyWeights(tablesSplit, WEIGHT_EDITORS);
        tablesSplit.setLeftComponent(wrapResultsTable(resultTable));
        tablesSplit.setRightComponent(new JScrollPane(payloadtable));
        leftSplitPane.setTopComponent(tablesSplit);

        // 下方：请求/响应编辑器（编辑器由基类 createEditors() 创建）
        leftSplitPane.setBottomComponent(buildEditorSplit());
        applyWeights(leftSplitPane, WEIGHT_TABLE_EDITOR);

        // 右半部分：配置面板
        JPanel rightPanel = buildRightPanel();

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setLeftComponent(leftSplitPane);
        mainSplit.setRightComponent(rightPanel);
        applyWeights(mainSplit, WEIGHT_MAIN);

        panel.add(mainSplit, BorderLayout.CENTER);
    }

    /** 构建右侧配置面板（扫描选项 + 白名单/Header 配置 + Payload/ErrorKey 输入）。 */
    private JPanel buildRightPanel() {
        JPanel rightSplitPane = new JPanel(new BorderLayout());
        rightSplitPane.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

        // 扫描选项
        JPanel scanOptionsPanel = createCompactOptionsPanel(
                I18nUtils.get("sql.border.scan_options"),
                passiveScanCheckBox, deleteOriginalValueCheckBox, checkCookieCheckBox,
                checkHeaderCheckBox, checkWhiteListCheckBox, urlEncodeCheckBox,
                booleanBlindCheckBox, insertMissingHeaderCheckBox);

        // 配置面板
        JPanel configPanel = new JPanel(new BorderLayout(3, 3));
        configPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("sql.border.configuration")));

        JPanel whitelistPanel = new JPanel(new BorderLayout(3, 3));
        whitelistPanel.add(new JLabel(I18nUtils.get("sql.label.whitelist")), BorderLayout.NORTH);
        whitelistPanel.add(new JScrollPane(whiteListTextArea), BorderLayout.CENTER);
        JPanel wlBtn = createCompactButtonPanel(saveWhiteListButton);
        whitelistPanel.add(wlBtn, BorderLayout.SOUTH);

        JPanel headerPanel = new JPanel(new BorderLayout(3, 3));
        headerPanel.add(new JLabel(I18nUtils.get("sql.label.header")), BorderLayout.NORTH);
        headerPanel.add(new JScrollPane(headerTextArea), BorderLayout.CENTER);
        JPanel hBtn = createCompactButtonPanel(saveHeaderListButton);
        headerPanel.add(hBtn, BorderLayout.SOUTH);

        JSplitPane configSplit = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.5);
        configSplit.setTopComponent(whitelistPanel);
        configSplit.setBottomComponent(headerPanel);
        configPanel.add(configSplit, BorderLayout.CENTER);

        // 操作按钮
        JPanel actionButtonsPanel = createCompactButtonPanel(refreshTableButton, clearTableButton);
        actionButtonsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("sql.border.actions")));

        // 扫描选项不能只占 16%，否则在右侧窄栏中会被 JSplitPane 压缩到
        // 复选框文字/控件不可见。保留紧凑间距，但给选项区稳定的可用高度。
        Dimension scanOptionsSize = scanOptionsPanel.getPreferredSize();
        scanOptionsPanel.setMinimumSize(new Dimension(0, Math.max(86, scanOptionsSize.height)));
        JSplitPane mainRightSplit = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.30);
        mainRightSplit.setTopComponent(scanOptionsPanel);
        JPanel cfgAct = new JPanel(new BorderLayout(3, 3));
        cfgAct.add(configPanel, BorderLayout.CENTER);
        cfgAct.add(actionButtonsPanel, BorderLayout.SOUTH);
        mainRightSplit.setBottomComponent(cfgAct);

        // 下方：Payload 和 Error Key。使用真正的纵向分割器，避免 BorderLayout
        // 按 preferred size 抢占空间后把上面的扫描选项自动挤没。
        JPanel rightDownPanel = new JPanel(new BorderLayout());
        JSplitPane downSplit = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.5);

        JPanel payloadPanel = new JPanel(new BorderLayout(3, 3));
        payloadPanel.add(new JLabel(I18nUtils.get("sql.label.payload")), BorderLayout.NORTH);
        payloadPanel.add(new JScrollPane(sqlPayloadTextArea), BorderLayout.CENTER);
        payloadPanel.add(saveSqlPayloadButton, BorderLayout.SOUTH);

        JPanel errKeyPanel = new JPanel(new BorderLayout(3, 3));
        errKeyPanel.add(new JLabel(I18nUtils.get("sql.label.error_key")), BorderLayout.NORTH);
        errKeyPanel.add(new JScrollPane(sqlErrorKeyTextArea), BorderLayout.CENTER);
        errKeyPanel.add(saveSqlErrorKeyButton, BorderLayout.SOUTH);

        downSplit.setTopComponent(payloadPanel);
        downSplit.setBottomComponent(errKeyPanel);
        rightDownPanel.add(downSplit, BorderLayout.CENTER);

        JSplitPane rightOuterSplit = applyCompactSplit(
                new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.62);
        rightOuterSplit.setTopComponent(mainRightSplit);
        rightOuterSplit.setBottomComponent(rightDownPanel);
        rightSplitPane.add(rightOuterSplit, BorderLayout.CENTER);

        return rightSplitPane;
    }

    /** 加载已保存配置（payload/header/domain/errorKey + 阈值）到文本框与运行时静态快照，并绑定控件事件。 */
    @Override
    protected void loadSavedData() {
        // UI 文本框和扫描线程使用同一份运行时配置快照。
        List<SqlBean> sqlList = getSqlListsByType("payload");
        sqliPayload = Collections.unmodifiableList(new ArrayList<>(sqlList));
        headerList = Collections.unmodifiableList(new ArrayList<>(getSqlListsByType("header")));
        List<String> loadedDomains = new ArrayList<>();
        for (SqlBean bean : getSqlListsByType("domain")) {
            if (bean != null && bean.getValue() != null && !bean.getValue().trim().isEmpty()) {
                loadedDomains.add(bean.getValue().trim());
            }
        }
        domainList = Collections.unmodifiableList(loadedDomains);
        List<String> loadedErrorKeys = new ArrayList<>();
        for (SqlBean bean : getSqlListsByType("sqlErrorKey")) {
            if (bean != null && bean.getValue() != null && !bean.getValue().trim().isEmpty()) {
                loadedErrorKeys.add(bean.getValue().trim());
            }
        }
        listErrorKey = Collections.unmodifiableList(loadedErrorKeys);
        // 加载SQL payload
        for (int i = 0; i < sqlList.size(); i++) {
            SqlBean bean = sqlList.get(i);
            sqlPayloadTextArea.setText(sqlPayloadTextArea.getText() + bean.getValue()
                    + (i < sqlList.size() - 1 ? "\n" : ""));
        }
        // 加载header
        List<SqlBean> header = getSqlListsByType("header");
        for (int i = 0; i < header.size(); i++) {
            SqlBean bean = header.get(i);
            headerTextArea.setText(headerTextArea.getText() + bean.getValue()
                    + (i < header.size() - 1 ? "\n" : ""));
        }
        // 加载域名白名单
        List<SqlBean> domains = getSqlListsByType("domain");
        for (int i = 0; i < domains.size(); i++) {
            SqlBean bean = domains.get(i);
            whiteListTextArea.setText(whiteListTextArea.getText() + bean.getValue()
                    + (i < domains.size() - 1 ? "\n" : ""));
        }
        // 加载error key
        List<SqlBean> sqlErrorKey = getSqlListsByType("sqlErrorKey");
        for (int i = 0; i < sqlErrorKey.size(); i++) {
            SqlBean bean = sqlErrorKey.get(i);
            sqlErrorKeyTextArea.setText(sqlErrorKeyTextArea.getText() + bean.getValue()
                    + (i < sqlErrorKey.size() - 1 ? "\n" : ""));
        }

        // 加载阈值配置
        try {
            String lt = getConfig("config", "lengthThreshold").getValue();
            if (lt != null && !lt.isEmpty()) {
                lengthThreshold = Integer.parseInt(lt);
            }
            String st = getConfig("config", "similarityThreshold").getValue();
            if (st != null && !st.isEmpty()) {
                similarityThreshold = Integer.parseInt(st);
            }
            String tt = getConfig("config", "timeBlindThreshold").getValue();
            if (tt != null && !tt.isEmpty()) {
                timeBlindThreshold = Integer.parseInt(tt);
            }
        } catch (Exception e) {
            Utils.stderr.println(I18nUtils.get("sql.detection.error_prefix") + e.getMessage());
        }

        // 复选框事件
        passiveScanCheckBox.addActionListener(e -> {
            isPassiveScan = passiveScanCheckBox.isSelected();
            passiveScanEnabled = isPassiveScan;
        });
        deleteOriginalValueCheckBox.addActionListener(e -> isDeleteOrgin = deleteOriginalValueCheckBox.isSelected());
        checkCookieCheckBox.addActionListener(e -> isCheckCookie = checkCookieCheckBox.isSelected());
        checkHeaderCheckBox.addActionListener(e -> isCheckHeader = checkHeaderCheckBox.isSelected());
        checkWhiteListCheckBox.addActionListener(e -> isWhiteDomain = checkWhiteListCheckBox.isSelected());
        urlEncodeCheckBox.addActionListener(e -> isUrlEncode = urlEncodeCheckBox.isSelected());
        booleanBlindCheckBox.addActionListener(e -> isBooleanBlind = booleanBlindCheckBox.isSelected());
        insertMissingHeaderCheckBox.addActionListener(e -> isInsertMissingHeader = insertMissingHeaderCheckBox.isSelected());

        // 按钮事件
        refreshTableButton.addActionListener(e -> {
            SqlUI ui = instance;
            if (ui != null) refreshTableModel(ui.resultTable);
            refreshTableModel(payloadtable);
        });
        clearTableButton.addActionListener(e -> {
            urlPayloadMapping.clear();
            synchronized (urldata) {
                urldata.clear();
            }
            synchronized (payloaddata) {
                payloaddata.clear();
            }
            synchronized (payloaddata2) {
                payloaddata2.clear();
            }
            vul.clear();
            passiveErrorIssueKeys.clear();
            UrlCacheUtil.resetCache("sqli");
            if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
            if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
            SqlUI ui = instance;
            if (ui != null) refreshTableModel(ui.resultTable);
            if (ui != null) refreshTableModel(ui.payloadtable);
        });

        saveSqlPayloadButton.addActionListener(e -> saveTextAreaContent(sqlPayloadTextArea, "payload", SqlBean::new));
        saveHeaderListButton.addActionListener(e -> saveTextAreaContent(headerTextArea, "header", SqlBean::new));
        saveWhiteListButton.addActionListener(e -> saveTextAreaContent(whiteListTextArea, "domain", SqlBean::new));

        saveSqlErrorKeyButton.addActionListener(e -> {
            deleteSqlByType("sqlErrorKey");
            saveTextAreaContent(sqlErrorKeyTextArea, "sqlErrorKey", SqlBean::new);
            List<String> updatedErrorKeys = new ArrayList<>();
            getSqlListsByType("sqlErrorKey").forEach(b -> {
                if (b != null && b.getValue() != null && !b.getValue().trim().isEmpty()) {
                    updatedErrorKeys.add(b.getValue().trim());
                }
            });
            listErrorKey = Collections.unmodifiableList(updatedErrorKeys);
            sqlErrorKeyTextArea.repaint();
            showSaveSuccess();
        });
    }

    /**
     * 由 BurpExtender 的全局 HTTP listener 调用，确保 SQL 模块不依赖子 UI listener 的注册时序。
     */
    public static void dispatchPassiveHttpMessage(int toolFlag, boolean messageIsRequest,
                                                   IHttpRequestResponse messageInfo) {
        SqlUI ui = instance;
        if (ui != null) {
            ui.processHttpMessage(toolFlag, messageIsRequest, messageInfo);
        }
    }

    /** 被动/手动扫描入口（ScanTaskExecutor 池线程），判空后委托 Check。 */
    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
        if (requestResponses == null || requestResponses.length == 0 || requestResponses[0] == null) {
            return;
        }
        Check(requestResponses, isManual);
    }

    @Override
    protected String getScanName() {
        return "SQL";
    }

    @Override
    public String getTabName() {
        return "SqlInject";
    }

    /** 保存文本框内容到 sql 表（先删后插，多行按行拆分），并刷新对应运行时快照。 */
    private void saveTextAreaContent(JTextArea textArea, String type, java.util.function.BiFunction<String, String, SqlBean> factory) {
        String text = textArea.getText();
        deleteSqlByType(type);
        if (text.contains("\n")) {
            for (String line : text.split("\n")) {
                if (line.trim().isEmpty()) continue;
                saveSql(factory.apply(type, line.trim()));
            }
        } else if (!text.trim().isEmpty()) {
            saveSql(factory.apply(type, text.trim()));
        }
        if ("payload".equals(type)) sqliPayload = Collections.unmodifiableList(new ArrayList<>(getSqlListsByType("payload")));
        if ("header".equals(type)) headerList = Collections.unmodifiableList(new ArrayList<>(getSqlListsByType("header")));
        if ("domain".equals(type)) {
            List<String> updatedDomains = new ArrayList<>();
            getSqlListsByType("domain").forEach(b -> {
                if (b != null && b.getValue() != null && !b.getValue().trim().isEmpty()) {
                    updatedDomains.add(b.getValue().trim());
                }
            });
            domainList = Collections.unmodifiableList(updatedDomains);
        }
        textArea.repaint();
        showSaveSuccess();
    }

    /** 保存成功后弹窗提示（EDT 调用）。 */
    private void showSaveSuccess() {
        JOptionPane.showMessageDialog(null, I18nUtils.get("config.message.save_success"),
                I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
    }

    /** URL 结果行实体（不可变；updateUrl 以新对象替换旧对象）。 */
    public static class SqlUIEntry {
        final int id;
        final String method;
        final String url;
        final int length;
        final String status;
        final IHttpRequestResponse requestResponse;

        SqlUIEntry(int id, String method, String url, int length, String status, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.length = length;
            this.status = status;
            this.requestResponse = requestResponse;
        }
    }

    /** payload 探测结果行实体（不可变）。 */
    public static class SqlPayloadEntry {
        final int selectId;
        final String key;
        final String value;
        final int length;
        final String change;
        final String errkey;
        final String time;
        final String status;
        final IHttpRequestResponse requestResponse;

        SqlPayloadEntry(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
            this.selectId = selectId;
            this.key = key;
            this.value = value;
            this.length = length;
            this.change = change;
            this.errkey = errkey;
            this.time = time;
            this.status = status;
            this.requestResponse = requestResponse;
        }
    }

    /** URL 结果表模型：直接读 urldata（读取全程持锁，扫描线程写入同锁互斥）。 */
    static class SqlUrlModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            synchronized (urldata) {
                return urldata.size();
            }
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            synchronized (urldata) {
                if (rowIndex < 0 || rowIndex >= urldata.size()) {
                    return null;
                }
                switch (columnIndex) {
                    case 0:
                        return urldata.get(rowIndex).id;
                    case 1:
                        return urldata.get(rowIndex).method;
                    case 2:
                        return urldata.get(rowIndex).url;
                    case 3:
                        return urldata.get(rowIndex).length;
                    case 4:
                        return urldata.get(rowIndex).status;
                    default:
                        return null;
                }
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return I18nUtils.get("sql.table.id");
                case 1:
                    return I18nUtils.get("sql.table.method");
                case 2:
                    return I18nUtils.get("sql.table.url");
                case 3:
                    return I18nUtils.get("sql.table.length");
                case 4:
                    return I18nUtils.get("sql.table.status");
                default:
                    return null;
            }
        }

        @Override
        public Class<?> getColumnClass(int column) {
            if (column == 0) {
                return Integer.class;
            }
            return super.getColumnClass(column);
        }
    }

    /** payload 结果表模型：展示 payloaddata（由 URLTable 选中行按 selectId 过滤填充，读取持锁）。 */
    static class SqlPayloadModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            synchronized (payloaddata) {
                return payloaddata.size();
            }
        }

        @Override
        public int getColumnCount() {
            return 7;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            synchronized (payloaddata) {
                if (rowIndex < 0 || rowIndex >= payloaddata.size()) {
                    return null;
                }
                switch (columnIndex) {
                    case 0:
                        return payloaddata.get(rowIndex).key;
                    case 1:
                        return payloaddata.get(rowIndex).value;
                    case 2:
                        return payloaddata.get(rowIndex).length;
                    case 3:
                        return payloaddata.get(rowIndex).change;
                    case 4:
                        return payloaddata.get(rowIndex).errkey;
                    case 5:
                        return payloaddata.get(rowIndex).time;
                    case 6:
                        return payloaddata.get(rowIndex).status;
                    default:
                        return null;
                }
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return I18nUtils.get("sql.table.parameter");
                case 1:
                    return I18nUtils.get("sql.table.value");
                case 2:
                    return I18nUtils.get("sql.table.response_length");
                case 3:
                    return I18nUtils.get("sql.table.change");
                case 4:
                    return I18nUtils.get("sql.table.error");
                case 5:
                    return I18nUtils.get("sql.table.time");
                case 6:
                    return I18nUtils.get("sql.table.status_code");
                default:
                    return null;
            }
        }
    }

    /** URL 结果表格：选中行时按 id 过滤 payload 并同步刷新编辑器。 */
    private class URLTable extends JTable {
        public URLTable(AbstractTableModel model) {
            super(model);
            setAutoCreateRowSorter(true);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(1).setMaxWidth(100);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            // 如果表格已排序，需要将视图索引转换为模型索引
            if (rowIndex < 0 || rowIndex >= getRowCount()) {
                return;
            }
            int modelRow = getRowSorter() == null ? rowIndex : convertRowIndexToModel(rowIndex);
            SqlUIEntry logEntry;
            synchronized (urldata) {
                if (modelRow < 0 || modelRow >= urldata.size()) {
                    return;
                }
                logEntry = urldata.get(modelRow);
            }
            if (logEntry.requestResponse == null) {
                return;
            }
            int select_id = logEntry.id;
            synchronized (payloaddata) {
                payloaddata.clear();
                synchronized (payloaddata2) {
                    for (SqlPayloadEntry payloadEntry : payloaddata2) {
                        if (payloadEntry.selectId == select_id) {
                            payloaddata.add(payloadEntry);
                        }
                    }
                }
            }
            refreshTableModel(payloadtable);
            if (requestEditor != null) {
                requestEditor.setMessage(logEntry.requestResponse.getRequest(), true);
            }
            if (responseEditor != null) {
                if (logEntry.requestResponse.getResponse() == null) {
                    responseEditor.setMessage(new byte[0], false);
                } else {
                    responseEditor.setMessage(logEntry.requestResponse.getResponse(), false);
                }
            }
            currentlyDisplayedItem = logEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

    /** payload 结果表格：选中行时同步刷新请求/响应编辑器。 */
    private class PayloadTable extends JTable {
        public PayloadTable(AbstractTableModel model) {
            super(model);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(6).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {

            if (rowIndex < 0 || rowIndex >= getRowCount()) {
                return;
            }
            int modelRow = getRowSorter() == null ? rowIndex : convertRowIndexToModel(rowIndex);
            SqlPayloadEntry dataEntry;
            synchronized (payloaddata) {
                if (modelRow < 0 || modelRow >= payloaddata.size()) {
                    return;
                }
                dataEntry = payloaddata.get(modelRow);
            }
            if (dataEntry.requestResponse == null) {
                return;
            }
            if (requestEditor != null) {
                requestEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            }
            if (responseEditor != null) {
                if (dataEntry.requestResponse.getResponse() == null) {
                    responseEditor.setMessage(new byte[0], false);
                } else {
                    responseEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
                }
            }
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

}

