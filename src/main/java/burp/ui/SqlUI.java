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
import java.util.concurrent.atomic.AtomicLong;
import java.security.MessageDigest;
import java.util.regex.Pattern;

import static burp.IParameter.*;
import static burp.dao.ConfigDao.getConfig;
import static burp.dao.SqlDao.*;

/**
 * @Author Xm17
 * @Date 2024-06-21 15:39
 */
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
    private static volatile List<String> listErrorKey = new ArrayList<>(); // // 存放错误key
    private static volatile List<SqlBean> sqliPayload = new ArrayList<>(); // 存放sql关键字
    private static volatile List<String> domainList = new ArrayList<>(); // 存放域名白名单
    private static volatile List<SqlBean> headerList = new ArrayList<>(); // 存放header白名单
    private static final ConcurrentHashMap<Integer, Set<String>> vul = new ConcurrentHashMap<>();// 防止插入重复
    private static final ConcurrentHashMap<Integer, Set<String>> reportedIssues = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, Set<String>> confirmedLocations = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, String> baselineResponseBodies = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, Long> baselineResponseTimes = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, BaselineStats> baselineStatsMap = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, IHttpRequestResponse> baselineRequestResponses = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<Integer, SqlInjectionDetector.DatabaseType> databaseFingerprints = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, AtomicInteger> wafBlockCounters = new ConcurrentHashMap<>();
    private static final Set<String> wafProtectedHosts = ConcurrentHashMap.newKeySet();
    /** 被动 SQL 错误泄露按 URL + 指纹去重，不受注入 URL 缓存影响。 */
    private static final Set<String> passiveErrorIssueKeys = ConcurrentHashMap.newKeySet();
    private static final ConcurrentHashMap<String, AtomicLong> lastRequestTimes = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, ScanBudget> parameterBudgets = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, TimeCandidateState> timeCandidates = new ConcurrentHashMap<>();
    private JCheckBox booleanBlindCheckBox; // 布尔盲注选择框
    private static boolean isBooleanBlind;  // 是否进行布尔盲注
    private static int timeBlindThreshold = 6000; // 延时注入阈值(ms)
    private static int lengthThreshold = 10; // 响应长度差异阈值
    private static int similarityThreshold = 85; // 相似度阈值(百分比)
    private static final long MIN_TIME_DELAY_DELTA = 2500L; // 相对基线的最小延时差(ms)
    private static final int BASELINE_SAMPLE_COUNT = 3;
    private static final double BASELINE_HIGH_VARIANCE_RATIO = 0.5d;
    private static final int MAX_CUSTOM_PAYLOADS_PER_PARAMETER = 6;
    private static final long NORMAL_REQUEST_INTERVAL_MS = 80L;
    private static final long WAF_REQUEST_INTERVAL_MS = 300L;
    private static final List<SqlErrorRule> SQL_ERROR_RULES = SqlInjectionDetector.immutableDefaultErrorRules();
    private static volatile SqlUI instance;
    private static final ConcurrentHashMap<Integer, List<SqlPayloadEntry>> urlPayloadMapping = new ConcurrentHashMap<>();
    private static final AtomicInteger urlIdCounter = new AtomicInteger(0);

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
        wafProtectedHosts.clear();
        lastRequestTimes.clear();
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

    // sql检测核心方法
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
            updatePassiveStatus(logid, "跳过：不支持的HTTP方法");
            return;
        }
        if (Utils.isUrlBlackListSuffix(url)) {
            updatePassiveStatus(logid, "跳过：URL后缀黑名单");
            return;
        }

        // 检查是否存在实际可检测的输入点，Cookie/Header 开关只作用于对应位置。
        List<Integer> parameterTypes = new ArrayList<>();
        for (IParameter para : paraLists) {
            parameterTypes.add((int) para.getType());
        }

        if (!isSend && isWhiteDomain && !Utils.isMatchDomainName(host, domainList)) {
            updatePassiveStatus(logid, "跳过：域名不在白名单");
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
                    updatePassiveStatus(logid, "跳过：SQL错误泄露已报告");
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
                updatePassiveStatus(logid, "跳过：URL已去重");
                return;
            }
        }

        // 没有可检测参数时才按普通跳过项处理；被动错误泄露已在上面直接完成。
        if (!SqlInjectionDetector.hasDetectableInput(parameterTypes, isCheckCookie, isCheckHeader, !headerList.isEmpty())) {
            updatePassiveStatus(logid, "跳过：没有可检测参数");
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
                updatePassiveStatus(logid, "跳过：基线请求失败");
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
                    updatePassiveStatus(logid, "跳过：基线疑似WAF拦截");
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
                updatePassiveStatus(logid, "跳过：空响应");
            }
            return;
        }
        if (originalResponseInfo.getStatusCode() == 404) {
            if (passiveErrorDisclosure) {
                finishPassiveOnly(logid, method, url, getResponseLength(baseRequestResponse), baseRequestResponse);
            } else {
                updatePassiveStatus(logid, "跳过：404响应");
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
                    // 先进行轻量盲注探测；一旦该位置已经确认，跳过其它盲注形态和深度 payload。
                    if (!isLocationConfirmed(logid, parameterLocation)) {
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
                if (actualHeaderName == null) {
                    continue;
                }
                for (SqlBean sql : selectPayloads(logid, "header:" + actualHeaderName)) {
                    if (isLocationConfirmed(logid, "header:" + actualHeaderName)
                            || isWafProtected(logid, baseRequestResponse.getHttpService())
                            || !acquireBudget(logid, "header:" + actualHeaderName)) {
                        break;
                    }
                    String sqlPayload = Utils.ReplaceChar(sql.getValue());
                    if (sqlPayload == null || sqlPayload.isEmpty()) {
                        continue;
                    }
                    String payload = isDeleteOrgin ? sqlPayload : originalHeaderValue + sqlPayload;
                    List<String> mutatedHeaders = SqlInjectionDetector.replaceHeader(reqheaders, actualHeaderName, payload);
                    if (mutatedHeaders.isEmpty()) {
                        continue;
                    }
                    String errkey = "x";
                    long startTime = System.currentTimeMillis();
                    IHttpRequestResponse newRequestResponse = sendRequest(
                            baseRequestResponse.getHttpService(),
                            Utils.helpers.buildHttpMessage(mutatedHeaders, body));
                    long responseTimeMs = System.currentTimeMillis() - startTime;
                    if (newRequestResponse == null || newRequestResponse.getResponse() == null) {
                        addPayload(logid, actualHeaderName, payload, 0, "N/A", errkey, String.valueOf(responseTimeMs), "", null);
                        continue;
                    }
                    IResponseInfo responseInfo = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                    int sqlLength = getResponseLength(newRequestResponse);
                    if (reportSQLError(logid, "header:" + actualHeaderName, getResponseBody(newRequestResponse), I18nUtils.format("sql.vuln.header_error", actualHeaderName), I18nUtils.get("sql.issue.error"), url, newRequestResponse)) {
                        errkey = I18nUtils.get("sql.vuln.error");
                    }
                    if (!isLocationConfirmed(logid, "header:" + actualHeaderName)
                            && reportTimeBlind(logid, "header:" + actualHeaderName, responseTimeMs, I18nUtils.format("sql.vuln.header_time", actualHeaderName), I18nUtils.get("sql.issue.time"), url, newRequestResponse)) {
                        errkey = I18nUtils.get("sql.vuln.time");
                    }
                    addPayload(logid, actualHeaderName, payload, sqlLength, SqlInjectionDetector.formatSignedLengthChange(originalLength, sqlLength), errkey, String.valueOf(responseTimeMs), String.valueOf(responseInfo.getStatusCode()), newRequestResponse);
                }
            }
        }
        } catch (Exception e) {
            // 检测过程中出现异常，记录错误信息
            addToVulStr(logid, I18nUtils.get("sql.detection.error") + " " + e.getMessage());
            Utils.stderr.println(I18nUtils.get("sql.detection.error_prefix") + " " + e.getMessage());
            e.printStackTrace();
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
    private static void logScanMessage(String message) {
        if (Utils.stderr != null) {
            Utils.stderr.println("[SQL] " + message);
        }
    }

    /**
     * 删除被动扫描的临时记录。
     *
     * <p>被动流量为了让用户能看到“确实进入了模块”，会在前置检查前创建临时行；
     * 如果后续被判定为跳过，则不把“跳过”项留在结果表中。</p>
     */
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

    private static void finishPassiveOnly(int logid, String method, String url, int length,
                                          IHttpRequestResponse requestResponse) {
        if (logid < 0) return;
        addToVulStr(logid, I18nUtils.get("sql.detection.complete"));
        updateUrl(logid, method, url, length, getVulnerabilityMessage(logid), requestResponse);
    }

    private static void updatePassiveStatus(int logid, String status) {
        if (logid < 0) {
            return;
        }
        removeUrlEntry(logid);
        logScanMessage("passive request skipped: " + status);
    }

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
        parameterBudgets.keySet().removeIf(key -> key.startsWith(logid + "|"));
        timeCandidates.keySet().removeIf(key -> key.startsWith(logid + "|"));

        SqlUI ui = instance;
        if (ui != null) {
            refreshTableModel(ui.resultTable);
            refreshTableModel(ui.payloadtable);
        }
    }

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
        for (SqlBean bean : normal) {
            if (result.size() >= normalLimit) break;
            result.add(bean);
        }
        // 延时检测最多保留两个候选，避免用户配置造成请求风暴。
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

    private static int shortDelaySeconds() {
        return Math.max(2, (int) Math.ceil(timeBlindThreshold / 2000.0d));
    }

    private static int longDelaySeconds() {
        return Math.max(shortDelaySeconds() + 2, (int) Math.ceil(timeBlindThreshold / 1000.0d) + 1);
    }

    private static boolean containsDelayPayload(String value) {
        return SqlInjectionDetector.containsDelayPayload(value);
    }

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

    private static String changeDelaySeconds(String payload, int seconds) {
        if (payload == null) return null;
        return SqlInjectionDetector.changeDelaySeconds(payload, seconds);
    }

    private static String budgetKey(int logid, String location) {
        return logid + "|" + (location == null ? "" : location.trim().toLowerCase(Locale.ROOT));
    }

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

    private static boolean isWafProtected(int logid, IHttpService service) {
        if (service == null) return false;
        String hostKey = service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
        return wafProtectedHosts.contains(hostKey);
    }

    private static boolean acquireBudget(int logid, String location) {
        return parameterBudgets.computeIfAbsent(budgetKey(logid, location),
                key -> new ScanBudget(15)).tryAcquire();
    }

    private static WafEvidence analyzeAndTrackWaf(int logid, IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) return WafEvidence.none();
        try {
            IResponseInfo info = Utils.helpers.analyzeResponse(response.getResponse());
            WafEvidence evidence = SqlInjectionDetector.detectWaf(
                    (int) info.getStatusCode(), info.getHeaders(), getResponseBody(response), false);
            if (evidence.isBlocked() && response.getHttpService() != null) {
                IHttpService service = response.getHttpService();
                String hostKey = service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
                if (wafBlockCounters.computeIfAbsent(hostKey, key -> new AtomicInteger())
                        .incrementAndGet() >= 2) wafProtectedHosts.add(hostKey);
            }
            return evidence;
        } catch (Exception ignored) {
            return WafEvidence.none();
        }
    }

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

    /** 统一发送入口：按目标主机节流，WAF 保护目标自动降低频率。 */
    private static IHttpRequestResponse sendRequest(IHttpService service, byte[] request) {
        if (service == null || request == null) {
            return null;
        }
        String hostKey = service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
        long interval = wafProtectedHosts.contains(hostKey)
                ? WAF_REQUEST_INTERVAL_MS : NORMAL_REQUEST_INTERVAL_MS;
        AtomicLong previous = lastRequestTimes.computeIfAbsent(hostKey, k -> new AtomicLong(0L));
        synchronized (previous) {
            long now = System.currentTimeMillis();
            long wait = interval - (now - previous.get());
            if (wait > 0L) {
                try {
                    Thread.sleep(wait);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            previous.set(System.currentTimeMillis());
        }
        return Utils.callbacks.makeHttpRequest(service, request);
    }

    // 将 JSON 变异结果按路径索引，避免扫描过程中反复线性查找。
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

    // 检测数字型盲注：三响应交叉判定后再做独立重放复核。
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

    // 检测引号型盲注。
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
        return replay != null && replay.isConfirmedPattern()
                && abnormalElapsed >= 0L && normalElapsed >= 0L;
    }

    // 盲注响应长度及相似度对比
    private static boolean checkBlindInjection(String originalResponse, String abnormalResponse, String normalResponse) {
        if (originalResponse == null || abnormalResponse == null || normalResponse == null
                || abnormalResponse.isEmpty() || normalResponse.isEmpty()) {
            return false;
        }
        // 长度差异 alone 容易被随机内容误触发；必须同时满足长度模式和相似度模式。
        boolean lengthBasedCheck = checkResponseLength(originalResponse, abnormalResponse, normalResponse);
        return lengthBasedCheck && checkResponseSimilarity(originalResponse, abnormalResponse, normalResponse);
    }

    // 检查响应长度模式，考虑动态内容
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

    // 清理响应内容（用于长度计算和相似度比对）
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

    private static void markLocationConfirmed(int logid, String location) {
        if (location == null || location.trim().isEmpty()) return;
        confirmedLocations.computeIfAbsent(logid, k -> ConcurrentHashMap.newKeySet())
                .add(location.trim().toLowerCase(Locale.ROOT));
    }

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

    // 检测并报告SQL报错注入：候选响应必须出现基线中不存在的新错误签名。
    private static boolean reportSQLError(int logid, String location, String responseBody,
                                          String vulnDetail, String issueDetail, String url,
                                          IHttpRequestResponse requestResponse) {
        return reportSQLError(logid, location, baselineResponseBodies.get(logid), responseBody,
                vulnDetail, issueDetail, url, requestResponse);
    }

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

    // 检测并报告延时注入。单个高延迟只作为候选，必须收集两个不同 sleep 时长并验证单调性。
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

    private static int extractDelaySeconds(byte[] request) {
        if (request == null || request.length == 0) return 0;
        return SqlInjectionDetector.extractDelaySeconds(Utils.helpers.bytesToString(request));
    }

    // 报告盲注：只有长度+相似度交叉成立且独立重放稳定时才提交 Issue。
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

    // 更新url数据到表格
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

    // 检查参数是否为整数类型
    private static boolean isIntegerParameter(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        return value.matches("^-?\\d+$");
    }

    // 获取响应包的响应体内容
    public static String getResponseBody(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return "";
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();

        return new String(Arrays.copyOfRange(response, bodyOffset, response.length), java.nio.charset.StandardCharsets.UTF_8);
    }

    // 获取响应体实际长度，避免信任错误或缺失的 Content-Length
    private static int getResponseLength(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return 0;
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        return SqlInjectionDetector.actualBodyLength(response, responseInfo.getBodyOffset());
    }


    // 添加url数据到表格
    public static int addUrl(String method, String url, int length, IHttpRequestResponse requestResponse) {
        int id = urlIdCounter.getAndIncrement();
        SqlUIEntry entry = new SqlUIEntry(id, method, url, length, I18nUtils.get("sql.detection.in_progress"), requestResponse);
        urlPayloadMapping.put(id, Collections.synchronizedList(new ArrayList<>()));

        synchronized (urldata) {
            urldata.add(entry);
        }
        SqlUI ui = instance;
        if (ui != null) {
            refreshTableModel(ui.resultTable);
        }
        return id;
    }

    // 添加漏洞数据到表格
    public static void addToVulStr(int key, CharSequence value) {
        if (value == null || value.toString().trim().isEmpty()) {
            return;
        }
        vul.computeIfAbsent(key, k -> ConcurrentHashMap.newKeySet()).add(value.toString().trim());
    }

    private static String getVulnerabilityMessage(int key) {
        Set<String> values = vul.get(key);
        if (values == null || values.isEmpty()) {
            return "";
        }
        return String.join(", ", values);
    }

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

    // 添加payload数据到表格
    public static void addPayload(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
        SqlPayloadEntry entry = new SqlPayloadEntry(selectId, key, value, length, change, errkey, time, status, requestResponse);
        urlPayloadMapping.computeIfAbsent(selectId,
                cacheKey -> Collections.synchronizedList(new ArrayList<>())).add(entry);

        SwingUtilities.invokeLater(() -> {
            synchronized (payloaddata2) {
                payloaddata2.add(entry);
            }
            SqlUI ui = instance;
            if (ui != null) {
                refreshTableModel(ui.payloadtable);
            }
        });
    }

    // payload检测方法
    public static IHttpRequestResponse checkPayload(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, long baselineResponseTime, IHttpRequestResponse originalRequestResponse, IHttpRequestResponse baseRequestResponse, String value) {

        String payload;
        String errkey = "x";

        // URL编码处理
        if (isUrlEncode) {
            value = Utils.UrlEncode(value);
        }

        // 构造payload
        payload = isDeleteOrgin ? value : paraValue + value;

        // 发送请求并记录时间
        long startTime = System.currentTimeMillis();

        // 构造新的参数
        if (para == null || baseRequestResponse == null || baseRequestResponse.getRequest() == null
                || paraName == null || paraName.trim().isEmpty()) {
            return null;
        }
        IParameter iParameters = Utils.helpers.buildParameter(paraName, payload, para.getType());
        byte[] paramByte = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters);
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

    private JPanel buildRightPanel() {
        JPanel rightSplitPane = new JPanel(new BorderLayout());
        rightSplitPane.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

        // 扫描选项
        JPanel scanOptionsPanel = createCompactOptionsPanel(
                I18nUtils.get("sql.border.scan_options"),
                passiveScanCheckBox, deleteOriginalValueCheckBox, checkCookieCheckBox,
                checkHeaderCheckBox, checkWhiteListCheckBox, urlEncodeCheckBox,
                booleanBlindCheckBox);

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

    private void showSaveSuccess() {
        JOptionPane.showMessageDialog(null, I18nUtils.get("config.message.save_success"),
                I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
    }
    // url 实体类
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

    // payload 实体类
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

    // url 模型
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

    // Payload 模型
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

    // url 表格
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

    // payload 表格
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

