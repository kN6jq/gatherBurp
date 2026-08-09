package burp.ui;

import burp.*;
import burp.bean.SqlBean;
import burp.utils.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;

import static burp.IParameter.*;
import static burp.dao.SqlDao.*;

/**
 * @Author Xm17
 * @Date 2024-06-21 15:39
 */
public class SqlUI extends AbstractScanUI {
    private static JTable payloadtable; // payload 表格
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
    public AbstractTableModel model = new SqlPayloadModel();
    private static boolean isPassiveScan; // 是否被动扫描
    private static boolean isCheckCookie; // 是否检测cookie
    private static boolean isCheckHeader; // 是否检测header
    private static boolean isWhiteDomain; // 是否白名单域名
    private static boolean isDeleteOrgin; // 是否删除原始值
    private static boolean isUrlEncode; // 是否进行URL编码
    private static List<String> listErrorKey = new ArrayList<>(); // // 存放错误key
    private static List<SqlBean> sqliPayload = new ArrayList<>(); // 存放sql关键字
    private static List<String> domainList = new ArrayList<>(); // 存放域名白名单
    private static List<SqlBean> headerList = new ArrayList<>(); // 存放header白名单
    private static ConcurrentHashMap<Integer, StringBuilder> vul = new ConcurrentHashMap<>();// 防止插入重复
    private JCheckBox booleanBlindCheckBox; // 布尔盲注选择框
    private static boolean isBooleanBlind;  // 是否进行布尔盲注
    private static int timeBlindThreshold = 6000; // 延时注入阈值(ms)
    private static final ConcurrentHashMap<Integer, List<SqlPayloadEntry>> urlPayloadMapping = new ConcurrentHashMap<>();
    private static final AtomicInteger urlIdCounter = new AtomicInteger(0);

    public static void resetAllCaches() {
        urlHashList.clear();
        urlPayloadMapping.clear();
        urlIdCounter.set(0);
        UrlCacheUtil.resetCache("sqli");
    }

    private static final List<Pattern> rules = new ArrayList<>();

    // Pre-compiled patterns for response cleaning
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
    private static final Pattern CLEAN_NEWLINE = Pattern.compile("\\n|\\r|\\r\\n");
    private static final Pattern CLEAN_WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern CLEAN_HTML_TAGS = Pattern.compile("<[^>]+>");

    static {
        String[] rulePatterns = {
                "the\\s+used\\s+select\\s+statements\\s+have\\s+different\\s+number\\s+of\\s+columns",
                "An\\s+illegal\\s+character\\s+has\\s+been\\s+found\\s+in\\s+the\\s+statement",
                "MySQL\\s+server\\s+version\\s+for\\s+the\\s+right\\s+syntax\\s+to\\s+use",
                "supplied\\s+argument\\s+is\\s+not\\s+a\\s+valid\\s+PostgreSQL\\s+result",
                "Unclosed\\s+quotation\\s+mark\\s+before\\s+the\\s+character\\s+string",
                "Unclosed\\s+quotation\\s+mark\\s+after\\s+the\\s+character\\s+string",
                "Column\\s+count\\s+doesn't\\s+match\\s+value\\s+count\\s+at\\s+row",
                "Syntax\\s+error\\s+in\\s+string\\s+in\\s+query\\s+expression",
                "Microsoft\\s+OLE\\s+DB\\s+Provider\\s+for\\s+ODBC\\s+Drivers",
                "Microsoft\\s+OLE\\s+DB\\s+Provider\\s+for\\s+SQL\\s+Server",
                "\\[Microsoft\\]\\[ODBC\\s+Microsoft\\s+Access\\s+Driver\\]",
                "You\\s+have\\s+an\\s+error\\s+in\\s+your\\s+SQL\\s+syntax",
                "supplied\\s+argument\\s+is\\s+not\\s+a\\s+valid\\s+MySQL",
                "Data\\s+type\\s+mismatch\\s+in\\s+criteria\\s+expression",
                "internal\\s+error\\s+\\[IBM\\]\\[CLI\\s+Driver\\]\\[DB2",
                "Unexpected\\s+end\\s+of\\s+command\\s+in\\s+statement",
                "\\[Microsoft\\]\\[ODBC\\s+SQL\\s+Server\\s+Driver\\]",
                "\\[Macromedia\\]\\[SQLServer\\s+JDBC\\s+Driver\\]",
                "has\\s+occurred\\s+in\\s+the\\s+vicinity\\s+of:",
                "A\\s+Parser\\s+Error\\s+\\(syntax\\s+error\\)",
                "Procedure\\s+'[^']+'\\s+requires\\s+parameter",
                "Microsoft\\s+SQL\\s+Native\\s+Client\\s+error",
                "Syntax\\s+error\\s+in\\s+query\\s+expression",
                "System\\.Data\\.SqlClient\\.SqlException",
                "Dynamic\\s+Page\\s+Generation\\s+Error:",
                "System\\.Exception: SQL Execution Error",
                "Microsoft\\s+JET\\s+Database\\s+Engine",
                "System\\.Data\\.OleDb\\.OleDbException",
                "Sintaxis\\s+incorrecta\\s+cerca\\s+de",
                "Table\\s+'[^']+'\\s+doesn't\\s+exist",
                "java\\.sql\\.SQLSyntaxErrorException",
                "Column\\s+count\\s+doesn't\\s+match",
                "your\\s+MySQL\\s+server\\s+version",
                "\\[SQLServer\\s+JDBC\\s+Driver\\]",
                "ADODB\\.Field\\s+\\(0x800A0BCD\\)",
                "com.microsoft\\.sqlserver\\.jdbc",
                "ODBC\\s+SQL\\s+Server\\s+Driver",
                "(PLS|ORA)-[0-9][0-9][0-9][0-9]",
                "PostgreSQL\\s+query\\s+failed:",
                "on\\s+MySQL\\s+result\\s+index",
                "valid\\s+PostgreSQL\\s+result",
                "macromedia\\.jdbc\\.sqlserver",
                "Access\\s+Database\\s+Engine",
                "SQLServer\\s+JDBC\\s+Driver",
                "Incorrect\\s+syntax\\s+near",
                "java\\.sql\\.SQLException",
                "java\\.sql\\.SQLException",
                "MySQLSyntaxErrorException",
                "<b>Warning</b>:\\s+ibase_",
                "valid\\s+MySQL\\s+result",
                "org\\.postgresql\\.jdbc",
                "com\\.jnetdirect\\.jsql",
                "Dynamic\\s+SQL\\s+Error",
                "\\[DM_QUERY_E_SYNTAX\\]",
                "mysql_fetch_array\\(\\)",
                "pg_query\\(\\)\\s+\\[:",
                "pg_exec\\(\\)\\s+\\[:",
                "com\\.informix\\.jdbc",
                "DB2\\s+SQL\\s+error:",
                "DB2\\s+SQL\\s+error",
                "Microsoft\\s+Access",
                "\\[CLI\\s+Driver\\]",
                "\\[SQL\\s+Server\\]",
                "com\\.mysql\\.jdbc",
                "Sybase\\s+message:",
                "\\[MySQL\\]\\[ODBC",
                "ADODB\\.Recordset",
                "Unknown\\s+column",
                "mssql_query\\(\\)",
                "Sybase\\s+message",
                "Database\\s+error",
                "PG::SyntaxError:",
                "where\\s+clause",
                "Syntax\\s+error",
                "Oracle\\s+error",
                "SQLite\\s+error",
                "SybSQLException",
                "\\[SqlException",
                "odbc_exec\\(\\)",
                "MySqlException",
                "INSERT\\s+INTO",
                "SQL\\s+syntax",
                "Error\\s+SQL:",
                "SQL\\s+error",
                "PSQLException",
                "SQLSTATE=\\d+",
                "SELECT .{1,30}FROM ",
                "UPDATE .{1,30}SET ",
                "附近有语法错误",
                "MySqlClient",
                "ORA-\\d{5}",
                "引号不完整",
                "数据库出错",
                "Parameter '\\w+' not found",
                "org\\.apache\\.ibatis\\.binding\\.BindingException",
                "mybatis\\.binding\\.BindingException",
                "org\\.mybatis\\.spring\\.MyBatisSystemException",
                "java\\.lang\\.IllegalArgumentException: invalid parameter",
                "Could not resolve parameter",
                "There is no getter for property named",
                "Error evaluating expression",
                "Error parsing parameter",
                "Invalid bound statement"
        };
        for (String pattern : rulePatterns) {
            rules.add(Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
        }
    }
    // sql检测核心方法
    public static void Check(IHttpRequestResponse[] requestResponses, boolean isSend) {
        IHttpRequestResponse baseRequestResponse = requestResponses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<String> reqheaders = analyzeRequest.getHeaders();
        String host = baseRequestResponse.getHttpService().getHost();
        String method = analyzeRequest.getMethod();
        URL rdurlURL = analyzeRequest.getUrl();
        String url = rdurlURL.toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();

        if (!method.equals("GET") && !method.equals("POST")) {
            return;
        }
        if (Utils.isUrlBlackListSuffix(url)) {
            return;
        }

        // 检查是否存在可检测的参数类型
        boolean hasDetectableParam = false;
        for (IParameter para : paraLists) {
            if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY ||
                    para.getType() == PARAM_JSON || isCheckCookie || isCheckHeader) {
                hasDetectableParam = true;
                break;
            }
        }
        if (!hasDetectableParam) {
            return;
        }

        if (!isSend) {
            if (!UrlCacheUtil.checkUrlUnique("sqli", method, rdurlURL, paraLists)) {
                return;
            }
            if (isWhiteDomain && !Utils.isMatchDomainName(host, domainList)) {
                return;
            }
        }

        // 发送原始请求用于对比
        byte[] request = baseRequestResponse.getRequest();
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
        IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(),
                Utils.helpers.buildHttpMessage(reqheaders, body)
        );

        byte[] origResponseBody = originalRequestResponse.getResponse();
        if (origResponseBody == null) {
            return;
        }
        IResponseInfo originalResponseInfo = Utils.helpers.analyzeResponse(origResponseBody);
        String contentLength = HelperPlus.getHeaderValueOf(originalResponseInfo.getHeaders(), "Content-Length");
        int originalLength = (contentLength != null) ? Integer.parseInt(contentLength) : origResponseBody.length;
        if (originalLength == 0 || originalResponseInfo.getStatusCode() == 404) {
            return;
        }

        int logid = addUrl(method, url, originalLength, baseRequestResponse);

        try {
            // 检测常规注入
            for (IParameter para : paraLists) {
            // 如果参数符合下面的类型，则进行检测
            if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_COOKIE || para.getType() == PARAM_JSON) {
                String paraName = para.getName();
                String paraValue = para.getValue();
                // 检测常规参数的注入
                if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
                    if (paraName.isEmpty()) {
                        break;
                    }
                    // 先判断是否为数字型参数
                    if (isIntegerParameter(paraValue)) {
                        checkNumberBasedBlind(logid, para, paraName, paraValue, url, originalLength, originalRequestResponse);
                        checkQuoteBasedBlind(logid, para, paraName, paraValue, url, originalLength, originalRequestResponse);
                    } else {
                        checkQuoteBasedBlind(logid, para, paraName, paraValue, url, originalLength, originalRequestResponse);
                    }

                    // 正常的检测流程
                    // 使用payload进行检测
                    for (SqlBean sql : sqliPayload) {
                        String payload = Utils.ReplaceChar(sql.getValue());
                        // 如果sqlPayload是上面的 可以直接跳过
                        if (payload.equals("'") || payload.equals("''") || payload.equals("'''") || payload.isEmpty()) {
                            continue;
                        }
                        checkPayload(logid, para, paraName, paraValue, url, originalLength, baseRequestResponse, payload);
                    }

                }
                // 检测json类型的注入
                if (para.getType() == PARAM_JSON) {
                    // 获取JSON请求体
                    String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                    if (request_data.isEmpty()) {
                        break;
                    }

                    // 获取原始响应数据
                    byte[] jsonBody = Utils.helpers.buildHttpMessage(reqheaders, request_data.getBytes());
                    IHttpRequestResponse jsonRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), jsonBody);
                    String originalResponse = getResponseBody(jsonRequestResponse);
                    int jsonResponseLength = originalResponse.length();

                    // 对每个JSON参数进行测试
                    List<JsonProcessorUtil.ProcessResult> processResults = JsonProcessorUtil.processWithPath(request_data, "", isDeleteOrgin);
                    for (JsonProcessorUtil.ProcessResult pathResult : processResults) {
                        String jsonParam = pathResult.getParamPath();  // JSON参数路径

                        // 测试单引号响应
                        long singleQuoteStartTime = System.currentTimeMillis();
                        List<JsonProcessorUtil.ProcessResult> singleQuoteResults = JsonProcessorUtil.processWithPath(request_data, "'", isDeleteOrgin);
                        JsonProcessorUtil.ProcessResult singleQuoteResult = findResultByPath(singleQuoteResults, jsonParam);
                        byte[] singleQuoteBytes = Utils.helpers.buildHttpMessage(reqheaders, singleQuoteResult.getModifiedJson().getBytes());
                        IHttpRequestResponse singleQuoteResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), singleQuoteBytes);
                        long singleQuoteResponseTime = System.currentTimeMillis() - singleQuoteStartTime;
                        String singleQuoteBody = getResponseBody(singleQuoteResponse);

                        // 测试双引号响应
                        long doubleQuoteStartTime = System.currentTimeMillis();
                        List<JsonProcessorUtil.ProcessResult> doubleQuoteResults = JsonProcessorUtil.processWithPath(request_data, "''", isDeleteOrgin);
                        JsonProcessorUtil.ProcessResult doubleQuoteResult = findResultByPath(doubleQuoteResults, jsonParam);
                        byte[] doubleQuoteBytes = Utils.helpers.buildHttpMessage(reqheaders, doubleQuoteResult.getModifiedJson().getBytes());
                        IHttpRequestResponse doubleQuoteResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), doubleQuoteBytes);
                        long doubleQuoteResponseTime = System.currentTimeMillis() - doubleQuoteStartTime;
                        String doubleQuoteBody = getResponseBody(doubleQuoteResponse);

                        // 检查是否存在盲注
                        boolean isVulnerable = checkBlindInjection(
                                originalResponse,
                                singleQuoteBody,
                                doubleQuoteBody,
                                jsonResponseLength,
                                singleQuoteBody.length(),
                                doubleQuoteBody.length()
                        );

                        // 如果存在盲注，添加到漏洞字符串
                        if (isVulnerable) {
                            addToVulStr(logid, jsonParam + " " + I18nUtils.get("sql.vuln.possible_blind").replace("{0}", ""));
                            try {
                                IScanIssue issues = new CustomScanIssue(
                                        jsonRequestResponse.getHttpService(),
                                        new URL(url),
                                        new IHttpRequestResponse[]{jsonRequestResponse, singleQuoteResponse, doubleQuoteResponse},
                                        "SqlInject Blind",
                                        String.format(I18nUtils.get("sql.issue.json_blind"), jsonParam, jsonResponseLength, singleQuoteBody.length(), doubleQuoteBody.length()),
                                        "High",
                                        "Certain"
                                );
                                Utils.callbacks.addScanIssue(issues);
                            } catch (MalformedURLException e) {
                                throw new RuntimeException("CheckJsonBlind" + e);
                            }
                        }

                        // 为单引号payload添加记录
                        String singleQuoteErrKey = "x";
                        // 检查报错
                        if (reportSQLError(logid, singleQuoteBody, String.format(I18nUtils.get("sql.vuln.json_error"), jsonParam), I18nUtils.get("sql.issue.json_error"), url, singleQuoteResponse)) {
                            singleQuoteErrKey = I18nUtils.get("sql.vuln.error");
                        }

                        // 为双单引号payload添加记录
                        String doubleQuoteErrKey = "x";
                        // 检查报错
                        if (reportSQLError(logid, doubleQuoteBody, String.format(I18nUtils.get("sql.vuln.json_error"), jsonParam), I18nUtils.get("sql.issue.json_error"), url, doubleQuoteResponse)) {
                            doubleQuoteErrKey = I18nUtils.get("sql.vuln.error");
                        }

                        // 记录单引号payload结果
                        addPayload(
                                logid,
                                jsonParam,
                                "'",
                                singleQuoteBody.length(),
                                String.valueOf(Math.abs(singleQuoteBody.length() - jsonResponseLength)),
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
                                doubleQuoteBody.length(),
                                String.valueOf(Math.abs(doubleQuoteBody.length() - jsonResponseLength)),
                                doubleQuoteErrKey,
                                String.valueOf(doubleQuoteResponseTime),
                                String.valueOf(Utils.helpers.analyzeResponse(doubleQuoteResponse.getResponse()).getStatusCode()),
                                doubleQuoteResponse
                        );

                        for (SqlBean sql : sqliPayload) {
                            String payload = Utils.ReplaceChar(sql.getValue());
                            // 跳过已测试过的引号payload
                            if (payload.equals("'") || payload.equals("''") || payload.equals("'''") || payload.isEmpty()) {
                                continue;
                            }

                            // 测试当前payload
                            long startTime = System.currentTimeMillis();
                            List<JsonProcessorUtil.ProcessResult> payloadResults = JsonProcessorUtil.processWithPath(request_data, payload, isDeleteOrgin);
                            JsonProcessorUtil.ProcessResult payloadResult = findResultByPath(payloadResults, jsonParam);
                            if (payloadResult == null) continue;

                            byte[] payloadBytes = Utils.helpers.buildHttpMessage(reqheaders, payloadResult.getModifiedJson().getBytes());
                            IHttpRequestResponse payloadResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), payloadBytes);
                            long responseTime = System.currentTimeMillis() - startTime;
                            String payloadBody = getResponseBody(payloadResponse);

                            String errkey = "x";

                            // 检查报错注入
                            if (reportSQLError(logid, payloadBody, String.format(I18nUtils.get("sql.vuln.json_error"), jsonParam), I18nUtils.get("sql.issue.json_error"), url, payloadResponse)) {
                                errkey = I18nUtils.get("sql.vuln.error");
                            }

                            // 检查延时注入
                            if (reportTimeBlind(logid, responseTime, String.format(I18nUtils.get("sql.vuln.json_time"), jsonParam), I18nUtils.get("sql.issue.json_time"), url, payloadResponse)) {
                                errkey = I18nUtils.get("sql.vuln.time");
                            }

                            // 记录payload测试结果
                            addPayload(
                                    logid,
                                    jsonParam,
                                    payload,
                                    payloadBody.length(),
                                    String.valueOf(Math.abs(payloadBody.length() - jsonResponseLength)),
                                    errkey,
                                    String.valueOf(responseTime),
                                    String.valueOf(Utils.helpers.analyzeResponse(payloadResponse.getResponse()).getStatusCode()),
                                    payloadResponse
                            );
                        }
                    }
                    break;
                }
                // 检测cookie注入
                if (isCheckCookie && para.getType() == PARAM_COOKIE) {
                    if (paraName.isEmpty()) {
                        break;
                    }
                    for (SqlBean sql : sqliPayload) {
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
                        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                        long endTime = System.currentTimeMillis();
                        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                        int statusCode = analyzeResponse.getStatusCode();
                        String responseTime = String.valueOf(endTime - startTime);
                        byte[] sqlresponseBody = newRequestResponse.getResponse();
                        int sqlLength = sqlresponseBody != null ? getResponseLength(newRequestResponse) : 0;
                        String sqlResponseBody = new String(sqlresponseBody);
                        if (reportSQLError(logid, sqlResponseBody, String.format(I18nUtils.get("sql.vuln.cookie_error"), paraName), I18nUtils.get("sql.issue.error"), url, newRequestResponse)) {
                            errkey = I18nUtils.get("sql.vuln.error");
                        }
                        long cookieResponseTime = Long.parseLong(responseTime);
                        if (reportTimeBlind(logid, cookieResponseTime, String.format(I18nUtils.get("sql.vuln.cookie_time"), paraName), I18nUtils.get("sql.issue.time"), url, newRequestResponse)) {
                            errkey = I18nUtils.get("sql.vuln.time");
                        }
                        addPayload(logid, paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }
                }
            }
        }
        // 检测header注入
        if (isCheckHeader && !headerList.isEmpty()) {
            // 新建一个用于存储新请求头的列表，并复制原始请求头到新列表中
            List<String> newReqheaders = new ArrayList<>(reqheaders);
            for (String reqheadersx : reqheaders) {
                for (SqlBean sqlBean : headerList) {
                    String headerName = sqlBean.getValue();
                    if (reqheadersx.contains(headerName)) {
                        // 删除原始请求头中包含的相同头部字段
                        newReqheaders.remove(reqheadersx);
                        // 不检测cookie
                        if (headerName.contains("Cookie")) {
                            break;
                        }
                        // 分割 reqheadersx 获取 header 值
                        String[] headerParts = reqheadersx.split(":", 2);
                        String originalHeaderValue = headerParts.length > 1 ? headerParts[1].trim() : "";

                        for (SqlBean sql : sqliPayload) {
                            String errkey = "x";
                            String payload = "";
                            String sqlPayload = Utils.ReplaceChar(sql.getValue());
                            if (sqlPayload.isEmpty()) {
                                continue;
                            }
                            if (isDeleteOrgin) {
                                payload = sqlPayload;
                            } else {
                                payload = originalHeaderValue + sqlPayload;
                            }
                            // 添加新的头部字段到新的列表中
                            newReqheaders.add(headerName + ": " + payload);
                            byte[] bytes = Utils.helpers.buildHttpMessage(newReqheaders, body);
                            long startTime = System.currentTimeMillis();
                            IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                            IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                            long endTime = System.currentTimeMillis();
                            String responseTime = String.valueOf(endTime - startTime);
                            int statusCode = analyzeResponse.getStatusCode();
                            byte[] sqlresponseBody = newRequestResponse.getResponse();
                            int sqlLength = 0;
                            if (sqlresponseBody != null) {
                                sqlLength = getResponseLength(newRequestResponse);
                                // 判断body中是否有errorkey关键字
                                String sqlResponseBody = new String(sqlresponseBody);
                                if (reportSQLError(logid, sqlResponseBody, I18nUtils.get("sql.vuln.header_error"), I18nUtils.get("sql.issue.error"), url, newRequestResponse)) {
                                    errkey = I18nUtils.get("sql.vuln.error");
                                }
                                long headerResponseTime = Long.parseLong(responseTime);
                                if (reportTimeBlind(logid, headerResponseTime, I18nUtils.get("sql.vuln.header_time"), I18nUtils.get("sql.issue.time"), url, newRequestResponse)) {
                                    errkey = I18nUtils.get("sql.vuln.time");
                                }
                            }
                            addPayload(logid, headerName, sqlPayload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                            // 每次完成请求后，移除刚刚添加的新头部字段，以便下一次迭代
                            newReqheaders.remove(newReqheaders.size() - 1);
                        }
                        break; // 已经处理了当前的头部信息，可以退出内循环
                    }
                }
            }
        }
        } catch (Exception e) {
            // 检测过程中出现异常，记录错误信息
            addToVulStr(logid, I18nUtils.get("sql.detection.error") + " " + e.getMessage());
            Utils.stderr.println(I18nUtils.get("sql.detection.error_prefix") + e.getMessage());
            e.printStackTrace();
        } finally {
            // 无论是否出现异常，都要更新最终状态
            // 如果没有异常且正常完成，添加检测完成状态
            if (!vul.containsKey(logid) || !vul.get(logid).toString().contains(I18nUtils.get("sql.detection.error"))) {
                addToVulStr(logid, I18nUtils.get("sql.detection.complete"));
            }
            // 更新数据
            updateUrl(logid, method, url, originalLength, vul.get(logid).toString(), originalRequestResponse);
        }
    }
    // 在json结果列表中查找指定路径的结果
    private static JsonProcessorUtil.ProcessResult findResultByPath(List<JsonProcessorUtil.ProcessResult> results, String path) {
        return results.stream()
                .filter(r -> r.getParamPath().equals(path))
                .findFirst()
                .orElse(null);
    }

    // 检测数字型盲注
    private static void checkNumberBasedBlind(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, IHttpRequestResponse originalRequestResponse) {
        // 获取测试响应
        IHttpRequestResponse checkedPayload1 = checkPayload(logid, para, paraName, paraValue, url, originalLength, originalRequestResponse, "-1");
        IHttpRequestResponse checkedPayload0 = checkPayload(logid, para, paraName, paraValue, url, originalLength, originalRequestResponse, "-0");

        // 获取响应体
        String originalResponse = getResponseBody(originalRequestResponse);
        String payload1Response = getResponseBody(checkedPayload1);
        String payload0Response = getResponseBody(checkedPayload0);

        // 检查是否存在盲注
        boolean isVulnerable = checkBlindInjection(originalResponse, payload1Response, payload0Response, originalLength, payload1Response.length(), payload0Response.length());

        if (isVulnerable) {
            reportBlindInjection(logid, paraName, url, checkedPayload1, "Number");
        }
    }

    // 检测引号型盲注
    private static void checkQuoteBasedBlind(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, IHttpRequestResponse originalRequestResponse) {
        // 获取测试响应
        IHttpRequestResponse checkedPayloadQuote = checkPayload(logid, para, paraName, paraValue, url, originalLength, originalRequestResponse, "'");
        IHttpRequestResponse checkedPayloadQuotes = checkPayload(logid, para, paraName, paraValue, url, originalLength, originalRequestResponse, "''");

        // 获取响应体
        String originalResponse = getResponseBody(originalRequestResponse);
        String quoteResponse = getResponseBody(checkedPayloadQuote);
        String quotesResponse = getResponseBody(checkedPayloadQuotes);

        // 检查是否存在盲注
        boolean isVulnerable = checkBlindInjection(originalResponse, quoteResponse, quotesResponse, originalLength, quotesResponse.length(), quoteResponse.length());

        if (isVulnerable) {
            reportBlindInjection(logid, paraName, url, checkedPayloadQuote, "Quote");
        }
    }

    // 盲注响应长度及相似度对比
    private static boolean checkBlindInjection(String originalResponse, String abnormalResponse, String normalResponse, int originalLength, int abnormalLength, int normalLength) {
        // 判断方式1: 基于响应长度变化（考虑动态内容），始终执行
        boolean lengthBasedCheck = checkResponseLength(
                originalResponse, abnormalResponse, normalResponse,
                originalLength, abnormalLength, normalLength
        );

        if (!isBooleanBlind) {
            return lengthBasedCheck;
        }

        // 判断方式2: 基于相似度比对（仅在启用布尔盲注时执行，计算开销较大）
        boolean similarityBasedCheck = checkResponseSimilarity(
                originalResponse, abnormalResponse, normalResponse
        );

        return lengthBasedCheck || similarityBasedCheck;
    }

    // 检查响应长度模式，考虑动态内容
    private static boolean checkResponseLength(String originalResponse, String abnormalResponse, String normalResponse, int originalLength, int abnormalLength, int normalLength) {

        // 获取处理后的响应长度
        int cleanOriginalLength = cleanResponse(originalResponse).length();
        int cleanAbnormalLength = cleanResponse(abnormalResponse).length();
        int cleanNormalLength = cleanResponse(normalResponse).length();

        // 计算长度差异
        int diffOriginalAbnormal = Math.abs(cleanOriginalLength - cleanAbnormalLength);
        int diffOriginalNormal = Math.abs(cleanOriginalLength - cleanNormalLength);
        int diffNormalAbnormal = Math.abs(cleanNormalLength - cleanAbnormalLength);

        // 定义长度差异阈值（可根据实际情况调整）
        int LENGTH_THRESHOLD = 10;

        // 判断长度模式
        return diffOriginalNormal <= LENGTH_THRESHOLD && // 原始响应和正常响应长度相近
                diffOriginalAbnormal > LENGTH_THRESHOLD && // 原始响应和异常响应长度差异明显
                diffNormalAbnormal > LENGTH_THRESHOLD;     // 正常响应和异常响应长度差异明显
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

        // 相似度比对
        boolean originalVsNormalSimilar = !ResponseSimilarityMatcher.compareTwoResponses(
                cleanOriginal, cleanNormal);    // 相似
        boolean originalVsAbnormalDifferent = ResponseSimilarityMatcher.compareTwoResponses(
                cleanOriginal, cleanAbnormal);  // 不相似
        boolean normalVsAbnormalDifferent = ResponseSimilarityMatcher.compareTwoResponses(
                cleanNormal, cleanAbnormal);    // 不相似

        return originalVsNormalSimilar &&
                originalVsAbnormalDifferent &&
                normalVsAbnormalDifferent;
    }

    // 检测并报告SQL报错注入
    private static boolean reportSQLError(int logid, String responseBody, String vulnDetail, String issueDetail, String url, IHttpRequestResponse requestResponse) {
        if (errSqlCheck(responseBody)) {
            addToVulStr(logid, vulnDetail);
            try {
                IScanIssue issues = new CustomScanIssue(
                        requestResponse.getHttpService(),
                        new URL(url),
                        new IHttpRequestResponse[]{requestResponse},
                        "SqlInject Error",
                        issueDetail,
                        "High",
                        "Certain"
                );
                Utils.callbacks.addScanIssue(issues);
            } catch (Exception e) {
                Utils.stderr.println("reportSQLError: " + e.getMessage());
            }
            return true;
        }
        return false;
    }

    // 检测并报告延时注入
    private static boolean reportTimeBlind(int logid, long responseTime, String vulnDetail, String issueDetail, String url, IHttpRequestResponse requestResponse) {
        if (responseTime > timeBlindThreshold) {
            addToVulStr(logid, vulnDetail);
            try {
                IScanIssue issues = new CustomScanIssue(
                        requestResponse.getHttpService(),
                        new URL(url),
                        new IHttpRequestResponse[]{requestResponse},
                        "SqlInject Time",
                        issueDetail,
                        "High",
                        "Certain"
                );
                Utils.callbacks.addScanIssue(issues);
            } catch (Exception e) {
                Utils.stderr.println("reportTimeBlind: " + e.getMessage());
            }
            return true;
        }
        return false;
    }

    // 存在盲注漏洞
    private static void reportBlindInjection(int logid, String paraName, String url, IHttpRequestResponse requestResponse, String type) {
        addToVulStr(logid, String.format(I18nUtils.get("sql.vuln.possible_blind"), paraName));

        try {
            IScanIssue issues = new CustomScanIssue(requestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{requestResponse}, "SQL Injection Blind", String.format(I18nUtils.get("sql.issue.blind"), type), "High", "Certain");
            Utils.callbacks.addScanIssue(issues);
        } catch (MalformedURLException e) {
            throw new RuntimeException("CheckBlind: " + e);
        }
    }

    // 更新url数据到表格
    public static void updateUrl(int index, String method, String url, int length, String message, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            if (index >= 0 && index < urldata.size()) {
                urldata.set(index, new SqlUIEntry(index, method, url, length, message, requestResponse));
            }
            resultTable.updateUI();
            payloadtable.updateUI();
        }
    }

    // 检查参数是否为整数类型
    private static boolean isIntegerParameter(String value) {
        if (value == null || value.trim().isEmpty()) {
            return false;
        }
        return value.matches("^-?\\d+$");
    }

    // 正则判断响应数据包中是否包含报错关键字
    private static boolean errSqlCheck(String responseBody) {
        if (!listErrorKey.isEmpty()) {
            for (String errKey : listErrorKey) {
                if (responseBody.contains(errKey)) {
                    return true;
                }
            }
        }

        String cleanedText = CLEAN_NEWLINE.matcher(responseBody).replaceAll("");
        for (Pattern rule : rules) {
            if (rule.matcher(cleanedText).find()) {
                return true;
            }
        }
        return false;
    }

    // 获取响应包的响应体内容
    public static String getResponseBody(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return "";
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();

        return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
    }

    // 获取响应长度（优先使用Content-Length头，否则使用响应体长度）
    private static int getResponseLength(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return 0;
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        String contentLength = HelperPlus.getHeaderValueOf(responseInfo.getHeaders(), "Content-Length");
        return (contentLength != null) ? Integer.parseInt(contentLength) : response.length;
    }

    // 添加url数据到表格
    public static int addUrl(String method, String url, int length, IHttpRequestResponse requestResponse) {
        int id = urlIdCounter.getAndIncrement();
        SqlUIEntry entry = new SqlUIEntry(id, method, url, length, I18nUtils.get("sql.detection.in_progress"), requestResponse);
        urlPayloadMapping.put(id, Collections.synchronizedList(new ArrayList<>()));

        SwingUtilities.invokeLater(() -> {
            urldata.add(entry);
            resultTable.updateUI();
        });
        return id;
    }

    // 添加漏洞数据到表格
    public static void addToVulStr(int key, CharSequence value) {
        // 检查是否已经存在该键，如果不存在则创建一个新的 ArrayList 存储值
        vul.computeIfAbsent(key, k -> new StringBuilder()).append(value).append(", ");
    }

    // 添加payload数据到表格
    public static void addPayload(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
        SqlPayloadEntry entry = new SqlPayloadEntry(selectId, key, value, length, change, errkey, time, status, requestResponse);
        urlPayloadMapping.get(selectId).add(entry);

        SwingUtilities.invokeLater(() -> {
            payloaddata2.add(entry);
            payloadtable.updateUI();
        });
    }

    // payload检测方法
    public static IHttpRequestResponse checkPayload(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, IHttpRequestResponse baseRequestResponse, String value) {

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
        IParameter iParameters = Utils.helpers.buildParameter(paraName, payload, para.getType());
        byte[] paramByte = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters);

        // 发送请求
        IHttpRequestResponse newRequestResponses = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), paramByte);

        long endTime = System.currentTimeMillis();
        long responseTime = endTime - startTime;

        // 获取响应数据
        byte[] responseBody = newRequestResponses.getResponse();
        if (responseBody != null) {
            // 分析响应
            IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(responseBody);
            int statusCode = analyzeResponse.getStatusCode();
            int length = getResponseLength(newRequestResponses);

            // 检查SQL错误
            String responseBodyStr = new String(responseBody);
            if (reportSQLError(logid, responseBodyStr, String.format(I18nUtils.get("sql.vuln.param_error"), paraName), I18nUtils.get("sql.issue.error"), url, newRequestResponses)) {
                errkey = I18nUtils.get("sql.vuln.error");
            }

            // 检查延时注入（时间盲注）
            if (reportTimeBlind(logid, responseTime, String.format(I18nUtils.get("sql.vuln.param_time"), paraName), I18nUtils.get("sql.issue.time"), url, newRequestResponses)) {
                errkey = I18nUtils.get("sql.vuln.time");
            }

            // 记录payload结果
            addPayload(logid, paraName, payload, length, String.valueOf(length - originalLength), errkey, String.valueOf(responseTime), String.valueOf(statusCode), newRequestResponses);
        }

        return newRequestResponses;
    }
    @Override
    protected void setupScanUI() {
        Utils.callbacks.registerHttpListener(this);

        resultTable = new URLTable(new SqlUrlModel());
        payloadtable = new PayloadTable(new SqlPayloadModel());

        passiveScanCheckBox = new JCheckBox(I18nUtils.get("sql.checkbox.passive"));
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
        leftSplitPane.setResizeWeight(0.6);

        // 上方：URL表格 + Payload表格水平分割
        JSplitPane tablesSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        tablesSplit.setResizeWeight(0.5);
        JScrollPane urlScrollPane = new JScrollPane(resultTable);
        JScrollPane payloadScrollPane = new JScrollPane(payloadtable);
        tablesSplit.setLeftComponent(urlScrollPane);
        tablesSplit.setRightComponent(payloadScrollPane);
        leftSplitPane.setTopComponent(tablesSplit);

        // 下方：请求/响应编辑器
        requestEditor = Utils.callbacks.createMessageEditor(SqlUI.this, true);
        responseEditor = Utils.callbacks.createMessageEditor(SqlUI.this, false);
        requestTabPane = new JTabbedPane();
        requestTabPane.addTab("Request", requestEditor.getComponent());
        responseTabPane = new JTabbedPane();
        responseTabPane.addTab("Response", responseEditor.getComponent());
        JSplitPane editorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        editorSplit.setResizeWeight(0.5);
        editorSplit.setLeftComponent(requestTabPane);
        editorSplit.setRightComponent(responseTabPane);
        leftSplitPane.setBottomComponent(editorSplit);

        // 右半部分：配置面板
        JPanel rightPanel = buildRightPanel();

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.65);
        mainSplit.setLeftComponent(leftSplitPane);
        mainSplit.setRightComponent(rightPanel);

        panel.add(mainSplit, BorderLayout.CENTER);
    }

    private JPanel buildRightPanel() {
        JPanel rightSplitPane = new JPanel(new BorderLayout());
        rightSplitPane.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // 扫描选项
        JPanel scanOptionsPanel = new JPanel(new GridLayout(2, 3, 5, 5));
        scanOptionsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("sql.border.scan_options")));
        scanOptionsPanel.add(passiveScanCheckBox);
        scanOptionsPanel.add(deleteOriginalValueCheckBox);
        scanOptionsPanel.add(checkCookieCheckBox);
        scanOptionsPanel.add(checkHeaderCheckBox);
        scanOptionsPanel.add(checkWhiteListCheckBox);
        scanOptionsPanel.add(urlEncodeCheckBox);
        scanOptionsPanel.add(booleanBlindCheckBox);

        // 配置面板
        JPanel configPanel = new JPanel(new BorderLayout(5, 5));
        configPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("sql.border.configuration")));

        JPanel whitelistPanel = new JPanel(new BorderLayout(5, 5));
        whitelistPanel.add(new JLabel(I18nUtils.get("sql.label.whitelist")), BorderLayout.NORTH);
        whitelistPanel.add(new JScrollPane(whiteListTextArea), BorderLayout.CENTER);
        JPanel wlBtn = new JPanel(new FlowLayout(FlowLayout.LEFT));
        wlBtn.add(saveWhiteListButton);
        whitelistPanel.add(wlBtn, BorderLayout.SOUTH);

        JPanel headerPanel = new JPanel(new BorderLayout(5, 5));
        headerPanel.add(new JLabel(I18nUtils.get("sql.label.header")), BorderLayout.NORTH);
        headerPanel.add(new JScrollPane(headerTextArea), BorderLayout.CENTER);
        JPanel hBtn = new JPanel(new FlowLayout(FlowLayout.LEFT));
        hBtn.add(saveHeaderListButton);
        headerPanel.add(hBtn, BorderLayout.SOUTH);

        JSplitPane configSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        configSplit.setResizeWeight(0.5);
        configSplit.setTopComponent(whitelistPanel);
        configSplit.setBottomComponent(headerPanel);
        configPanel.add(configSplit, BorderLayout.CENTER);

        // 操作按钮
        JPanel actionButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        actionButtonsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("sql.border.actions")));
        actionButtonsPanel.add(refreshTableButton);
        actionButtonsPanel.add(clearTableButton);

        JSplitPane mainRightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainRightSplit.setResizeWeight(0.3);
        mainRightSplit.setTopComponent(scanOptionsPanel);
        JPanel cfgAct = new JPanel(new BorderLayout(5, 5));
        cfgAct.add(configPanel, BorderLayout.CENTER);
        cfgAct.add(actionButtonsPanel, BorderLayout.SOUTH);
        mainRightSplit.setBottomComponent(cfgAct);
        rightSplitPane.add(mainRightSplit, BorderLayout.CENTER);

        // 下方：Payload和Error Key
        JPanel rightDownPanel = new JPanel(new BorderLayout());
        JSplitPane downSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        downSplit.setResizeWeight(0.5);

        JPanel payloadPanel = new JPanel(new BorderLayout(5, 5));
        payloadPanel.add(new JLabel(I18nUtils.get("sql.label.payload")), BorderLayout.NORTH);
        payloadPanel.add(new JScrollPane(sqlPayloadTextArea), BorderLayout.CENTER);
        payloadPanel.add(saveSqlPayloadButton, BorderLayout.SOUTH);

        JPanel errKeyPanel = new JPanel(new BorderLayout(5, 5));
        errKeyPanel.add(new JLabel(I18nUtils.get("sql.label.error_key")), BorderLayout.NORTH);
        errKeyPanel.add(new JScrollPane(sqlErrorKeyTextArea), BorderLayout.CENTER);
        errKeyPanel.add(saveSqlErrorKeyButton, BorderLayout.SOUTH);

        downSplit.setTopComponent(payloadPanel);
        downSplit.setBottomComponent(errKeyPanel);
        rightDownPanel.add(downSplit, BorderLayout.CENTER);
        rightSplitPane.add(rightDownPanel, BorderLayout.SOUTH);

        return rightSplitPane;
    }

    @Override
    protected void loadSavedData() {
        // 加载SQL payload
        List<SqlBean> sqlList = getSqlListsByType("payload");
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

        // 复选框事件
        passiveScanCheckBox.addActionListener(e -> isPassiveScan = passiveScanCheckBox.isSelected());
        deleteOriginalValueCheckBox.addActionListener(e -> isDeleteOrgin = deleteOriginalValueCheckBox.isSelected());
        checkCookieCheckBox.addActionListener(e -> isCheckCookie = checkCookieCheckBox.isSelected());
        checkHeaderCheckBox.addActionListener(e -> isCheckHeader = checkHeaderCheckBox.isSelected());
        checkWhiteListCheckBox.addActionListener(e -> isWhiteDomain = checkWhiteListCheckBox.isSelected());
        urlEncodeCheckBox.addActionListener(e -> isUrlEncode = urlEncodeCheckBox.isSelected());
        booleanBlindCheckBox.addActionListener(e -> isBooleanBlind = booleanBlindCheckBox.isSelected());

        // 按钮事件
        refreshTableButton.addActionListener(e -> {
            resultTable.updateUI();
            payloadtable.updateUI();
        });
        clearTableButton.addActionListener(e -> {
            urlPayloadMapping.clear();
            urlIdCounter.set(0);
            urldata.clear();
            payloaddata.clear();
            payloaddata2.clear();
            vul.clear();
            UrlCacheUtil.resetCache("sqli");
            requestEditor.setMessage(new byte[0], true);
            responseEditor.setMessage(new byte[0], false);
            resultTable.updateUI();
            payloadtable.updateUI();
        });

        saveSqlPayloadButton.addActionListener(e -> saveTextAreaContent(sqlPayloadTextArea, "payload", SqlBean::new));
        saveHeaderListButton.addActionListener(e -> saveTextAreaContent(headerTextArea, "header", SqlBean::new));
        saveWhiteListButton.addActionListener(e -> saveTextAreaContent(whiteListTextArea, "domain", SqlBean::new));

        saveSqlErrorKeyButton.addActionListener(e -> {
            deleteSqlByType("sqlErrorKey");
            saveTextAreaContent(sqlErrorKeyTextArea, "sqlErrorKey", SqlBean::new);
            listErrorKey.clear();
            getSqlListsByType("sqlErrorKey").forEach(b -> listErrorKey.add(b.getValue()));
            sqlErrorKeyTextArea.updateUI();
            showSaveSuccess();
        });
    }

    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
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
        if ("payload".equals(type)) sqliPayload = getSqlListsByType("payload");
        if ("header".equals(type)) headerList = getSqlListsByType("header");
        if ("domain".equals(type)) {
            domainList.clear();
            getSqlListsByType("domain").forEach(b -> domainList.add(b.getValue()));
        }
        textArea.updateUI();
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
            return urldata.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
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
            return payloaddata.size();
        }

        @Override
        public int getColumnCount() {
            return 7;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
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
            int modelRow = rowIndex;
            if (getRowSorter() != null) {
                modelRow = convertRowIndexToModel(rowIndex);
            }

            SqlUIEntry logEntry = urldata.get(modelRow);
            int select_id = logEntry.id;
            payloaddata.clear();
            for (SqlPayloadEntry payloadEntry : payloaddata2) {
                if (payloadEntry.selectId == select_id) {
                    payloaddata.add(payloadEntry);
                }
            }
            payloadtable.updateUI();


            model.fireTableRowsInserted(payloaddata.size(), payloaddata.size());
            model.fireTableDataChanged();
            requestEditor.setMessage(logEntry.requestResponse.getRequest(), true);
            if (logEntry.requestResponse.getResponse() == null) {
                responseEditor.setMessage(new byte[0], false);
            } else {
                responseEditor.setMessage(logEntry.requestResponse.getResponse(), false);
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

            SqlPayloadEntry dataEntry = payloaddata.get(rowIndex);
            requestEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            if (dataEntry.requestResponse.getResponse() == null) {
                responseEditor.setMessage(new byte[0], false);
            } else {
                responseEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            }
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

}

