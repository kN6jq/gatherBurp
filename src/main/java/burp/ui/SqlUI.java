package burp.ui;

import burp.*;
import burp.bean.SqlBean;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
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
public class SqlUI implements UIHandler, IMessageEditorController, IHttpListener {
    private IHttpRequestResponse currentlyDisplayedItem; // 请求响应
    private JPanel panel; // 主面板
    private static JTable urltable; // url 表格
    private static JTable payloadtable; // payload 表格
    private JTabbedPane tabbedPanereq; // 左下的请求
    private JTabbedPane tabbedPaneresp; // 左下的响应
    private JScrollPane urltablescrollpane; // url 表格滚动
    private JScrollPane payloadtablescrollpane; // payload 表格滚动
    private JCheckBox passiveScanCheckBox; // 被动扫描选择框
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
    private IMessageEditor HRequestTextEditor; // 请求
    private IMessageEditor HResponseTextEditor; // 响应
    private static final List<UrlEntry> urldata = new ArrayList<>();  // urldata
    private static final List<PayloadEntry> payloaddata = new ArrayList<>(); // payload
    private static final List<PayloadEntry> payloaddata2 = new ArrayList<>(); // payload
    public AbstractTableModel model = new PayloadModel(); // payload 模型
    private static boolean isPassiveScan; // 是否被动扫描
    private static boolean isCheckCookie; // 是否检测cookie
    private static boolean isCheckHeader; // 是否检测header
    private static boolean isWhiteDomain; // 是否白名单域名
    private static boolean isDeleteOrgin; // 是否删除原始值
    private static boolean isUrlEncode; // 是否进行URL编码
    private static final Set<String> urlHashList = new HashSet<>(); // 存放url的hash值
    private static List<String> listErrorKey = new ArrayList<>(); // // 存放错误key
    private static List<SqlBean> sqliPayload = new ArrayList<>(); // 存放sql关键字
    private static List<String> domainList = new ArrayList<>(); // 存放域名白名单
    private static List<SqlBean> headerList = new ArrayList<>(); // 存放header白名单
    private static ConcurrentHashMap<Integer, StringBuilder> vul = new ConcurrentHashMap<>();// 防止插入重复
    private JCheckBox booleanBlindCheckBox; // 布尔盲注选择框
    private static boolean isBooleanBlind;  // 是否进行布尔盲注
    private static final ConcurrentHashMap<Integer, List<PayloadEntry>> urlPayloadMapping = new ConcurrentHashMap<>();
    private static final AtomicInteger urlIdCounter = new AtomicInteger(0);
    private static final String[] rules = {
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

    // sql检测核心方法
    public static void Check(IHttpRequestResponse[] requestResponses, boolean isSend) {
        // 常规初始化流程代码
        IHttpRequestResponse baseRequestResponse = requestResponses[0]; // 获取第一个请求
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse); // 获取请求
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders(); // 获取请求头
        String host = baseRequestResponse.getHttpService().getHost(); // 获取域名
        String method = analyzeRequest.getMethod(); // 获取请求方法
        URL rdurlURL = analyzeRequest.getUrl(); // 获取请求url
        String url = analyzeRequest.getUrl().toString(); // 获取请求url
        List<IParameter> paraLists = analyzeRequest.getParameters(); // 获取参数列表

        // 如果method不是get或者post方式直接返回
        if (!method.equals("GET") && !method.equals("POST")) {
            return;
        }
        // url 中匹配为静态资源
        if (Utils.isUrlBlackListSuffix(url)) {
            return;
        }

        // 判断参数类型，不符合的直接跳过检测
        boolean ruleHit = true; // 默认设置为true，表示命中规则
        for (IParameter para : paraLists) {
            if ((para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON)
                    || isCheckCookie || isCheckHeader) {
                ruleHit = false; // 如果有 URL、BODY、JSON 参数或者开启了 cookie 或 header 检测，则不命中规则
                break;
            }
        }
        if (ruleHit) {
            return; // 如果命中规则，则直接返回
        }


        // 如果不是手动发送的请求，检测url是否重复及域名是否匹配
        if (!isSend) {
            if (!UrlCacheUtil.checkUrlUnique("sqli", method, rdurlURL, paraLists)) {
                return;
            }
            if (isWhiteDomain) {
                // 如果未匹配到 直接返回
                if (!Utils.isMatchDomainName(host, domainList)) {
                    return;
                }
            }
        }


        // 将原始流量数据包发送一次,用来做后面的对比
        byte[] request = baseRequestResponse.getRequest();
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] body = Arrays.copyOfRange(request, bodyOffset, request.length);
        byte[] postMessage = Utils.helpers.buildHttpMessage(reqheaders, body);
        IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
        byte[] responseBody = originalRequestResponse.getResponse();
        IResponseInfo originalReqResponse = null;
        // 如果有返回,尝试拿到Content-Length
        int originalLength = 0;
        if (responseBody != null) {
            originalReqResponse = Utils.helpers.analyzeResponse(responseBody);
            List<String> sqlHeaders = originalReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                originalLength = Integer.parseInt(contentLength);
            } else {
                originalLength = Integer.parseInt(String.valueOf(responseBody.length));
            }
        }
        // 如果原始包没有返回数据或者响应状态为404 直接return
        if (originalLength == 0 || originalReqResponse.getStatusCode() == 404) {
            return;
        }

        // 尝试添加一个url到url表格
        int logid = addUrl(method, url, originalLength, baseRequestResponse);
        addToVulStr(logid, "检测完成");
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
                            addToVulStr(logid, jsonParam + " 可能存在盲注");
                            try {
                                IScanIssue issues = new CustomScanIssue(
                                        jsonRequestResponse.getHttpService(),
                                        new URL(url),
                                        new IHttpRequestResponse[]{jsonRequestResponse, singleQuoteResponse, doubleQuoteResponse},
                                        "SqlInject Blind",
                                        String.format("在JSON参数 %s 中发现SQL盲注\n原始长度: %d\n单引号长度: %d\n双引号长度: %d",
                                                jsonParam, jsonResponseLength, singleQuoteBody.length(), doubleQuoteBody.length()),
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
                        if (errSqlCheck(singleQuoteBody)) {
                            singleQuoteErrKey = "存在报错";
                            addToVulStr(logid, jsonParam + " 存在报错");
                            try {
                                IScanIssue issues = new CustomScanIssue(
                                        singleQuoteResponse.getHttpService(),
                                        new URL(url),
                                        new IHttpRequestResponse[]{singleQuoteResponse},
                                        "SqlInject Error",
                                        "在JSON参数 " + jsonParam + " 发现SQL报错注入",
                                        "High",
                                        "Certain"
                                );
                                Utils.callbacks.addScanIssue(issues);
                            } catch (MalformedURLException e) {
                                throw new RuntimeException("CheckJsonError" + e);
                            }
                        }

                        // 为双单引号payload添加记录
                        String doubleQuoteErrKey = "x";
                        // 检查报错
                        if (errSqlCheck(doubleQuoteBody)) {
                            doubleQuoteErrKey = "存在报错";
                            addToVulStr(logid, jsonParam + " 存在报错");
                            try {
                                IScanIssue issues = new CustomScanIssue(
                                        doubleQuoteResponse.getHttpService(),
                                        new URL(url),
                                        new IHttpRequestResponse[]{doubleQuoteResponse},
                                        "SqlInject Error",
                                        "在JSON参数 " + jsonParam + " 发现SQL报错注入",
                                        "High",
                                        "Certain"
                                );
                                Utils.callbacks.addScanIssue(issues);
                            } catch (MalformedURLException e) {
                                throw new RuntimeException("CheckJsonError" + e);
                            }
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
                            if (errSqlCheck(payloadBody)) {
                                errkey = "存在报错";
                                addToVulStr(logid, jsonParam + " 存在报错");
                                try {
                                    IScanIssue issues = new CustomScanIssue(payloadResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{payloadResponse}, "SqlInject Error", "在JSON参数 " + jsonParam + " 发现SQL报错注入", "High", "Certain");
                                    Utils.callbacks.addScanIssue(issues);
                                } catch (MalformedURLException e) {
                                    throw new RuntimeException("CheckJsonError" + e);
                                }
                            }

                            // 检查延时注入
                            if (responseTime > 6000) {
                                errkey = "存在延时";
                                addToVulStr(logid, jsonParam + " 存在延时注入");
                                try {
                                    IScanIssue issues = new CustomScanIssue(payloadResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{payloadResponse}, "SqlInject Time", "在JSON参数 " + jsonParam + " 发现延时注入", "High", "Certain");
                                    Utils.callbacks.addScanIssue(issues);
                                } catch (MalformedURLException e) {
                                    throw new RuntimeException("CheckJsonTime" + e);
                                }
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
                        int sqlLength = 0;
                        if (sqlresponseBody != null) {
                            // 判断有无Content-Length字段
                            List<String> sqlHeaders = analyzeResponse.getHeaders();
                            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
                            if (contentLength != null) {
                                sqlLength = Integer.parseInt(contentLength);
                            } else {
                                sqlLength = sqlresponseBody.length;
                            }
                            // 判断body中是否有errorkey关键字
                            String sqlResponseBody = new String(sqlresponseBody);
                            if (errSqlCheck(sqlResponseBody)) {
                                errkey = "存在报错";
                                addToVulStr(logid, "参数" + paraName + "cookie存在报错");
                                try {
                                    IScanIssue issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse}, "SqlInject Error", "SqlInject 发现报错", "High", "Certain");
                                    Utils.callbacks.addScanIssue(issues);
                                } catch (MalformedURLException e) {
                                    throw new RuntimeException("CheckCookie" + e);
                                }
                            }
                            if (Integer.parseInt(responseTime) > 6000) {
                                addToVulStr(logid, "参数" + paraName + "cookie存在延时");
                                errkey = "cookie存在延时";
                                try {
                                    IScanIssue issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse}, "SqlInject Time", "SqlInject 发现延时注入", "High", "Certain");
                                    Utils.callbacks.addScanIssue(issues);
                                } catch (MalformedURLException e) {
                                    throw new RuntimeException("CheckCookie" + e);
                                }
                            }
                        }
                        addPayload(logid, paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }
                }
            }
        }
        // 检测header注入
        if (isCheckHeader) {
            // 如果header为空，直接返回
            if (headerList.isEmpty()) {
                return;
            }
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
                                // 判断有无Content-Length字段
                                List<String> sqlHeaders = analyzeResponse.getHeaders();
                                String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
                                if (contentLength != null) {
                                    sqlLength = Integer.parseInt(contentLength);
                                } else {
                                    sqlLength = sqlresponseBody.length;
                                }
                                // 判断body中是否有errorkey关键字
                                String sqlResponseBody = new String(sqlresponseBody);
                                if (errSqlCheck(sqlResponseBody)) {
                                    errkey = "存在报错";
                                    addToVulStr(logid, "header存在报错");
                                    try {
                                        IScanIssue issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse}, "SqlInject Error", "SqlInject 发现报错", "High", "Certain");
                                        Utils.callbacks.addScanIssue(issues);
                                    } catch (MalformedURLException e) {
                                        throw new RuntimeException("CheckHeader" + e);
                                    }
                                }
                                if (Integer.parseInt(responseTime) > 6000) {
                                    addToVulStr(logid, "header存在延时");
                                    try {
                                        IScanIssue issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse}, "SqlInject Time", "SqlInject 发现延时注入", "High", "Certain");
                                        Utils.callbacks.addScanIssue(issues);
                                    } catch (MalformedURLException e) {
                                        throw new RuntimeException("CheckHeader" + e);
                                    }
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
        // 更新数据
        updateUrl(logid, method, url, originalLength, vul.get(logid).toString(), originalRequestResponse);
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
        if (isBooleanBlind){
            // 判断方式1: 基于响应长度变化（考虑动态内容）
            boolean lengthBasedCheck = checkResponseLength(
                    originalResponse, abnormalResponse, normalResponse,
                    originalLength, abnormalLength, normalLength
            );

            // 判断方式2: 基于相似度比对
            boolean similarityBasedCheck = checkResponseSimilarity(
                    originalResponse, abnormalResponse, normalResponse
            );

            return lengthBasedCheck || similarityBasedCheck;
        }else {
            return false;
        }
    }

    // 检查响应长度模式，考虑动态内容
    private static boolean checkResponseLength(String originalResponse, String abnormalResponse, String normalResponse, int originalLength, int abnormalLength, int normalLength) {

        // 获取处理后的响应长度
        int cleanOriginalLength = getCleanResponseLength(originalResponse);
        int cleanAbnormalLength = getCleanResponseLength(abnormalResponse);
        int cleanNormalLength = getCleanResponseLength(normalResponse);

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

    // 获取清理后的响应长度
    private static int getCleanResponseLength(String response) {
        if (response == null || response.isEmpty()) {
            return 0;
        }

        String cleanResponse = response;

        // 1. 移除可能的动态令牌
        cleanResponse = cleanResponse.replaceAll("[a-zA-Z0-9]{32,}", "TOKEN");  // 移除32位以上的随机字符串
        cleanResponse = cleanResponse.replaceAll("token=([^&\\s\"']+)", "token=TOKEN"); // 移除token参数值

        // 2. 移除时间戳相关内容
        cleanResponse = cleanResponse.replaceAll("\\d{10,13}", "TIMESTAMP"); // Unix时间戳
        cleanResponse = cleanResponse.replaceAll("\\d{4}-\\d{2}-\\d{2}[T\\s]\\d{2}:\\d{2}:\\d{2}", "DATETIME"); // 日期时间

        // 3. 移除动态ID和数字
        cleanResponse = cleanResponse.replaceAll("id=\"?\\d+\"?", "id=\"ID\"");

        // 4. 移除CSRF令牌
        cleanResponse = cleanResponse.replaceAll("csrf[^=]+=([^&\\s\"']+)", "csrf=TOKEN");

        // 5. 移除Session相关信息
        cleanResponse = cleanResponse.replaceAll("JSESSIONID=([^;\\s\"']+)", "JSESSIONID=TOKEN");
        cleanResponse = cleanResponse.replaceAll("session[^=]+=([^&\\s\"']+)", "session=TOKEN");

        // 6. 移除随机生成的文件名或路径
        cleanResponse = cleanResponse.replaceAll("/tmp/[^\\s\"']+", "/tmp/FILE");
        cleanResponse = cleanResponse.replaceAll("filename=\"[^\"]+\"", "filename=\"FILE\"");

        // 7. 移除HTML注释中的动态内容
        cleanResponse = cleanResponse.replaceAll("<!--[\\s\\S]*?-->", "");

        // 8. 移除版本号和随机字符串
        cleanResponse = cleanResponse.replaceAll("v\\d+\\.\\d+\\.\\d+", "VERSION");
        cleanResponse = cleanResponse.replaceAll("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "UUID");

        return cleanResponse.length();
    }

    // 检查响应相似度模式
    private static boolean checkResponseSimilarity(String originalResponse, String abnormalResponse, String normalResponse) {

        // 清理响应内容
        String cleanOriginal = cleanResponseForComparison(originalResponse);
        String cleanAbnormal = cleanResponseForComparison(abnormalResponse);
        String cleanNormal = cleanResponseForComparison(normalResponse);

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

    // 清理响应内容用于相似度比对
    private static String cleanResponseForComparison(String response) {
        if (response == null || response.isEmpty()) {
            return "";
        }

        String cleanResponse = response;

        // 1. 移除HTML标签（保留内容）
        cleanResponse = cleanResponse.replaceAll("<[^>]+>", " ");

        // 2. 移除所有动态内容（与getCleanResponseLength相同的处理）
        cleanResponse = cleanResponse.replaceAll("[a-zA-Z0-9]{32,}", "TOKEN");
        cleanResponse = cleanResponse.replaceAll("token=([^&\\s\"']+)", "token=TOKEN");
        // ... [使用与getCleanResponseLength相同的清理规则]

        // 3. 标准化空白字符
        cleanResponse = cleanResponse.replaceAll("\\s+", " ").trim();

        // 4. 转换为小写以忽略大小写差异
        cleanResponse = cleanResponse.toLowerCase();

        return cleanResponse;
    }

    // 存在盲注漏洞
    private static void reportBlindInjection(int logid, String paraName, String url, IHttpRequestResponse requestResponse, String type) {
        addToVulStr(logid, "参数" + paraName + "可能存在" + type + "盲注");

        try {
            IScanIssue issues = new CustomScanIssue(requestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{requestResponse}, "SQL Injection Blind", "发现" + type + "SQL盲注", "High", "Certain");
            Utils.callbacks.addScanIssue(issues);
        } catch (MalformedURLException e) {
            throw new RuntimeException("CheckBlind: " + e);
        }
    }

    // 更新url数据到表格
    public static void updateUrl(int index, String method, String url, int length, String message, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            if (index >= 0 && index < urldata.size()) {
                urldata.set(index, new UrlEntry(index, method, url, length, message, requestResponse));
            }
            urltable.updateUI();
            payloadtable.updateUI();
        }
    }

    // 检查参数是否为整数类型
    private static boolean isIntegerParameter(String value) {
        // 空值检查
        if (value == null || value.trim().isEmpty()) {
            return false;
        }

        // 检查是否为纯数字
        if (!value.matches("^-?\\d+$")) {
            return false;
        }

        try {
            // 尝试转换为整数
            Integer.parseInt(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    // 正则判断响应数据包中是否包含报错关键字 @href https://github.com/saoshao/DetSql/blob/master/src/main/java/DetSql/MyHttpHandler.java
    private static boolean errSqlCheck(String responseBody) {
        if (!listErrorKey.isEmpty()) {
            for (String errKey : listErrorKey) {
                if (responseBody.contains(errKey)) {
                    return true;
                }
            }
        }

        String cleanedText = responseBody.replaceAll("\\n|\\r|\\r\\n", "");
        for (String rule : rules) {
            Pattern pattern = Pattern.compile(rule, Pattern.CASE_INSENSITIVE);
            if (pattern.matcher(cleanedText).find()) {
                return true;
            }
        }
        return false;
    }

    // 获取响应包的响应体内容
    private static String getResponseBody(IHttpRequestResponse requestResponse) {
        if (requestResponse == null || requestResponse.getResponse() == null) {
            return "";
        }
        byte[] response = requestResponse.getResponse();
        IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response);
        int bodyOffset = responseInfo.getBodyOffset();

        return new String(Arrays.copyOfRange(response, bodyOffset, response.length));
    }

    // 添加url数据到表格
    public static int addUrl(String method, String url, int length, IHttpRequestResponse requestResponse) {
        int id = urlIdCounter.getAndIncrement();
        UrlEntry entry = new UrlEntry(id, method, url, length, "正在检测", requestResponse);
        urlPayloadMapping.put(id, Collections.synchronizedList(new ArrayList<>()));

        SwingUtilities.invokeLater(() -> {
            urldata.add(entry);
            urltable.updateUI();
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
        PayloadEntry entry = new PayloadEntry(selectId, key, value, length, change, errkey, time, status, requestResponse);
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
        String responseTimes = String.valueOf(endTime - startTime);


        // 获取响应数据
        byte[] responseBody = newRequestResponses.getResponse();
        if (responseBody != null) {
            // 分析响应
            IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(responseBody);
            int statusCode = analyzeResponse.getStatusCode();

            // 获取响应长度
            int length;
            List<String> headers = analyzeResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(headers, "Content-Length");
            if (contentLength != null) {
                length = Integer.parseInt(contentLength);
            } else {
                length = responseBody.length;
            }

            // 检查SQL错误
            String responseBodyStr = new String(responseBody);
            if (errSqlCheck(responseBodyStr)) {
                errkey = "存在报错";
                addToVulStr(logid, "参数" + paraName + "存在报错");

                try {
                    IScanIssue errIssues = new CustomScanIssue(newRequestResponses.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponses}, "SqlInject Error", "SqlInject 发现报错", "High", "Certain");
                    Utils.callbacks.addScanIssue(errIssues);
                } catch (Exception e) {
                    Utils.stderr.println("CustomScanIssue " + e);
                }
            }
            // 常规的检测不存在延时的
//            if (Integer.parseInt(responseTimes) > 6000) {
//                errkey = "存在延时";
//                addToVulStr(logid, "参数" + paraName + "存在延时");
//                try {
//                    IScanIssue timeIssues = new CustomScanIssue(newRequestResponses.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponses}, "SqlInject Time", "SqlInject 发现延时注入", "High", "Certain");
//                    Utils.callbacks.addScanIssue(timeIssues);
//                } catch (MalformedURLException e) {
//                    throw new RuntimeException("CheckRaw" + e);
//                }
//            }

            // 记录payload结果
            addPayload(logid, paraName, payload, length, String.valueOf(length - originalLength), errkey, String.valueOf(endTime - startTime), String.valueOf(statusCode), newRequestResponses);
        }

        return newRequestResponses;
    }


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (isPassiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            synchronized (urldata) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Check(new IHttpRequestResponse[]{iHttpRequestResponse}, false);
                    }
                });
                thread.start();
            }
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public void init() {
        // 获取所有报错关键字
        List<SqlBean> sqlErrorKey = getSqlListsByType("sqlErrorKey");
        for (SqlBean sqlBean : sqlErrorKey) {
            listErrorKey.add(sqlBean.getValue());
        }

        // 获取所有payload
        sqliPayload = getSqlListsByType("payload");

        List<SqlBean> domain = getSqlListsByType("domain");
        // 将domain转为List<String>
        domainList = new ArrayList<>();
        for (SqlBean sqlBean : domain) {
            domainList.add(sqlBean.getValue());
        }

        // 获取数据库中的header
        headerList = getSqlListsByType("header");

        setupUI();
        setupData();
    }

    private void setupData() {
        // 盲注检查
        booleanBlindCheckBox.addActionListener(e -> isBooleanBlind = booleanBlindCheckBox.isSelected());

        refreshTableButton.addActionListener(e -> {
            urltable.updateUI();
            payloadtable.updateUI();
        });
        clearTableButton.addActionListener(e -> {
            urlPayloadMapping.clear();
            urlIdCounter.set(0);
            urldata.clear();
            payloaddata.clear();
            payloaddata2.clear();
            vul.clear();
            HRequestTextEditor.setMessage(new byte[0], true);
            HResponseTextEditor.setMessage(new byte[0], false);
            urltable.updateUI();
            payloadtable.updateUI();
        });
        // 保存sql payload
        saveSqlPayloadButton.addActionListener(e -> {
            String sqleditorPane1Text = sqlPayloadTextArea.getText();
            deleteSqlByType("payload");
            // 清空内存中的sqliPayload列表
            sqliPayload.clear();
            // 如果包含换行符，就分割成多个payload
            if (sqleditorPane1Text.contains("\n")) {
                String[] payloads = sqleditorPane1Text.split("\n");
                for (String payload : payloads) {
                    if (payload.isEmpty()) {
                        continue;
                    }
                    SqlBean sqlBean = new SqlBean("payload", payload);
                    saveSql(sqlBean);
                }
            } else {
                if (sqleditorPane1Text.isEmpty()) {
                    return;
                }
                SqlBean sqlBean = new SqlBean("payload", sqleditorPane1Text);
                saveSql(sqlBean);
            }
            // 获取所有payload
            sqliPayload = getSqlListsByType("payload");
            sqlPayloadTextArea.updateUI();
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        // 保存header
        saveHeaderListButton.addActionListener(e -> {
            String headerTextAreaText = headerTextArea.getText();
            deleteSqlByType("header");
            // 如果包含换行符，就分割成多个header
            if (headerTextAreaText.contains("\n")) {
                String[] headers = headerTextAreaText.split("\n");
                for (String header : headers) {
                    if (header.isEmpty()) {
                        continue;
                    }
                    SqlBean sqlBean = new SqlBean("header", header);
                    saveSql(sqlBean);
                }
            } else {
                if (headerTextAreaText.isEmpty()) {
                    return;
                }
                SqlBean sqlBean = new SqlBean("header", headerTextAreaText);
                saveSql(sqlBean);
            }
            // 获取数据库中的header
            headerList = getSqlListsByType("header");
            headerTextArea.updateUI();
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        // 保存白名单域名
        saveWhiteListButton.addActionListener(e -> {
            String whiteListTextAreaText = whiteListTextArea.getText();
            deleteSqlByType("domain");
            // 如果包含换行符，就分割成多个domain
            if (whiteListTextAreaText.contains("\n")) {
                String[] whitedomains = whiteListTextAreaText.split("\n");
                for (String whitedomain : whitedomains) {
                    if (whitedomain.isEmpty()) {
                        continue;
                    }
                    SqlBean sqlBean = new SqlBean("domain", whitedomain);
                    saveSql(sqlBean);
                }
            } else {
                if (whiteListTextAreaText.isEmpty()) {
                    return;
                }
                SqlBean sqlBean = new SqlBean("domain", whiteListTextAreaText);
                saveSql(sqlBean);
            }
            List<SqlBean> domain = getSqlListsByType("domain");
            // 将domain转为List<String>
            for (SqlBean sqlBean : domain) {
                domainList.add(sqlBean.getValue());
            }
            whiteListTextArea.updateUI();
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        saveSqlErrorKeyButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                deleteSqlByType("sqlErrorKey");
                String sqlErrorKeyTextAreaText = sqlErrorKeyTextArea.getText();
                // 如果包含换行符，就分割成多个errorkey
                if (sqlErrorKeyTextAreaText.contains("\n")) {
                    String[] errkeys = sqlErrorKeyTextAreaText.split("\n");
                    for (String errkey : errkeys) {
                        if (errkey.isEmpty()) {
                            continue;
                        }
                        SqlBean sqlBean = new SqlBean("sqlErrorKey", errkey);
                        saveSql(sqlBean);
                    }
                } else {
                    if (sqlErrorKeyTextAreaText.isEmpty()) {
                        return;
                    }
                    SqlBean sqlBean = new SqlBean("sqlErrorKey", sqlErrorKeyTextAreaText);
                    saveSql(sqlBean);
                }
                // 获取所有报错关键字
                List<SqlBean> sqlErrorKey = getSqlListsByType("sqlErrorKey");
                for (SqlBean sqlBean : sqlErrorKey) {
                    listErrorKey.add(sqlBean.getValue());
                }
                sqlErrorKeyTextArea.updateUI();
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        // 被动扫描选择框事件
        passiveScanCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (passiveScanCheckBox.isSelected()) {
                    isPassiveScan = true;
                } else {
                    isPassiveScan = false;
                }
            }
        });
        // 删除原始值选择框事件
        deleteOriginalValueCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (deleteOriginalValueCheckBox.isSelected()) {
                    isDeleteOrgin = true;
                } else {
                    isDeleteOrgin = false;
                }
            }
        });
        // 检测cookie选择框事件
        checkCookieCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkCookieCheckBox.isSelected()) {
                    isCheckCookie = true;
                } else {
                    isCheckCookie = false;
                }
            }
        });
        // 检测header选择框事件
        checkHeaderCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkHeaderCheckBox.isSelected()) {
                    isCheckHeader = true;
                } else {
                    isCheckHeader = false;
                }
            }
        });
        // 白名单域名检测选择框事件
        checkWhiteListCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkWhiteListCheckBox.isSelected()) {
                    isWhiteDomain = true;
                } else {
                    isWhiteDomain = false;
                }
            }
        });
        // isUrlEncode
        urlEncodeCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (urlEncodeCheckBox.isSelected()) {
                    isUrlEncode = true;
                } else {
                    isUrlEncode = false;
                }
            }
        });
        // 数据库获取payload,输出到面板
        List<SqlBean> sqlList = getSqlListsByType("payload");
        for (SqlBean sqlBean : sqlList) {
            // 如果是最后一个，就不加换行符
            if (sqlList.indexOf(sqlBean) == sqlList.size() - 1) {
                sqlPayloadTextArea.setText(sqlPayloadTextArea.getText() + sqlBean.getValue());
                break;
            }
            sqlPayloadTextArea.setText(sqlPayloadTextArea.getText() + sqlBean.getValue() + "\n");
        }
        // 数据库获取header,输出到面板
        List<SqlBean> header = getSqlListsByType("header");
        for (SqlBean sqlBean : header) {
            // 如果是最后一个，就不加换行符
            if (header.indexOf(sqlBean) == header.size() - 1) {
                headerTextArea.setText(headerTextArea.getText() + sqlBean.getValue());
                break;
            }
            headerTextArea.setText(headerTextArea.getText() + sqlBean.getValue() + "\n");
        }
        // 数据库获取白名单域名,输出到面板
        List<SqlBean> domains = getSqlListsByType("domain");
        for (SqlBean sqlBean : domains) {
            // 如果是最后一个，就不加换行符
            if (domains.indexOf(sqlBean) == domains.size() - 1) {
                whiteListTextArea.setText(whiteListTextArea.getText() + sqlBean.getValue());
                break;
            }
            whiteListTextArea.setText(whiteListTextArea.getText() + sqlBean.getValue() + "\n");
        }
        // sqlErrorKeyTextArea
        List<SqlBean> sqlErrorKey = getSqlListsByType("sqlErrorKey");
        for (SqlBean sqlBean : sqlErrorKey) {
            // 如果是最后一个，就不加换行符
            if (sqlErrorKey.indexOf(sqlBean) == sqlErrorKey.size() - 1) {
                sqlErrorKeyTextArea.setText(sqlErrorKeyTextArea.getText() + sqlBean.getValue());
                break;
            }
            sqlErrorKeyTextArea.setText(sqlErrorKeyTextArea.getText() + sqlBean.getValue() + "\n");
        }
    }

    private void setupUI() {
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);
        panel = new JPanel();
        panel.setLayout(new BorderLayout());

        // 左边的面板
        // 左边的上下分割 上部分和下部分占比6:4
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.6);
        leftSplitPane.setDividerLocation(0.6);

        // 左边的上部分左右对称分割
        JSplitPane zsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        zsSplitPane.setResizeWeight(0.5);
        zsSplitPane.setDividerLocation(0.5);
        // 添加到leftSplitPane
        // 左右对称分割面板

        // 添加到zsSplitPane
        urltablescrollpane = new JScrollPane();
        zsSplitPane.setLeftComponent(urltablescrollpane);
        UrlModel urlModel = new UrlModel();
        urltable = new URLTable(urlModel);
        urltablescrollpane.setViewportView(urltable);


        // 创建一个自定义的单元格渲染器
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                label.setHorizontalAlignment(JLabel.CENTER);
                label.setHorizontalTextPosition(JLabel.CENTER);
                label.setIconTextGap(0);
                label.setMaximumSize(new Dimension(Integer.MAX_VALUE, label.getPreferredSize().height));
                label.setToolTipText((String) value); // 设置鼠标悬停时显示的提示文本
                return label;
            }
        };
        // 表格渲染
        urltable.getColumnModel().getColumn(4).setCellRenderer(renderer);


        payloadtablescrollpane = new JScrollPane();
        zsSplitPane.setRightComponent(payloadtablescrollpane);
        PayloadModel payloadModel = new PayloadModel();
        payloadtable = new PayloadTable(payloadModel);
        payloadtablescrollpane.setViewportView(payloadtable);

        // 表格渲染
        payloadtable.getColumnModel().getColumn(0).setCellRenderer(renderer);

        // 左边的下部分左右对称分割
        JSplitPane zxSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        zxSplitPane.setResizeWeight(0.5);
        zxSplitPane.setDividerLocation(0.5);
        // 添加到leftSplitPane下面
        HRequestTextEditor = Utils.callbacks.createMessageEditor(SqlUI.this, true);
        HResponseTextEditor = Utils.callbacks.createMessageEditor(SqlUI.this, false);
        tabbedPanereq = new JTabbedPane();
        tabbedPanereq.addTab("请求", HRequestTextEditor.getComponent());
        tabbedPaneresp = new JTabbedPane();
        tabbedPaneresp.addTab("响应", HResponseTextEditor.getComponent());
        zxSplitPane.setLeftComponent(tabbedPanereq);
        zxSplitPane.setRightComponent(tabbedPaneresp);

        leftSplitPane.setLeftComponent(zsSplitPane);
        leftSplitPane.setRightComponent(zxSplitPane);


        // 右边的上下按7:3分割
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplitPane.setResizeWeight(0.7);
        rightSplitPane.setDividerLocation(0.7);


        // 右边的上部分
        // 添加被动扫描选择框
        passiveScanCheckBox = new JCheckBox("被动扫描");
        // 添加删除原始值选择框
        deleteOriginalValueCheckBox = new JCheckBox("删除原始值");
        // 添加检测cookie选择框
        checkCookieCheckBox = new JCheckBox("检测cookie");
        // 添加检测header选择框
        checkHeaderCheckBox = new JCheckBox("检测header");
        // 添加白名单域名检测选择框
        checkWhiteListCheckBox = new JCheckBox("白名单域名检测");
        urlEncodeCheckBox = new JCheckBox("url编码");
        // 白名单域名保存按钮
        saveWhiteListButton = new JButton("保存白名单域名");
        // 保存header按钮
        saveHeaderListButton = new JButton("保存header");
        // 白名单域名输入框列表
        whiteListTextArea = new JTextArea(5, 10);
        whiteListTextArea.setLineWrap(false); // 自动换行
        whiteListTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane whiteListTextAreascrollPane = new JScrollPane(whiteListTextArea);

        // header检测数据框列表
        headerTextArea = new JTextArea(5, 10);
        headerTextArea.setLineWrap(true); // 自动换行
        headerTextArea.setWrapStyleWord(true); // 按单词换行
        JScrollPane headerTextAreascrollPane = new JScrollPane(headerTextArea);
        // 刷新表格按钮
        refreshTableButton = new JButton("刷新表格");
        // 清空表格按钮
        clearTableButton = new JButton("清空表格");
        // 白名单域名label
        JLabel whiteDomainListLabel = new JLabel("白名单域名");
        // 检测header label
        JLabel headerLabel = new JLabel("header检测列表");

        booleanBlindCheckBox = new JCheckBox("布尔盲注");
        // 添加到右边的上部分
        JPanel rightTopPanel = new JPanel();
        rightTopPanel.setLayout(new GridBagLayout());
        rightTopPanel.add(passiveScanCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(deleteOriginalValueCheckBox, new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkCookieCheckBox, new GridBagConstraintsHelper(2, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkHeaderCheckBox, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkWhiteListCheckBox, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(urlEncodeCheckBox, new GridBagConstraintsHelper(2, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(booleanBlindCheckBox, new GridBagConstraintsHelper(2, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveWhiteListButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(saveHeaderListButton, new GridBagConstraintsHelper(1, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteDomainListLabel, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(whiteListTextAreascrollPane, new GridBagConstraintsHelper(0, 4, 3, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightTopPanel.add(headerLabel, new GridBagConstraintsHelper(0, 5, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(headerTextAreascrollPane, new GridBagConstraintsHelper(0, 6, 3, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightTopPanel.add(refreshTableButton, new GridBagConstraintsHelper(0, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(clearTableButton, new GridBagConstraintsHelper(1, 7, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        rightSplitPane.setTopComponent(rightTopPanel);


        // 右边的下部分左边
        // sql payload label
        JLabel sqlPayloadLabel = new JLabel("sql payload");
        // sqlpayload输入框
        // sqlpayload保存按钮
        sqlPayloadTextArea = new JTextArea(5, 10);
        sqlPayloadTextArea.setLineWrap(false); // 自动换行
        sqlPayloadTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane sqlPayloadTextAreascrollPane = new JScrollPane(sqlPayloadTextArea);

        saveSqlPayloadButton = new JButton("保存sql payload");
        JPanel rightDownLeftPanel = new JPanel();
        rightDownLeftPanel.setLayout(new BorderLayout());
        rightDownLeftPanel.add(sqlPayloadLabel, BorderLayout.NORTH);
        rightDownLeftPanel.add(sqlPayloadTextAreascrollPane, BorderLayout.CENTER);
        rightDownLeftPanel.add(saveSqlPayloadButton, BorderLayout.SOUTH);
        // 右边的下部分左边
        JLabel sqlErrKey = new JLabel("sql error key");
        sqlErrorKeyTextArea = new JTextArea(5, 10);
        sqlErrorKeyTextArea.setLineWrap(false); // 自动换行
        sqlErrorKeyTextArea.setWrapStyleWord(false); // 按单词换行
        JScrollPane sqlErrorKeyTextAreascrollPane = new JScrollPane(sqlErrorKeyTextArea);
        saveSqlErrorKeyButton = new JButton("保存sql error key");
        JPanel rightDownRightPanel = new JPanel();
        rightDownRightPanel.setLayout(new BorderLayout());
        rightDownRightPanel.add(sqlErrKey, BorderLayout.NORTH);
        rightDownRightPanel.add(sqlErrorKeyTextAreascrollPane, BorderLayout.CENTER);
        rightDownRightPanel.add(saveSqlErrorKeyButton, BorderLayout.SOUTH);
        // 左右分割面板添加rightDownLeftPanel和rightDownRightPanel
        JSplitPane rightDownPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightDownPanel.setResizeWeight(0.5);
        rightDownPanel.setDividerLocation(0.5);
        rightDownPanel.setTopComponent(rightDownLeftPanel);
        rightDownPanel.setBottomComponent(rightDownRightPanel);
        rightSplitPane.setBottomComponent(rightDownPanel);

        panel.add(leftSplitPane, BorderLayout.CENTER);
        panel.add(rightSplitPane, BorderLayout.EAST);

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "SqlInject";
    }

    // url 实体类
    public static class UrlEntry {
        final int id;
        final String method;
        final String url;
        final int length;
        final String status;
        final IHttpRequestResponse requestResponse;

        UrlEntry(int id, String method, String url, int length, String status, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.length = length;
            this.status = status;
            this.requestResponse = requestResponse;
        }
    }

    // payload 实体类
    public static class PayloadEntry {
        final int selectId;
        final String key;
        final String value;
        final int length;
        final String change;
        final String errkey;
        final String time;
        final String status;
        final IHttpRequestResponse requestResponse;

        PayloadEntry(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
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
    static class UrlModel extends AbstractTableModel {

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
                    return "id";
                case 1:
                    return "method";
                case 2:
                    return "url";
                case 3:
                    return "length";
                case 4:
                    return "status";
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
    static class PayloadModel extends AbstractTableModel {

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
                    return "参数";
                case 1:
                    return "参数值";
                case 2:
                    return "响应长度";
                case 3:
                    return "变化";
                case 4:
                    return "报错";
                case 5:
                    return "时间";
                case 6:
                    return "返回码";
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
            
            UrlEntry logEntry = urldata.get(modelRow);
            int select_id = logEntry.id;
            payloaddata.clear();
            for (PayloadEntry payloadEntry : payloaddata2) {
                if (payloadEntry.selectId == select_id) {
                    payloaddata.add(payloadEntry);
                }
            }
            payloadtable.updateUI();


            model.fireTableRowsInserted(payloaddata.size(), payloaddata.size());
            model.fireTableDataChanged();
            HRequestTextEditor.setMessage(logEntry.requestResponse.getRequest(), true);
            if (logEntry.requestResponse.getResponse() == null) {
                HResponseTextEditor.setMessage(new byte[0], false);
            } else {
                HResponseTextEditor.setMessage(logEntry.requestResponse.getResponse(), false);
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

            PayloadEntry dataEntry = payloaddata.get(rowIndex);
            HRequestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            if (dataEntry.requestResponse.getResponse() == null) {
                HResponseTextEditor.setMessage(new byte[0], false);
            } else {
                HResponseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            }
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

}