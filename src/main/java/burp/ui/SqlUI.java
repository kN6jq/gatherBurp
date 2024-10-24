package burp.ui;

import burp.*;
import burp.bean.SqlBean;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.CustomScanIssue;
import burp.utils.JsonProcessorUtil;
import burp.utils.JsonUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import org.springframework.util.DigestUtils;
import org.xm.similarity.text.EditDistanceSimilarity;
import org.xm.similarity.text.TextSimilarity;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
    private static final List<String> parameterList = new ArrayList<>(); // 去重参数列表
    private static final List<String> urlHashList = new ArrayList<>(); // 存放url的hash值
    private static String similarity1 = ""; // 一个单引号相似度
    private static String similarity2 = ""; // 两个单引号相似度
    private static String similarity3 = ""; // 三个单引号相似度
    private static List<String> listErrorKey = new ArrayList<>(); // // 存放错误key
    private static List<SqlBean> sqliPayload = new ArrayList<>(); // 存放sql关键字
    private static List<String> domainList = new ArrayList<>(); // 存放域名白名单
    private static List<SqlBean> headerList = new ArrayList<>(); // 存放header白名单
    private static ConcurrentHashMap<Integer, StringBuilder> vul = new ConcurrentHashMap<>();// 防止插入重复
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
            "数据库出错"
    };
    // sql检测核心方法
    public static void Check(IHttpRequestResponse[] responses, boolean isSend) {
        // 常规初始化流程代码
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String host = baseRequestResponse.getHttpService().getHost();
        String method = analyzeRequest.getMethod();
        URL rdurlURL = analyzeRequest.getUrl();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();
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

        String rdurl = Utils.getUrlWithoutFilename(rdurlURL);
        // 如果不是手动发送则需要进行url去重
        if (!isSend) {
            // 对url进行hash去重
            for (IParameter paraList : paraLists) {
                String paraName = paraList.getName();
                parameterList.add(paraName);
            }
            if (!checkUrlHash(method + rdurl + parameterList)) {
                return;
            }
        } else {
            isWhiteDomain = false;
        }


        // host 不是白名单域名，直接返回
        if (isWhiteDomain) {
            // 如果未匹配到 直接返回
            if (!Utils.isMatchDomainName(host, domainList)) {
                return;
            }
        }
        // 原始请求包发送一次并记录相关返回数据,用来比对
        byte[] byte_Request = baseRequestResponse.getRequest();
        int bodyOffset = analyzeRequest.getBodyOffset();
        int len = byte_Request.length;
        byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
        byte[] postMessage = Utils.helpers.buildHttpMessage(reqheaders, body);
        IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
        byte[] responseBody = originalRequestResponse.getResponse();
        int originalLength = 0;
        if (responseBody != null) {
            IResponseInfo originalReqResponse = Utils.helpers.analyzeResponse(responseBody);
            List<String> sqlHeaders = originalReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                originalLength = Integer.parseInt(contentLength);
            }
        }
        if (originalLength == 0) {
            assert responseBody != null;
            originalLength = Integer.parseInt(String.valueOf(responseBody.length));
        }
        // 如果原始包没有返回数据,则return
        if (originalLength == 0) {
            return;
        }
        // 原始请求包的返回包
        String sqlOrginBody = new String(responseBody);

        int logid = addUrl(method, url, originalLength, originalRequestResponse);
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
                    // 分别检测单引号、双引号、三引号的检测步骤
                    IHttpRequestResponse checkedSingleQuote = CheckSingleQuote(logid, para, paraName, paraValue, url, originalLength, baseRequestResponse);
                    IHttpRequestResponse checkedDoubleQuote = CheckDoubleQuote(logid, para, paraName, paraValue, url, originalLength, baseRequestResponse);
                    IHttpRequestResponse checkedTripleQuote = CheckTripleQuote(logid, para, paraName, paraValue, url, originalLength, baseRequestResponse);
                    // 网页相似度计算
                    TextSimilarity editSimilarity = new EditDistanceSimilarity();
                    double score2 = editSimilarity.getSimilarity(sqlOrginBody, similarity1);
                    double score3 = editSimilarity.getSimilarity(sqlOrginBody, similarity2);
                    double score4 = editSimilarity.getSimilarity(sqlOrginBody, similarity3);
                    double formattedScore2 = Double.parseDouble(String.format("%.2f", score2));
                    double formattedScore3 = Double.parseDouble(String.format("%.2f", score3));
                    double formattedScore4 = Double.parseDouble(String.format("%.2f", score4));
                    if (checkedSingleQuote.getResponse().length != checkedDoubleQuote.getResponse().length &&
                            checkedDoubleQuote.getResponse().length != checkedTripleQuote.getResponse().length &&
                            checkedSingleQuote.getResponse().length != checkedTripleQuote.getResponse().length) {
                        if (formattedScore2 == formattedScore4 && (formattedScore2 != formattedScore3 || formattedScore3 != formattedScore4)) {
                            addToVulStr(logid, "参数" + paraName + "可能存在盲注");
                            IScanIssue issues = null;
                            try {
                                issues = new CustomScanIssue(checkedDoubleQuote.getHttpService(), new URL(url), new IHttpRequestResponse[]{checkedDoubleQuote},
                                        "SqlInject Blind", "SqlInject 发现可能存在盲注",
                                        "High", "Certain");
                                Utils.callbacks.addScanIssue(issues);
                            } catch (MalformedURLException e) {
                                throw new RuntimeException("CheckBlind" + e);
                            }
                        }
                    }


                    // 正常的检测流程
                    // 使用payload进行检测
                    for (SqlBean sql : sqliPayload) {
                        String errkeys = "x";
                        String payload = "";
                        String sqlPayload = Utils.ReplaceChar(sql.getValue());
                        // 如果sqlPayload是上面的 可以直接跳过
                        if (sqlPayload.equals("'") || sqlPayload.equals("''") || sqlPayload.equals("'''")) {
                            break;
                        }
                        if (sqlPayload.isEmpty()) {
                            break;
                        }
                        // 如果是在get请求中，需要对payload进行url编码
                        if (para.getType() == PARAM_URL) {
                            sqlPayload = Utils.UrlEncode(sqlPayload);
                        }
                        // 是否删除原始的参数值
                        if (isDeleteOrgin) {
                            payload = sqlPayload;
                        } else {
                            payload = paraValue + sqlPayload;
                        }
                        long startTimes4 = System.currentTimeMillis();
                        IParameter iParameters4 = Utils.helpers.buildParameter(paraName, payload, para.getType());
                        byte[] bytess4 = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters4);
                        IHttpRequestResponse newRequestResponses4 = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytess4);
                        // xm17: 考虑服务器被waf了  然后返回时间很长的情况
                        long endTimes4 = System.currentTimeMillis();
                        IResponseInfo analyzeResponses4 = Utils.helpers.analyzeResponse(newRequestResponses4.getResponse());
                        int statusCodes4 = analyzeResponses4.getStatusCode();
                        String responseTimes4 = String.valueOf(endTimes4 - startTimes4);
                        byte[] sqlresponseBodys4 = newRequestResponses4.getResponse();
                        int sqlLengths4 = 0;
                        if (sqlresponseBodys4 != null) {
                            // 判断有无Content-Length字段
                            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBodys4);
                            List<String> sqlHeaders = ReqResponse.getHeaders();
                            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
                            if (contentLength != null) {
                                sqlLengths4 = Integer.parseInt(contentLength);
                            }
                            // 判断body中是否有errorkey关键字
                            String sqlResponseBody = new String(sqlresponseBodys4);
                            if (errSqlCheck(sqlResponseBody)) {
                                errkeys = "存在报错";
                                addToVulStr(logid, "参数" + paraName + "存在报错");
                                IScanIssue issues = null;
                                try {
                                    issues = new CustomScanIssue(newRequestResponses4.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponses4},
                                            "SqlInject Error", "SqlInject 发现报错",
                                            "High", "Certain");
                                    Utils.callbacks.addScanIssue(issues);
                                } catch (MalformedURLException e) {
                                    throw new RuntimeException("CheckRaw" + e);
                                }
                            }
                        }
                        if (sqlLengths4 == 0) {
                            assert sqlresponseBodys4 != null;
                            sqlLengths4 = sqlresponseBodys4.length;
                        }
                        if (Integer.parseInt(responseTimes4) > 6000) {
                            errkeys = "存在延时";
                            addToVulStr(logid, "参数" + paraName + "存在延时");
                            IScanIssue issues = null;
                            try {
                                issues = new CustomScanIssue(newRequestResponses4.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponses4},
                                        "SqlInject Time", "SqlInject 发现延时注入",
                                        "High", "Certain");
                                Utils.callbacks.addScanIssue(issues);
                            } catch (MalformedURLException e) {
                                throw new RuntimeException("CheckRaw" + e);
                            }
                        }
                        addPayload(logid, paraName, payload, sqlLengths4, String.valueOf(sqlLengths4 - originalLength), errkeys, responseTimes4, String.valueOf(statusCodes4), newRequestResponses4);
                    }

                }
                // 检测json类型的注入
                if (para.getType() == PARAM_JSON) {
                    String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                    if (request_data.isEmpty()) {
                        break;
                    } else {
                        List<String> payloads = new ArrayList<>();
                        payloads.add("'");  // 添加初始值
                        for (SqlBean sqlBean : sqliPayload) {
                            payloads.add(sqlBean.getValue());
                        }
                        for (String payload : payloads) {
                            List<JsonProcessorUtil.ProcessResult> processResults = JsonProcessorUtil.processWithPath(request_data, payload, isDeleteOrgin);
                            for (JsonProcessorUtil.ProcessResult result : processResults) {
                                String errkey = "";
                                String jsonParam = result.getParamPath();  // 获取当前JSON参数路径
                                String jsonResult = result.getModifiedJson();
                                long startTime = System.currentTimeMillis();
                                byte[] bytes = Utils.helpers.buildHttpMessage(reqheaders, jsonResult.getBytes());
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                                long endTime = System.currentTimeMillis();
                                IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                                int statusCode = analyzeResponse.getStatusCode();
                                String responseTime = String.valueOf(endTime - startTime);
                                byte[] sqlresponseBody = newRequestResponse.getResponse();
                                int sqlLength = 0;
                                if (sqlresponseBody != null) {
                                    // 判断有无Content-Length字段
                                    IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                                    List<String> sqlHeaders = ReqResponse.getHeaders();
                                    String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
                                    if (contentLength != null) {
                                        sqlLength = Integer.parseInt(contentLength);
                                    }
                                    // 判断body中是否有errorkey关键字
                                    String sqlResponseBody = new String(sqlresponseBody);
                                    if (errSqlCheck(sqlResponseBody)) {
                                        errkey = "存在报错";
                                        addToVulStr(logid, "json存在报错");
                                        IScanIssue issues = null;
                                        try {
                                            issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                                                    "SqlInject Error", "SqlInject 发现报错",
                                                    "High", "Certain");
                                            Utils.callbacks.addScanIssue(issues);
                                        } catch (MalformedURLException e) {
                                            throw new RuntimeException("CheckJsonSingleQuote" + e);
                                        }
                                    }else {
                                        errkey = "x";
                                    }

                                }
                                if (sqlLength == 0) {
                                    assert sqlresponseBody != null;
                                    sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                                }
                                if (Integer.parseInt(responseTime) > 6000) {
                                    addToVulStr(logid, "json存在延时");
                                    IScanIssue issues = null;
                                    try {
                                        issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                                                "SqlInject Time", "SqlInject 发现延时注入",
                                                "High", "Certain");
                                        Utils.callbacks.addScanIssue(issues);
                                    } catch (MalformedURLException e) {
                                        throw new RuntimeException("CheckJsonSingleQuote" + e);
                                    }
                                }
                                addPayload(logid, "json", jsonParam, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);


                            }
                        }
                        break;
                    }
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
                            break;
                        }
                        // 是否删除原始的参数值
                        if (isDeleteOrgin) {
                            payload = sqlPayload;
                        } else {
                            payload = paraValue + sqlPayload;
                        }
                        long startTime = System.currentTimeMillis();
                        IParameter iParameter = Utils.helpers.buildParameter(paraName, payload, para.getType());
                        byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameter);
                        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                        // xm17: todo 考虑服务器被waf了  然后返回时间很长的情况
                        long endTime = System.currentTimeMillis();
                        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                        int statusCode = analyzeResponse.getStatusCode();
                        String responseTime = String.valueOf(endTime - startTime);
                        byte[] sqlresponseBody = newRequestResponse.getResponse();
                        int sqlLength = 0;
                        if (sqlresponseBody != null) {
                            // 判断有无Content-Length字段
                            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                            List<String> sqlHeaders = ReqResponse.getHeaders();
                            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
                            if (contentLength != null) {
                                sqlLength = Integer.parseInt(contentLength);
                            }
                            // 判断body中是否有errorkey关键字
                            String sqlResponseBody = new String(sqlresponseBody);
                            if (errSqlCheck(sqlResponseBody)) {
                                errkey = "存在报错";
                                addToVulStr(logid, "参数" + paraName + "cookie存在报错");
                                IScanIssue issues = null;
                                try {
                                    issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                                            "SqlInject Error", "SqlInject 发现报错",
                                            "High", "Certain");
                                    Utils.callbacks.addScanIssue(issues);
                                } catch (MalformedURLException e) {
                                    throw new RuntimeException("CheckCookie" + e);
                                }
                            }
                        }
                        if (sqlLength == 0) {
                            assert sqlresponseBody != null;
                            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                        }
                        if (Integer.parseInt(responseTime) > 6000) {
                            addToVulStr(logid, "参数" + paraName + "cookie存在延时");
                            errkey = "cookie存在延时";
                            IScanIssue issues = null;
                            try {
                                issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                                        "SqlInject Time", "SqlInject 发现延时注入",
                                        "High", "Certain");
                                Utils.callbacks.addScanIssue(issues);
                            } catch (MalformedURLException e) {
                                throw new RuntimeException("CheckCookie" + e);
                            }
                        }
                        addPayload(logid, paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }
                }
            }
        }
        // 检测header注入
        if (isCheckHeader) {

            // 组合header 构造请求数据包
            List<String> reqheadersxs = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            // 如果header为空，直接返回
            if (headerList.isEmpty()) {
                return;
            }

            // 新建一个用于存储新请求头的列表，并复制原始请求头到新列表中
            List<String> newReqheaders = new ArrayList<>(reqheadersxs);
            for (String reqheadersx : reqheadersxs) {
                for (SqlBean sqlBean : headerList) {
                    String headerName = sqlBean.getValue();
                    if (reqheadersx.contains(headerName)) {
                        // 删除原始请求头中包含的相同头部字段
                        newReqheaders.remove(reqheadersx);
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
                                IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                                List<String> sqlHeaders = ReqResponse.getHeaders();
                                String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
                                if (contentLength != null) {
                                    sqlLength = Integer.parseInt(contentLength);
                                }
                                // 判断body中是否有errorkey关键字
                                String sqlResponseBody = new String(sqlresponseBody);
                                if (errSqlCheck(sqlResponseBody)) {
                                    errkey = "存在报错";
                                    addToVulStr(logid, "header存在报错");
                                    IScanIssue issues = null;
                                    try {
                                        issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                                                "SqlInject Error", "SqlInject 发现报错",
                                                "High", "Certain");
                                        Utils.callbacks.addScanIssue(issues);
                                    } catch (MalformedURLException e) {
                                        throw new RuntimeException("CheckHeader" + e);
                                    }
                                }
                            }
                            if (sqlLength == 0) {
                                assert sqlresponseBody != null;
                                sqlLength = sqlresponseBody.length;
                            }
                            if (Integer.parseInt(responseTime) > 6000) {
                                addToVulStr(logid, "header存在延时");
                                IScanIssue issues = null;
                                try {
                                    issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                                            "SqlInject Time", "SqlInject 发现延时注入",
                                            "High", "Certain");
                                    Utils.callbacks.addScanIssue(issues);
                                } catch (MalformedURLException e) {
                                    throw new RuntimeException("CheckHeader" + e);
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

    // url去重
    public static boolean checkUrlHash(String url) {
        parameterList.clear();
        String md5 = DigestUtils.md5DigestAsHex(url.getBytes());
        if (urlHashList.contains(md5)) {
            return false;
        } else {
            urlHashList.add(md5);
            return true;
        }
    }

    // 添加url数据到表格
    public static int addUrl(String method, String url, int length, IHttpRequestResponse requestResponse) {
        synchronized (urldata) {
            int id = urldata.size();
            urldata.add(new UrlEntry(id, method, url, length, "正在检测", requestResponse));
            urltable.updateUI();
            payloadtable.updateUI();
            return id;
        }
    }

    // 添加漏洞数据到表格
    public static void addToVulStr(int key, CharSequence value) {
        // 检查是否已经存在该键，如果不存在则创建一个新的 ArrayList 存储值
        vul.computeIfAbsent(key, k -> new StringBuilder()).append(value).append(", ");
    }

    // 添加payload数据到表格
    public static void addPayload(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
        synchronized (payloaddata2) {
            payloaddata2.add(new PayloadEntry(selectId, key, value, length, change, errkey, time, status, requestResponse));
            urltable.updateUI();
            payloadtable.updateUI();
        }
    }

    // 检测一个单引号
    public static IHttpRequestResponse CheckSingleQuote(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, IHttpRequestResponse baseRequestResponse) {
        String s1Quotes = "'"; // 一个单引号
        String s1Payload = ""; // 构造一个单引号出来的payload
        String errkey = "x"; // 错误的key
        // 检测一个单引号
        // 如果是在get请求中，需要对payload进行url编码
        if (para.getType() == PARAM_URL) {
            s1Quotes = Utils.UrlEncode(s1Quotes);
        }
        // 是否删除原始的参数值
        if (isDeleteOrgin) {
            s1Payload = s1Quotes;
        } else {
            s1Payload = paraValue + s1Quotes;
        }
        long startTimes1 = System.currentTimeMillis();
        IParameter iParameters1 = Utils.helpers.buildParameter(paraName, s1Payload, para.getType());
        byte[] bytess1 = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters1);
        IHttpRequestResponse newRequestResponses1 = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytess1);
        long endTimes1 = System.currentTimeMillis();
        IResponseInfo analyzeResponses1 = Utils.helpers.analyzeResponse(newRequestResponses1.getResponse());
        int statusCodes1 = analyzeResponses1.getStatusCode();
        String responseTimes1 = String.valueOf(endTimes1 - startTimes1);
        byte[] sqlresponseBodys1 = newRequestResponses1.getResponse();
        int sqlLengths1 = 0;
        if (sqlresponseBodys1 != null) {
            // 判断有无Content-Length字段
            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBodys1);
            List<String> sqlHeaders = ReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                sqlLengths1 = Integer.parseInt(contentLength);
            }
            // 判断body中是否有errorkey关键字
            String sqlResponseBody = new String(sqlresponseBodys1);
            similarity1 = sqlResponseBody;
            if (errSqlCheck(sqlResponseBody)) {
                errkey = "存在报错";
                addToVulStr(logid, "参数" + paraName + "存在报错");
                IScanIssue issues = null;
                try {
                    issues = new CustomScanIssue(newRequestResponses1.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponses1},
                            "SqlInject Error", "SqlInject 发现报错",
                            "High", "Certain");
                    Utils.callbacks.addScanIssue(issues);
                } catch (MalformedURLException e) {
                    throw new RuntimeException("CheckSingleQuote" + e);
                }
            }
        }
        if (sqlLengths1 == 0) {
            assert sqlresponseBodys1 != null;
            sqlLengths1 = sqlresponseBodys1.length;
        }
        addPayload(logid, paraName, s1Payload, sqlLengths1, String.valueOf(sqlLengths1 - originalLength), errkey, responseTimes1, String.valueOf(statusCodes1), newRequestResponses1);
        return newRequestResponses1;
    }

    // 检测两个单引号
    public static IHttpRequestResponse CheckDoubleQuote(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, IHttpRequestResponse baseRequestResponse) {
        String s2Quotes = "''"; // 两个单引号
        String s2Payload = ""; // 构造两个单引号出来的payload
        String errkey = "x"; // 错误的key
        // 检测两个单引号
        // 如果是在get请求中，需要对payload进行url编码
        if (para.getType() == PARAM_URL) {
            s2Quotes = Utils.UrlEncode(s2Quotes);
        }
        // 是否删除原始的参数值
        if (isDeleteOrgin) {
            s2Payload = s2Quotes;
        } else {
            s2Payload = paraValue + s2Quotes;
        }
        long startTimes2 = System.currentTimeMillis();
        IParameter iParameters2 = Utils.helpers.buildParameter(paraName, s2Payload, para.getType());
        byte[] bytess2 = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters2);
        IHttpRequestResponse newRequestResponses2 = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytess2);
        // xm17: 考虑服务器被waf了  然后返回时间很长的情况
        long endTimes2 = System.currentTimeMillis();
        IResponseInfo analyzeResponses2 = Utils.helpers.analyzeResponse(newRequestResponses2.getResponse());
        int statusCodes2 = analyzeResponses2.getStatusCode();
        String responseTimes2 = String.valueOf(endTimes2 - startTimes2);
        byte[] sqlresponseBodys2 = newRequestResponses2.getResponse();
        int sqlLengths2 = 0;
        if (sqlresponseBodys2 != null) {
            // 判断有无Content-Length字段
            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBodys2);
            List<String> sqlHeaders = ReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                sqlLengths2 = Integer.parseInt(contentLength);
            }
            // 判断body中是否有errorkey关键字
            String sqlResponseBody = new String(sqlresponseBodys2);
            similarity2 = sqlResponseBody;
            if (errSqlCheck(sqlResponseBody)) {
                errkey = "存在报错";
                addToVulStr(logid, "参数" + paraName + "存在报错");
                IScanIssue issues = null;
                try {
                    issues = new CustomScanIssue(newRequestResponses2.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponses2},
                            "SqlInject Error", "SqlInject 发现报错",
                            "High", "Certain");
                    Utils.callbacks.addScanIssue(issues);
                } catch (MalformedURLException e) {
                    throw new RuntimeException("CheckDoubleQuote" + e);
                }
            }
        }
        if (sqlLengths2 == 0) {
            assert sqlresponseBodys2 != null;
            sqlLengths2 = sqlresponseBodys2.length;
        }

        addPayload(logid, paraName, s2Payload, sqlLengths2, String.valueOf(sqlLengths2 - originalLength), errkey, responseTimes2, String.valueOf(statusCodes2), newRequestResponses2);
        return newRequestResponses2;
    }

    // 检测三个单引号
    public static IHttpRequestResponse CheckTripleQuote(int logid, IParameter para, String paraName, String paraValue, String url, int originalLength, IHttpRequestResponse baseRequestResponse) {
        String s3Quotes = "'''"; // 三个单引号
        String s3Payload = ""; // 构造三个单引号出来的payload
        String errkey = "x"; // 错误的key
        // 检测三个单引号
        // 如果是在get请求中，需要对payload进行url编码
        if (para.getType() == PARAM_URL) {
            s3Quotes = Utils.UrlEncode(s3Quotes);
        }
        // 是否删除原始的参数值
        if (isDeleteOrgin) {
            s3Payload = s3Quotes;
        } else {
            s3Payload = paraValue + s3Quotes;
        }
        long startTimes3 = System.currentTimeMillis();
        IParameter iParameters3 = Utils.helpers.buildParameter(paraName, s3Payload, para.getType());
        byte[] bytess3 = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameters3);
        IHttpRequestResponse newRequestResponses3 = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytess3);
        // xm17: 考虑服务器被waf了  然后返回时间很长的情况
        long endTimes3 = System.currentTimeMillis();
        IResponseInfo analyzeResponses3 = Utils.helpers.analyzeResponse(newRequestResponses3.getResponse());
        int statusCodes3 = analyzeResponses3.getStatusCode();
        String responseTimes3 = String.valueOf(endTimes3 - startTimes3);
        byte[] sqlresponseBodys3 = newRequestResponses3.getResponse();
        int sqlLengths3 = 0;
        if (sqlresponseBodys3 != null) {
            // 判断有无Content-Length字段
            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBodys3);
            List<String> sqlHeaders = ReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                sqlLengths3 = Integer.parseInt(contentLength);
            }
            // 判断body中是否有errorkey关键字
            String sqlResponseBody = new String(sqlresponseBodys3);
            similarity3 = sqlResponseBody;
            if (errSqlCheck(sqlResponseBody)) {
                errkey = "存在报错";
                addToVulStr(logid, "参数" + paraName + "存在报错");
                IScanIssue issues = null;
                try {
                    issues = new CustomScanIssue(newRequestResponses3.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponses3},
                            "SqlInject Error", "SqlInject 发现报错",
                            "High", "Certain");
                    Utils.callbacks.addScanIssue(issues);
                } catch (MalformedURLException e) {
                    throw new RuntimeException("CheckTripleQuote" + e);
                }
            }
        }
        if (sqlLengths3 == 0) {
            assert sqlresponseBodys3 != null;
            sqlLengths3 = sqlresponseBodys3.length;
        }

        addPayload(logid, paraName, s3Payload, sqlLengths3, String.valueOf(sqlLengths3 - originalLength), errkey, responseTimes3, String.valueOf(statusCodes3), newRequestResponses3);
        return newRequestResponses3;
    }

    // 检测json一个单引号
    public static IHttpRequestResponse CheckJsonSingleQuote(int logid, Map<String, Object> request_json, List<String> reqheaders, String url, int originalLength, IHttpRequestResponse baseRequestResponse) {
        List<Object> objectList = new ArrayList<>();
        String s1Quotes = "'"; // 一个单引号
        String errkey = "x"; // 错误的key
        if (isDeleteOrgin) {
            objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(s1Quotes), 0);
        } else {
            objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(s1Quotes), 1);
        }

        // objectList为构造好的json数据，需要转成byte数组进行请求
        String json = "";
        for (Object o : objectList) {
            json = JSON.toJSONString(o);
        }
        long startTime = System.currentTimeMillis();
        byte[] bytes = Utils.helpers.buildHttpMessage(reqheaders, json.getBytes());
        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
        long endTime = System.currentTimeMillis();
        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
        int statusCode = analyzeResponse.getStatusCode();
        String responseTime = String.valueOf(endTime - startTime);
        byte[] sqlresponseBody = newRequestResponse.getResponse();
        int sqlLength = 0;
        if (sqlresponseBody != null) {
            // 判断有无Content-Length字段
            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
            List<String> sqlHeaders = ReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                sqlLength = Integer.parseInt(contentLength);
            }
            // 判断body中是否有errorkey关键字
            String sqlResponseBody = new String(sqlresponseBody);
            if (errSqlCheck(sqlResponseBody)) {
                errkey = "存在报错";
                addToVulStr(logid, "json存在报错");
                IScanIssue issues = null;
                try {
                    issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                            "SqlInject Error", "SqlInject 发现报错",
                            "High", "Certain");
                    Utils.callbacks.addScanIssue(issues);
                } catch (MalformedURLException e) {
                    throw new RuntimeException("CheckJsonSingleQuote" + e);
                }
            }
        }
        if (sqlLength == 0) {
            assert sqlresponseBody != null;
            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
        }
        if (Integer.parseInt(responseTime) > 6000) {
            addToVulStr(logid, "json存在延时");
            IScanIssue issues = null;
            try {
                issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                        "SqlInject Time", "SqlInject 发现延时注入",
                        "High", "Certain");
                Utils.callbacks.addScanIssue(issues);
            } catch (MalformedURLException e) {
                throw new RuntimeException("CheckJsonSingleQuote" + e);
            }
        }
        addPayload(logid, "json", s1Quotes, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
        return newRequestResponse;
    }

    // 检测json两个单引号
    public static IHttpRequestResponse CheckJsonDoubleQuote(int logid, Map<String, Object> request_json, List<String> reqheaders, String url, int originalLength, IHttpRequestResponse baseRequestResponse) {
        List<Object> objectList = new ArrayList<>();
        String s1Quotes = "''"; // 一个单引号
        String errkey = "x"; // 错误的key
        if (isDeleteOrgin) {
            objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(s1Quotes), 0);
        } else {
            objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(s1Quotes), 1);
        }

        // objectList为构造好的json数据，需要转成byte数组进行请求
        String json = "";
        for (Object o : objectList) {
            json = JSON.toJSONString(o);
        }
        long startTime = System.currentTimeMillis();
        byte[] bytes = Utils.helpers.buildHttpMessage(reqheaders, json.getBytes());
        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
        long endTime = System.currentTimeMillis();
        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
        int statusCode = analyzeResponse.getStatusCode();
        String responseTime = String.valueOf(endTime - startTime);
        byte[] sqlresponseBody = newRequestResponse.getResponse();
        int sqlLength = 0;
        if (sqlresponseBody != null) {
            // 判断有无Content-Length字段
            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
            List<String> sqlHeaders = ReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                sqlLength = Integer.parseInt(contentLength);
            }
            // 判断body中是否有errorkey关键字
            String sqlResponseBody = new String(sqlresponseBody);
            if (errSqlCheck(sqlResponseBody)) {
                errkey = "存在报错";
                addToVulStr(logid, "json存在报错");
                IScanIssue issues = null;
                try {
                    issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                            "SqlInject Error", "SqlInject 发现报错",
                            "High", "Certain");
                    Utils.callbacks.addScanIssue(issues);
                } catch (MalformedURLException e) {
                    throw new RuntimeException("CheckJsonDoubleQuote" + e);
                }
            }
        }
        if (sqlLength == 0) {
            assert sqlresponseBody != null;
            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
        }
        if (Integer.parseInt(responseTime) > 6000) {
            addToVulStr(logid, "json存在延时");
            IScanIssue issues = null;
            try {
                issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                        "SqlInject Time", "SqlInject 发现延时注入",
                        "High", "Certain");
                Utils.callbacks.addScanIssue(issues);
            } catch (MalformedURLException e) {
                throw new RuntimeException("CheckJsonDoubleQuote" + e);
            }
        }
        addPayload(logid, "json", s1Quotes, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
        return newRequestResponse;
    }

    // 检测json三个单引号
    public static IHttpRequestResponse CheckJsonTripleQuote(int logid, Map<String, Object> request_json, List<String> reqheaders, String url, int originalLength, IHttpRequestResponse baseRequestResponse) {
        List<Object> objectList = new ArrayList<>();
        String s1Quotes = "'''"; // 一个单引号
        String errkey = "x"; // 错误的key
        if (isDeleteOrgin) {
            objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(s1Quotes), 0);
        } else {
            objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(s1Quotes), 1);
        }

        // objectList为构造好的json数据，需要转成byte数组进行请求
        String json = "";
        for (Object o : objectList) {
            json = JSON.toJSONString(o);
        }
        long startTime = System.currentTimeMillis();
        byte[] bytes = Utils.helpers.buildHttpMessage(reqheaders, json.getBytes());
        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
        long endTime = System.currentTimeMillis();
        IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
        int statusCode = analyzeResponse.getStatusCode();
        String responseTime = String.valueOf(endTime - startTime);
        byte[] sqlresponseBody = newRequestResponse.getResponse();
        int sqlLength = 0;
        if (sqlresponseBody != null) {
            // 判断有无Content-Length字段
            IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
            List<String> sqlHeaders = ReqResponse.getHeaders();
            String contentLength = HelperPlus.getHeaderValueOf(sqlHeaders, "Content-Length");
            if (contentLength != null) {
                sqlLength = Integer.parseInt(contentLength);
            }
            // 判断body中是否有errorkey关键字
            String sqlResponseBody = new String(sqlresponseBody);
            if (errSqlCheck(sqlResponseBody)) {
                errkey = "存在报错";
                addToVulStr(logid, "json存在报错");
                IScanIssue issues = null;
                try {
                    issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                            "SqlInject Error", "SqlInject 发现报错",
                            "High", "Certain");
                    Utils.callbacks.addScanIssue(issues);
                } catch (MalformedURLException e) {
                    throw new RuntimeException("CheckJsonTripleQuote" + e);
                }
            }
        }
        if (sqlLength == 0) {
            assert sqlresponseBody != null;
            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
        }
        if (Integer.parseInt(responseTime) > 6000) {
            addToVulStr(logid, "json存在延时");
            IScanIssue issues = null;
            try {
                issues = new CustomScanIssue(newRequestResponse.getHttpService(), new URL(url), new IHttpRequestResponse[]{newRequestResponse},
                        "SqlInject Time", "SqlInject 发现延时注入",
                        "High", "Certain");
                Utils.callbacks.addScanIssue(issues);
            } catch (MalformedURLException e) {
                throw new RuntimeException("CheckJsonTripleQuote" + e);
            }
        }
        addPayload(logid, "json", s1Quotes, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
        return newRequestResponse;
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
        SqlBean sqlPassiveScanConfig = getSqlListByType("sqlPassiveScan");
        if (sqlPassiveScanConfig.getValue().equals("true")) {
            isPassiveScan = true;
            passiveScanCheckBox.setSelected(true);
        } else {
            isPassiveScan = false;
            passiveScanCheckBox.setSelected(false);
        }
        SqlBean sqlDeleteOrginConfig = getSqlListByType("sqlDeleteOrgin");
        if (sqlDeleteOrginConfig.getValue().equals("true")) {
            isDeleteOrgin = true;
            deleteOriginalValueCheckBox.setSelected(true);
        } else {
            isDeleteOrgin = false;
            deleteOriginalValueCheckBox.setSelected(false);
        }
        SqlBean sqlCheckCookieConfig = getSqlListByType("sqlCheckCookie");
        if (sqlCheckCookieConfig.getValue().equals("true")) {
            isCheckCookie = true;
            checkCookieCheckBox.setSelected(true);
        } else {
            isCheckCookie = false;
            checkCookieCheckBox.setSelected(false);
        }
        SqlBean sqlCheckHeaderConfig = getSqlListByType("sqlCheckHeader");
        if (sqlCheckHeaderConfig.getValue().equals("true")) {
            isCheckHeader = true;
            checkHeaderCheckBox.setSelected(true);
        } else {
            isCheckHeader = false;
            checkHeaderCheckBox.setSelected(false);
        }
        // 白名单域名
        SqlBean sqlWhiteDomainConfig = getSqlListByType("sqlWhiteDomain");
        if (sqlWhiteDomainConfig.getValue().equals("true")) {
            isWhiteDomain = true;
            checkWhiteListCheckBox.setSelected(true);
        } else {
            isWhiteDomain = false;
            checkWhiteListCheckBox.setSelected(false);
        }
        refreshTableButton.addActionListener(e -> {
            urltable.updateUI();
            payloadtable.updateUI();
        });
        clearTableButton.addActionListener(e -> {
            urldata.clear();
            payloaddata.clear();
            payloaddata2.clear();
            HRequestTextEditor.setMessage(new byte[0], true);
            HResponseTextEditor.setMessage(new byte[0], false);
            urlHashList.clear();
            urltable.updateUI();
            payloadtable.updateUI();
        });
        // 保存sql payload
        saveSqlPayloadButton.addActionListener(e -> {
            String sqleditorPane1Text = sqlPayloadTextArea.getText();
            deleteSqlByType("payload");
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
                    SqlBean sqlBean = new SqlBean("sqlPassiveScan", "true");
                    updateSql(sqlBean);
                } else {
                    isPassiveScan = false;
                    SqlBean sqlBean = new SqlBean("sqlPassiveScan", "false");
                    updateSql(sqlBean);
                }
            }
        });
        // 删除原始值选择框事件
        deleteOriginalValueCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (deleteOriginalValueCheckBox.isSelected()) {
                    isDeleteOrgin = true;
                    SqlBean sqlBean = new SqlBean("sqlDeleteOrgin", "true");
                    updateSql(sqlBean);
                } else {
                    isDeleteOrgin = false;
                    SqlBean sqlBean = new SqlBean("sqlDeleteOrgin", "false");
                    updateSql(sqlBean);
                }
            }
        });
        // 检测cookie选择框事件
        checkCookieCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkCookieCheckBox.isSelected()) {
                    isCheckCookie = true;
                    SqlBean sqlBean = new SqlBean("sqlCheckCookie", "true");
                    updateSql(sqlBean);
                } else {
                    isCheckCookie = false;
                    SqlBean sqlBean = new SqlBean("sqlCheckCookie", "false");
                    updateSql(sqlBean);
                }
            }
        });
        // 检测header选择框事件
        checkHeaderCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkHeaderCheckBox.isSelected()) {
                    isCheckHeader = true;
                    SqlBean sqlBean = new SqlBean("sqlCheckHeader", "true");
                    updateSql(sqlBean);
                } else {
                    isCheckHeader = false;
                    SqlBean sqlBean = new SqlBean("sqlCheckHeader", "false");
                    updateSql(sqlBean);
                }
            }
        });
        // 白名单域名检测选择框事件
        checkWhiteListCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (checkWhiteListCheckBox.isSelected()) {
                    isWhiteDomain = true;
                    SqlBean sqlBean = new SqlBean("sqlWhiteDomain", "true");
                    updateSql(sqlBean);
                } else {
                    isWhiteDomain = false;
                    SqlBean sqlBean = new SqlBean("sqlWhiteDomain", "false");
                    updateSql(sqlBean);
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
        tabbedPanereq.addTab("request", HRequestTextEditor.getComponent());
        tabbedPaneresp = new JTabbedPane();
        tabbedPaneresp.addTab("response", HResponseTextEditor.getComponent());
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


        // 添加到右边的上部分
        JPanel rightTopPanel = new JPanel();
        rightTopPanel.setLayout(new GridBagLayout());
        rightTopPanel.add(passiveScanCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(deleteOriginalValueCheckBox, new GridBagConstraintsHelper(1, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkCookieCheckBox, new GridBagConstraintsHelper(2, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkHeaderCheckBox, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightTopPanel.add(checkWhiteListCheckBox, new GridBagConstraintsHelper(1, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
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
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
            columnModel.getColumn(1).setMaxWidth(50);
            columnModel.getColumn(3).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            UrlEntry logEntry = urldata.get(rowIndex);
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