package burp.ui;

import burp.*;
import burp.bean.Log4jBean;
import burp.bean.SqlBean;
import burp.ui.UIHepler.GridBagConstraintsHelper;
import burp.utils.JsonUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumnModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;

import static burp.IParameter.*;
import static burp.dao.SqlDao.*;
import static burp.dao.SqlDao.getSqlListByType;
import static burp.utils.Utils.getSuffix;

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


    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (isPassiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            synchronized (urldata) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Check(new IHttpRequestResponse[]{iHttpRequestResponse},false);
                    }
                });
                thread.start();
            }
        }
    }

    // sql检测核心方法
    public static void Check(IHttpRequestResponse[] responses, boolean isSend) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String method = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();

        // 如果参数为空并且没有开启header检测,则直接返回
        if (paraLists.isEmpty() && !isCheckHeader) {
            return;
        }

        // 如果不是手动发送则需要进行url去重
        if (!isSend) {
            // 对url进行hash去重
            for (IParameter paraList : paraLists) {
                String paraName = paraList.getName();
                parameterList.add(paraName);
            }
            if (!checkUrlHash(method + url + parameterList)) {
                return;
            }
        }else {
            isWhiteDomain = false;
        }
        // url 中匹配为静态资源，直接返回
        List<String> suffix = getSuffix();
        for (String s : suffix) {
            if (url.endsWith(s)) {
                return;
            }
        }
        // url 不是白名单域名，直接返回
        if (isWhiteDomain) {
            List<SqlBean> domain = getSqlListsByType("domain");
            // 如果白名单为空，直接返回
            if (domain.isEmpty()) {
                return;
            }
            for (SqlBean sqlBean : domain) {
                if (!url.contains(sqlBean.getValue())) {
                    return;
                }
            }
        }
        // 原始请求包发送一次,用来比对
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
            List<String> headers = originalReqResponse.getHeaders();
            for (String header : headers) {
                if (header.contains("Content-Length")) {
                    originalLength = Integer.parseInt(header.split(":")[1].trim());
                    break;
                }
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

        // 拿到所有报错关键字
        List<String> listErrorKey = new ArrayList<>();
        List<SqlBean> sqlErrorKey = getSqlListsByType("sqlErrorKey");
        for (SqlBean sqlBean : sqlErrorKey) {
            listErrorKey.add(sqlBean.getValue());
        }
        // 如果没有设置关键报错字,默认为SQL syntax
        if (listErrorKey.isEmpty()) {
            listErrorKey.add("SQL syntax");
        }

        // 拿到所有payload
        List<SqlBean> sqliPayload = getSqlListsByType("payload");
        int logid = addUrl(method, url, originalLength, originalRequestResponse);

        // 检测常规注入
        for (IParameter para : paraLists) {
            if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_COOKIE || para.getType() == PARAM_JSON) {
                String paraName = para.getName();
                String paraValue = para.getValue();
                // 如果参数在url或body中，进行检测
                if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
                    if (paraName.isEmpty()) {
                        return;
                    }
                    for (SqlBean sql : sqliPayload) {
                        String errkey = "x";
                        String payload = "";
                        String sqlPayload = Utils.ReplaceChar(sql.getValue());
                        if (sqlPayload.isEmpty()) {
                            return;
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
                        long startTime = System.currentTimeMillis();
                        IParameter iParameter = Utils.helpers.buildParameter(paraName, payload, para.getType());
                        byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameter);
                        IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                        // xm17: 考虑服务器被waf了  然后返回时间很长的情况
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
                            for (String header : sqlHeaders) {
                                if (header.contains("Content-Length")) {
                                    sqlLength = Integer.parseInt(header.split(":")[1].trim());
                                    break;
                                }
                            }
                            // 判断body中是否有errorkey关键字
                            String sqlResponseBody = new String(sqlresponseBody);
                            for (String errorKey : listErrorKey) {
                                if (sqlResponseBody.contains(errorKey)) {
                                    errkey = "存在报错";
                                    break;
                                }
                            }
                        }
                        if (sqlLength == 0) {
                            assert sqlresponseBody != null;
                            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                        }

                        addPayload(logid, paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }

                } else if (isCheckCookie && para.getType() == PARAM_COOKIE) {
                    if (paraName.isEmpty()) {
                        return;
                    }
                    for (SqlBean sql : sqliPayload) {
                        String errkey = "x";
                        String payload = "";
                        String sqlPayload = Utils.ReplaceChar(sql.getValue());
                        if (sqlPayload.isEmpty()) {
                            return;
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
                        // xm17: 考虑服务器被waf了  然后返回时间很长的情况
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
                            for (String header : sqlHeaders) {
                                if (header.contains("Content-Length")) {
                                    sqlLength = Integer.parseInt(header.split(":")[1].trim());
                                    break;
                                }
                            }
                            // 判断body中是否有errorkey关键字
                            String sqlResponseBody = new String(sqlresponseBody);
                            for (String errorKey : listErrorKey) {
                                if (sqlResponseBody.contains(errorKey)) {
                                    errkey = "存在报错";
                                    break;
                                }
                            }
                        }
                        if (sqlLength == 0) {
                            assert sqlresponseBody != null;
                            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                        }
                        addPayload(logid, paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }
                } else if (para.getType() == PARAM_JSON) {
                    String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                    if (request_data.isEmpty()) {
                        return;
                    } else {
                        Map<String, Object> request_json = JSON.parseObject(request_data);
                        for (SqlBean sql : sqliPayload) {
                            List<Object> objectList = new ArrayList<>();
                            String payload = sql.getValue();
                            String errkey = "x";
                            if (isDeleteOrgin) {
                                objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(payload), 0);
                            } else {
                                objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(payload), 1);
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
                                for (String header : sqlHeaders) {
                                    if (header.contains("Content-Length")) {
                                        sqlLength = Integer.parseInt(header.split(":")[1].trim());
                                        break;
                                    }
                                }
                                // 判断body中是否有errorkey关键字
                                String sqlResponseBody = new String(sqlresponseBody);
                                for (String errorKey : listErrorKey) {
                                    if (sqlResponseBody.contains(errorKey)) {
                                        errkey = "存在报错";
                                        break;
                                    }
                                }
                            }
                            if (sqlLength == 0) {
                                assert sqlresponseBody != null;
                                sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                            }
                            addPayload(logid, "json", payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                        }
                        break;
                    }
                }
                // 更新url tables
                updateUrl(logid, method, url, originalLength, originalRequestResponse);
            }
        }
        // 检测header注入
        if (isCheckHeader) {
            // 获取数据库中的header
            List<SqlBean> header = getSqlListsByType("header");
            // 组合header 构造请求数据包
            List<String> reqheadersxs = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
            // 如果header为空，直接返回
            if (header.isEmpty()) {
                return;
            }

            // 新建一个用于存储新请求头的列表，并复制原始请求头到新列表中
            List<String> newReqheaders = new ArrayList<>(reqheadersxs);

            for (String reqheadersx : reqheadersxs) {
                for (SqlBean sqlBean : header) {
                    String headerName = sqlBean.getValue();
                    if (reqheadersx.contains(headerName)) {
                        // 删除原始请求头中包含的相同头部字段
                        newReqheaders.remove(reqheadersx);
                        if (headerName.contains("Cookie")) {
                            return;
                        }
                        for (SqlBean sql : sqliPayload) {
                            String errkey = "x";
                            String payload = "";
                            String sqlPayload = Utils.ReplaceChar(sql.getValue());
                            if (isDeleteOrgin) {
                                payload = sqlPayload;
                            } else {
                                payload = headerName + sqlPayload;
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
                                for (String headerx : sqlHeaders) {
                                    if (headerx.contains("Content-Length")) {
                                        sqlLength = Integer.parseInt(headerx.split(":")[1].trim());
                                        break;
                                    }
                                }
                                // 判断body中是否有errorkey关键字
                                String sqlResponseBody = new String(sqlresponseBody);
                                for (String errorKey : listErrorKey) {
                                    if (sqlResponseBody.contains(errorKey)) {
                                        errkey = "存在报错";
                                        break;
                                    }
                                }
                            }
                            if (sqlLength == 0) {
                                assert sqlresponseBody != null;
                                sqlLength = sqlresponseBody.length;
                            }
                            addPayload(logid, headerName, sqlPayload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);

                            // 每次完成请求后，移除刚刚添加的新头部字段，以便下一次迭代
                            newReqheaders.remove(newReqheaders.size() - 1);
                        }
                        break; // 已经处理了当前的头部信息，可以退出内循环
                    }
                }
            }
            // 更新url tables
            updateUrl(logid, method, url, originalLength, originalRequestResponse);
        }

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

    // 更新url数据到表格
    public static void updateUrl(int index, String method, String url, int length, IHttpRequestResponse
            requestResponse) {
        synchronized (urldata) {
            if (index >= 0 && index < urldata.size()) {
                urldata.set(index, new UrlEntry(index, method, url, length, "完成", requestResponse));
            }
            urltable.updateUI();
            payloadtable.updateUI();
        }
    }

    // 添加payload数据到表格
    public static void addPayload(int selectId, String key, String value, int length, String change, String
            errkey, String time, String status, IHttpRequestResponse requestResponse) {
        int id = payloaddata2.size();
        synchronized (payloaddata2) {
            payloaddata2.add(new PayloadEntry(id, selectId, key, value, length, change, errkey, time, status, requestResponse));
            urltable.updateUI();
            payloadtable.updateUI();
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
                String[] split = sqleditorPane1Text.split("\n");
                for (String s : split) {
                    SqlBean sqlBean = new SqlBean("payload", s);
                    saveSql(sqlBean);
                }
            } else {
                SqlBean sqlBean = new SqlBean("payload", sqleditorPane1Text);
                saveSql(sqlBean);
            }
            sqlPayloadTextArea.updateUI();
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        // 保存header
        saveHeaderListButton.addActionListener(e -> {
            String headerTextAreaText = headerTextArea.getText();
            deleteSqlByType("header");
            // 如果包含换行符，就分割成多个header
            if (headerTextAreaText.contains("\n")) {
                String[] split = headerTextAreaText.split("\n");
                for (String s : split) {
                    SqlBean sqlBean = new SqlBean("header", s);
                    saveSql(sqlBean);
                }
            } else {
                SqlBean sqlBean = new SqlBean("header", headerTextAreaText);
                saveSql(sqlBean);
            }
            headerTextArea.updateUI();
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        // 保存白名单域名
        saveWhiteListButton.addActionListener(e -> {
            String whiteListTextAreaText = whiteListTextArea.getText();
            deleteSqlByType("domain");
            // 如果包含换行符，就分割成多个domain
            if (whiteListTextAreaText.contains("\n")) {
                String[] split = whiteListTextAreaText.split("\n");
                for (String s : split) {
                    SqlBean sqlBean = new SqlBean("domain", s);
                    saveSql(sqlBean);
                }
            } else {
                SqlBean sqlBean = new SqlBean("domain", whiteListTextAreaText);
                saveSql(sqlBean);
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
                    String[] split = sqlErrorKeyTextAreaText.split("\n");
                    for (String s : split) {
                        SqlBean sqlBean = new SqlBean("sqlErrorKey", s);
                        saveSql(sqlBean);
                    }
                } else {
                    SqlBean sqlBean = new SqlBean("sqlErrorKey", sqlErrorKeyTextAreaText);
                    saveSql(sqlBean);
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
        // 左右分割
        JPanel splitPane = new JPanel(new BorderLayout());

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

        payloadtablescrollpane = new JScrollPane();
        zsSplitPane.setRightComponent(payloadtablescrollpane);
        PayloadModel payloadModel = new PayloadModel();
        payloadtable = new PayloadTable(payloadModel);
        payloadtablescrollpane.setViewportView(payloadtable);


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
        whiteListTextArea = new JTextArea();
        whiteListTextArea.setLineWrap(true); // 自动换行
        whiteListTextArea.setWrapStyleWord(true); // 按单词换行
        JScrollPane whiteListTextAreascrollPane = new JScrollPane(whiteListTextArea);

        // header检测数据框列表
        headerTextArea = new JTextArea();
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
        sqlPayloadTextArea = new JTextArea();
        sqlPayloadTextArea.setLineWrap(true); // 自动换行
        sqlPayloadTextArea.setWrapStyleWord(true); // 按单词换行
        JScrollPane sqlPayloadTextAreascrollPane = new JScrollPane(sqlPayloadTextArea);
        saveSqlPayloadButton = new JButton("保存sql payload");
        JPanel rightDownLeftPanel = new JPanel();
        rightDownLeftPanel.setLayout(new GridBagLayout());
        rightDownLeftPanel.add(sqlPayloadLabel, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownLeftPanel.add(sqlPayloadTextAreascrollPane, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightDownLeftPanel.add(saveSqlPayloadButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        // 右边的下部分左边
        JLabel sqlErrKey = new JLabel("sql error key");
        sqlErrorKeyTextArea = new JTextArea();
        sqlErrorKeyTextArea.setLineWrap(true); // 自动换行
        sqlErrorKeyTextArea.setWrapStyleWord(true); // 按单词换行
        JScrollPane sqlErrorKeyTextAreascrollPane = new JScrollPane(sqlErrorKeyTextArea);
        saveSqlErrorKeyButton = new JButton("保存sql error key");
        JPanel rightDownRightPanel = new JPanel();
        rightDownRightPanel.setLayout(new GridBagLayout());
        rightDownRightPanel.add(sqlErrKey, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));
        rightDownRightPanel.add(sqlErrorKeyTextAreascrollPane, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5).setIpad(0, 0).setWeight(1.0, 1.0).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));
        rightDownRightPanel.add(saveSqlErrorKeyButton, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5).setIpad(0, 0).setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        // 左右分割面板添加rightDownLeftPanel和rightDownRightPanel
        JSplitPane rightDownPanel = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        rightDownPanel.setResizeWeight(0.5);
        rightDownPanel.setDividerLocation(0.5);
        rightDownPanel.setLeftComponent(rightDownLeftPanel);
        rightDownPanel.setRightComponent(rightDownRightPanel);
        rightSplitPane.setBottomComponent(rightDownPanel);

        //splitPane添加到splitPane左边

        splitPane.add(leftSplitPane, BorderLayout.CENTER);
        splitPane.add(rightSplitPane, BorderLayout.EAST);
        panel.add(splitPane, BorderLayout.CENTER);

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
        final int id;
        final int selectId;
        final String key;
        final String value;
        final int length;
        final String change;
        final String errkey;
        final String time;
        final String status;
        final IHttpRequestResponse requestResponse;

        PayloadEntry(int id, int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
            this.id = id;
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
            return 8;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return payloaddata.get(rowIndex).id;
                case 1:
                    return payloaddata.get(rowIndex).key;
                case 2:
                    return payloaddata.get(rowIndex).value;
                case 3:
                    return payloaddata.get(rowIndex).length;
                case 4:
                    return payloaddata.get(rowIndex).change;
                case 5:
                    return payloaddata.get(rowIndex).errkey;
                case 6:
                    return payloaddata.get(rowIndex).time;
                case 7:
                    return payloaddata.get(rowIndex).status;
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
                    return "参数";
                case 2:
                    return "参数值";
                case 3:
                    return "响应长度";
                case 4:
                    return "变化";
                case 5:
                    return "报错";
                case 6:
                    return "时间";
                case 7:
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
            columnModel.getColumn(7).setMaxWidth(50);
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
