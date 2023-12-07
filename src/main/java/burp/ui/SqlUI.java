package burp.ui;

import burp.*;
import burp.bean.ConfigBean;
import burp.bean.SqlBean;
import burp.utils.JsonUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static burp.IParameter.*;
import static burp.dao.ConfigDao.getConfig;
import static burp.dao.ConfigDao.saveConfig;
import static burp.dao.SqlDao.*;
import static burp.utils.Utils.getSuffix;

public class SqlUI implements UIHandler, IMessageEditorController, IHttpListener {
    private static final List<UrlEntry> log = new ArrayList<>();
    private static final List<PayloadEntry> data = new ArrayList<>();
    private static final List<PayloadEntry> data2 = new ArrayList<>();
    private static JTable sqlUrltable1;
    private static JTable sqlPayloadtable2;
    private static boolean isPassiveScan;
    private static boolean isDeleteOrgin;
    private static boolean isCheckCookie;
    private static boolean isWhiteDomain;
    private static final List<String> parameterList = new ArrayList<>();
    private static final List<String> urlHashList = new ArrayList<>();
    public AbstractTableModel model = new PayloadModel();
    private JPanel panel;
    private JCheckBox sqlPassiveScanCheckBox;
    private JCheckBox sqlDeleteOrginCheckBox;
    private JCheckBox sqlCheckCookieCheckBox;
    private JCheckBox sqlWhiteCheckBox;
    private JTextField sqlWhiteDomaintextField;
    private JButton sqlRefershButton;
    private JButton sqlClearTableButton1;
    private JLabel sqlWhiteDomainLabel;
    private JButton sqlSaveWhiteDomainButton;
    private JButton sqlSavePayloadButton1;
    private JLabel sqlSqlPayloadLabel;
    private JEditorPane sqleditorPane1;
    private JTabbedPane tabbedPane1;
    private JTabbedPane tabbedPane2;
    private JScrollPane sqlJScrollPanetop1;
    private JScrollPane sqlJScrollPanetop2;
    private JPanel sqltabbedPane1;
    private JPanel sqltabbedPane2;
    private IMessageEditor HResponseTextEditor;
    private IMessageEditor HRequestTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;

    public static void Check(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String method = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();

        // 如果没有开启cookie检测，并且cookie中有参数，其他参数为空，直接返回
        if (!isCheckCookie) {
            int urlParamCount = 0;
            int bodyParamCount = 0;
            int jsonParamCount = 0;

            // 遍历参数列表，统计各种参数的个数
            for (IParameter parameter : paraLists) {
                if (parameter.getType() == IParameter.PARAM_URL) {
                    urlParamCount++;
                } else if (parameter.getType() == IParameter.PARAM_BODY) {
                    bodyParamCount++;
                } else if (parameter.getType() == IParameter.PARAM_JSON) {
                    jsonParamCount++;
                }
            }

            // 判断条件是否满足
            if (urlParamCount < 1 && bodyParamCount < 1 && jsonParamCount < 1) {
                return;
            }
        }

        // 如果参数为空，直接返回
        if (paraLists.isEmpty()) {
            return;
        }

        // 对url进行hash去重
        for (IParameter paraList : paraLists) {
            String paraName = paraList.getName();
            String paraValue = paraList.getValue();
            parameterList.add(paraName + "=" + paraValue);
        }
        if (!checkUrlHash(method + url + parameterList)) {
            return;
        }

        List<SqlBean> sqliPayload = getSqlList();

        // url 中为静态资源，直接返回
        List<String> suffix = getSuffix();
        for (String s : suffix) {
            if (url.endsWith(s)) {
                return;
            }
        }
        // url 不是白名单域名，直接返回
        if (isWhiteDomain) {
            ConfigBean whiteSqlDomain = getConfig("sql", "sqlWhiteSqlDomain");
            if (!url.contains(whiteSqlDomain.getValue())) {
                return;
            }
        }
        // 原始请求包发送一次
        List<String> originalheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        byte[] byte_Request = baseRequestResponse.getRequest();
        int bodyOffset = analyzeRequest.getBodyOffset();
        int len = byte_Request.length;
        byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
        byte[] postMessage = Utils.helpers.buildHttpMessage(originalheaders, body);
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
        List<String> listErrorKey = new ArrayList<>();
        String sqliErrorKey = getConfig("sql", "sqlErrorKey").getValue();
        // 如果sqlErrorKey包含|xxx| 则分割成多个
        if (sqliErrorKey.contains("|XXXXX|")) {
            String[] sqliErrorKeyValue = sqliErrorKey.split("\\|XXXXX\\|");
            listErrorKey.addAll(Arrays.asList(sqliErrorKeyValue));
        } else {
            listErrorKey.add(sqliErrorKey);
        }
        int logid = addLog(method, url, originalLength, originalRequestResponse);
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
                        String sqlPayload = Utils.ReplaceChar(sql.getSql());
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
                                    errkey = "√";
                                    break;
                                }
                            }
                        }
                        if (sqlLength == 0) {
                            assert sqlresponseBody != null;
                            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                        }

                        addPayloadLog(logid, paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }

                } else if (isCheckCookie && para.getType() == PARAM_COOKIE) {
                    if (paraName.isEmpty()) {
                        return;
                    }
                    for (SqlBean sql : sqliPayload) {
                        String errkey = "x";
                        String payload = "";
                        String sqlPayload = Utils.ReplaceChar(sql.getSql());
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
                                    errkey = "√";
                                    break;
                                }
                            }
                        }
                        if (sqlLength == 0) {
                            assert sqlresponseBody != null;
                            sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                        }
                        addPayloadLog(logid, paraName, payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                    }

                } else if (para.getType() == PARAM_JSON) {
                    String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                    if (request_data.isEmpty()) {
                        return;
                    } else {
                        Map<String, Object> request_json = JSON.parseObject(request_data);
                        for (SqlBean sql : sqliPayload) {
                            List<Object> objectList = new ArrayList<>();
                            String payload = sql.getSql();
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
                                        errkey = "√";
                                        break;
                                    }
                                }
                            }
                            if (sqlLength == 0) {
                                assert sqlresponseBody != null;
                                sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                            }

                            addPayloadLog(logid, "json", payload, sqlLength, String.valueOf(Math.abs(sqlLength - originalLength)), errkey, responseTime, String.valueOf(statusCode), newRequestResponse);
                        }

                        break;

                    }
                }
            }
        }
        updateLog(logid, method, url, originalLength, originalRequestResponse);
    }

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

    // 添加url数据
    public static int addLog(String method, String url, int length, IHttpRequestResponse requestResponse) {

        synchronized (log) {
            int id = log.size();
            log.add(new UrlEntry(id, method, url, length, "正在检测", requestResponse));
            sqlUrltable1.updateUI();
            sqlPayloadtable2.updateUI();
            return id;
        }

    }

    // 更新url数据
    public static void updateLog(int index, String method, String url, int length, IHttpRequestResponse requestResponse) {
        synchronized (log) {
            if (index >= 0 && index < log.size()) {
                log.set(index, new UrlEntry(index, method, url, length, "完成", requestResponse));
            }
            sqlUrltable1.updateUI();
            sqlPayloadtable2.updateUI();
        }
    }

    // 添加payload数据
    public static void addPayloadLog(int selectId, String key, String value, int length, String change, String errkey, String time, String status, IHttpRequestResponse requestResponse) {
        int id = data2.size();
        synchronized (data2) {
            data2.add(new PayloadEntry(id, selectId, key, value, length, change, errkey, time, status, requestResponse));
            sqlUrltable1.updateUI();
            sqlPayloadtable2.updateUI();
        }
    }

    private void setupUI() {
        Utils.callbacks.registerHttpListener(this);
        panel = new JPanel();
        panel.setLayout(new BorderLayout(0, 0));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new BorderLayout(0, 0));
        panel.add(panel2, BorderLayout.CENTER);
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new BorderLayout(0, 0));
        panel2.add(panel3, BorderLayout.EAST);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new GridLayoutManager(6, 3, new Insets(0, 0, 0, 0), -1, -1));
        panel3.add(panel4, BorderLayout.NORTH);
        sqlPassiveScanCheckBox = new JCheckBox();
        sqlPassiveScanCheckBox.setText("被动扫描");
        panel4.add(sqlPassiveScanCheckBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlDeleteOrginCheckBox = new JCheckBox();
        sqlDeleteOrginCheckBox.setText("删除原始值");
        panel4.add(sqlDeleteOrginCheckBox, new GridConstraints(0, 1, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlCheckCookieCheckBox = new JCheckBox();
        sqlCheckCookieCheckBox.setText("检测cookie");
        panel4.add(sqlCheckCookieCheckBox, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlWhiteCheckBox = new JCheckBox();
        sqlWhiteCheckBox.setText("白名单检测");
        panel4.add(sqlWhiteCheckBox, new GridConstraints(1, 1, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlWhiteDomaintextField = new JTextField();
        panel4.add(sqlWhiteDomaintextField, new GridConstraints(3, 0, 1, 3, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        sqlRefershButton = new JButton();
        sqlRefershButton.setText("刷新表格");
        panel4.add(sqlRefershButton, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlClearTableButton1 = new JButton();
        sqlClearTableButton1.setText("清空表格");
        panel4.add(sqlClearTableButton1, new GridConstraints(4, 1, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlWhiteDomainLabel = new JLabel();
        sqlWhiteDomainLabel.setText("白名单域名");
        panel4.add(sqlWhiteDomainLabel, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlSaveWhiteDomainButton = new JButton();
        sqlSaveWhiteDomainButton.setText("保存白名单");
        panel4.add(sqlSaveWhiteDomainButton, new GridConstraints(2, 1, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlSavePayloadButton1 = new JButton();
        sqlSavePayloadButton1.setText("保存payload");
        panel4.add(sqlSavePayloadButton1, new GridConstraints(5, 1, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        sqlSqlPayloadLabel = new JLabel();
        sqlSqlPayloadLabel.setText("sql payload");
        panel4.add(sqlSqlPayloadLabel, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panel3.add(panel5, BorderLayout.CENTER);
        sqleditorPane1 = new JEditorPane();
        panel5.add(sqleditorPane1, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_WANT_GROW, null, new Dimension(150, 50), null, 0, false));
        final JSplitPane splitPane1 = new JSplitPane();
        splitPane1.setDividerSize(1);
        splitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane1.setResizeWeight(0.5);
        panel2.add(splitPane1, BorderLayout.CENTER);
        final JSplitPane splitPane2 = new JSplitPane();
        splitPane2.setDividerSize(2);
        splitPane2.setResizeWeight(0.5);
        splitPane1.setLeftComponent(splitPane2);
        sqlJScrollPanetop1 = new JScrollPane();
        splitPane2.setLeftComponent(sqlJScrollPanetop1);
        UrlModel urlModel = new UrlModel();
        sqlUrltable1 = new URLTable(urlModel);
        sqlJScrollPanetop1.setViewportView(sqlUrltable1);
        sqlJScrollPanetop2 = new JScrollPane();
        splitPane2.setRightComponent(sqlJScrollPanetop2);
        PayloadModel payloadModel = new PayloadModel();
        sqlPayloadtable2 = new PayloadTable(payloadModel);
        sqlJScrollPanetop2.setViewportView(sqlPayloadtable2);
        final JSplitPane splitPane3 = new JSplitPane();
        splitPane3.setDividerSize(2);
        splitPane3.setResizeWeight(0.5);
        splitPane1.setRightComponent(splitPane3);
        tabbedPane1 = new JTabbedPane();
        splitPane3.setLeftComponent(tabbedPane1);
        HRequestTextEditor = Utils.callbacks.createMessageEditor(SqlUI.this, true);
        HResponseTextEditor = Utils.callbacks.createMessageEditor(SqlUI.this, false);
        tabbedPane1.addTab("request", HRequestTextEditor.getComponent());
        tabbedPane2 = new JTabbedPane();
        splitPane3.setRightComponent(tabbedPane2);
        sqltabbedPane2 = new JPanel();
        sqltabbedPane2.setLayout(new GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPane2.addTab("response", HResponseTextEditor.getComponent());

    }

    private void setupData() {
        ConfigBean sqlPassiveScanCheckBoxConfig = getConfig("sql", "sqlPassiveScanCheckBox");
        if (sqlPassiveScanCheckBoxConfig.getValue().equals("true")) {
            isPassiveScan = true;

            sqlPassiveScanCheckBox.setSelected(true);
        } else {
            isPassiveScan = false;

            sqlPassiveScanCheckBox.setSelected(false);
        }
        ConfigBean sqlDeleteOrginCheckBoxConfig = getConfig("sql", "sqlDeleteOrginCheckBox");
        if (sqlDeleteOrginCheckBoxConfig.getValue().equals("true")) {
            isDeleteOrgin = true;

            sqlDeleteOrginCheckBox.setSelected(true);
        } else {
            isDeleteOrgin = false;

            sqlDeleteOrginCheckBox.setSelected(false);
        }
        ConfigBean sqlCheckCookieCheckBoxConfig = getConfig("sql", "sqlCheckCookieCheckBox");
        if (sqlCheckCookieCheckBoxConfig.getValue().equals("true")) {
            isCheckCookie = true;

            sqlCheckCookieCheckBox.setSelected(true);
        } else {
            isCheckCookie = false;

            sqlCheckCookieCheckBox.setSelected(false);
        }
        ConfigBean sqlWhiteCheckBoxConfig = getConfig("sql", "sqlWhiteCheckBox");
        if (sqlWhiteCheckBoxConfig.getValue().equals("true")) {
            isWhiteDomain = true;

            sqlWhiteCheckBox.setSelected(true);
        } else {
            isWhiteDomain = false;

            sqlWhiteCheckBox.setSelected(false);
        }
        ConfigBean sqlWhiteDomaintextFieldConfig = getConfig("sql", "sqlWhiteSqlDomain");
        sqlWhiteDomaintextField.setText(sqlWhiteDomaintextFieldConfig.getValue());
        sqlRefershButton.addActionListener(e -> {
            sqlUrltable1.updateUI();
            sqlPayloadtable2.updateUI();
        });
        sqlClearTableButton1.addActionListener(e -> {
            log.clear();
            data.clear();
            data2.clear();
            HRequestTextEditor.setMessage(new byte[0], true);
            HResponseTextEditor.setMessage(new byte[0], false);
            sqlUrltable1.updateUI();
            sqlPayloadtable2.updateUI();
        });
        sqlSaveWhiteDomainButton.addActionListener(e -> {
            String whiteDomaintextFieldText = sqlWhiteDomaintextField.getText();
            ConfigBean sqlWhiteDomaintextFieldConfig1 = new ConfigBean("sql", "sqlWhiteSqlDomain", whiteDomaintextFieldText);
            saveConfig(sqlWhiteDomaintextFieldConfig1);
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        sqlSavePayloadButton1.addActionListener(e -> {
            String sqleditorPane1Text = sqleditorPane1.getText();
            deleteSql();
            // 如果包含换行符，就分割成多个payload
            if (sqleditorPane1Text.contains("\n")) {
                String[] split = sqleditorPane1Text.split("\n");
                for (String s : split) {
                    SqlBean sqlBean = new SqlBean(s);
                    saveSql(sqlBean);
                }
            } else {
                SqlBean sqlBean = new SqlBean(sqleditorPane1Text);
                saveSql(sqlBean);
            }
            sqleditorPane1.updateUI();
            JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
        });
        sqlPassiveScanCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (sqlPassiveScanCheckBox.isSelected()) {
                    isPassiveScan = true;
                    ConfigBean sqlPassiveScanCheckBoxConfig1 = new ConfigBean("sql", "sqlPassiveScanCheckBox", "true");
                    saveConfig(sqlPassiveScanCheckBoxConfig1);
                } else {
                    isPassiveScan = false;
                    ConfigBean sqlPassiveScanCheckBoxConfig1 = new ConfigBean("sql", "sqlPassiveScanCheckBox", "false");
                    saveConfig(sqlPassiveScanCheckBoxConfig1);
                }
            }
        });
        sqlDeleteOrginCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (sqlDeleteOrginCheckBox.isSelected()) {
                    isDeleteOrgin = true;
                    ConfigBean sqlDeleteOrginCheckBoxConfig1 = new ConfigBean("sql", "sqlDeleteOrginCheckBox", "true");
                    saveConfig(sqlDeleteOrginCheckBoxConfig1);
                } else {
                    isDeleteOrgin = false;
                    ConfigBean sqlDeleteOrginCheckBoxConfig1 = new ConfigBean("sql", "sqlDeleteOrginCheckBox", "false");
                    saveConfig(sqlDeleteOrginCheckBoxConfig1);
                }
            }
        });
        sqlCheckCookieCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (sqlCheckCookieCheckBox.isSelected()) {
                    isCheckCookie = true;
                    ConfigBean sqlCheckCookieCheckBoxConfig1 = new ConfigBean("sql", "sqlCheckCookieCheckBox", "true");
                    saveConfig(sqlCheckCookieCheckBoxConfig1);
                } else {
                    isCheckCookie = false;
                    ConfigBean sqlCheckCookieCheckBoxConfig1 = new ConfigBean("sql", "sqlCheckCookieCheckBox", "false");
                    saveConfig(sqlCheckCookieCheckBoxConfig1);
                }
            }
        });
        sqlWhiteCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (sqlWhiteCheckBox.isSelected()) {
                    isWhiteDomain = true;
                    ConfigBean sqlWhiteCheckBoxConfig1 = new ConfigBean("sql", "sqlWhiteCheckBox", "true");
                    saveConfig(sqlWhiteCheckBoxConfig1);
                } else {
                    isWhiteDomain = false;
                    ConfigBean sqlWhiteCheckBoxConfig1 = new ConfigBean("sql", "sqlWhiteCheckBox", "false");
                    saveConfig(sqlWhiteCheckBoxConfig1);
                }
            }
        });
        List<SqlBean> sqlList = getSqlList();
        for (SqlBean sqlBean : sqlList) {
            // 如果是最后一个，就不加换行符
            if (sqlList.indexOf(sqlBean) == sqlList.size() - 1) {
                sqleditorPane1.setText(sqleditorPane1.getText() + sqlBean.getSql());
                break;
            }
            sqleditorPane1.setText(sqleditorPane1.getText() + sqlBean.getSql() + "\n");

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

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    public String getTabName() {
        return "sql";
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {

        if (isPassiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            synchronized (log) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Check(new IHttpRequestResponse[]{iHttpRequestResponse});
                    }
                });
                thread.start();
            }
        }
    }

    // url 模型
    static class UrlModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return log.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return log.get(rowIndex).id;
                case 1:
                    return log.get(rowIndex).method;
                case 2:
                    return log.get(rowIndex).url;
                case 3:
                    return log.get(rowIndex).length;
                case 4:
                    return log.get(rowIndex).status;
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
            return data.size();
        }

        @Override
        public int getColumnCount() {
            return 8;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex) {
                case 0:
                    return data.get(rowIndex).id;
                case 1:
                    return data.get(rowIndex).key;
                case 2:
                    return data.get(rowIndex).value;
                case 3:
                    return data.get(rowIndex).length;
                case 4:
                    return data.get(rowIndex).change;
                case 5:
                    return data.get(rowIndex).errkey;
                case 6:
                    return data.get(rowIndex).time;
                case 7:
                    return data.get(rowIndex).status;
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

    // 检测url类
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

    // Payload 类
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

    private class URLTable extends JTable {
        public URLTable(AbstractTableModel model) {
            super(model);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            UrlEntry logEntry = log.get(rowIndex);
            int select_id = logEntry.id;
            data.clear();
            for (PayloadEntry payloadEntry : data2) {
                if (payloadEntry.selectId == select_id) {
                    data.add(payloadEntry);
                }
            }
            sqlPayloadtable2.updateUI();


            model.fireTableRowsInserted(data.size(), data.size());
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

    private class PayloadTable extends JTable {
        public PayloadTable(AbstractTableModel model) {
            super(model);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {

            PayloadEntry dataEntry = data.get(rowIndex);
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
