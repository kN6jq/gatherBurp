package burp.ui;

import burp.*;
import burp.bean.ConfigBean;
import burp.bean.Log4jBean;
import burp.utils.JsonUtils;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import org.springframework.util.DigestUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.List;
import java.util.*;

import static burp.IParameter.*;
import static burp.dao.ConfigDao.getConfig;
import static burp.dao.ConfigDao.saveConfig;
import static burp.dao.Log4jDao.*;

public class Log4jUI implements UIHandler, IMessageEditorController, IHttpListener {
    private static final List<LogEntry> log = new ArrayList<>();
    private static final List<String> parameterList = new ArrayList<>();
    private static final List<String> urlHashList = new ArrayList<>();
    private static JTable log4jTable;
    private static boolean enableHeader;
    private static boolean enableParam;
    private static boolean enableWhiteDomain;
    private static boolean originalPayload;
    private static boolean passiveScan;
    private JPanel panel;
    private JCheckBox passiveBox;
    private JCheckBox headerBox;
    private JCheckBox dnsIpCheckBox;
    private JCheckBox orgpayloadCheckBox;
    private JCheckBox paramBox;
    private JCheckBox whiteDomainCheckBox;
    private JButton saveWhiteDomainButton;
    private JTextField whiteDomaintextField;
    private JButton refershTableButton;
    private JButton clearTableButton;
    private JButton savePayloadButton;
    private JButton saveHeaderButton;
    private JEditorPane headertextField;
    private JEditorPane payloadtextField;
    private JTabbedPane tabbedPane2;
    private JTabbedPane tabbedPane3;
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;

    public static void Check(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String method = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();
        // url 中为静态资源，直接返回
        List<String> suffix = Utils.getSuffix();
        for (String s : suffix) {
            if (url.endsWith(s) || url.contains(s)) {
                return;
            }
        }

        // 对url进行hash去重
        for (IParameter paraList : paraLists) {
            String paraName = paraList.getName();
            parameterList.add(paraName);
        }
        if (!checkUrlHash(method + url + parameterList.toString())) {
            return;
        }


        ConfigBean enableHeaderConfig = getConfig("log4j", "log4jHeaderCheckBox");
        enableHeader = enableHeaderConfig.getValue().equals("true");
        ConfigBean enableWhiteDomainConfig = getConfig("log4j", "log4jWhiteDomainCheckBox");
        enableWhiteDomain = enableWhiteDomainConfig.getValue().equals("true");
        ConfigBean originalPayloadConfig = getConfig("log4j", "log4jOrgPayloadCheckBox");
        originalPayload = originalPayloadConfig.getValue().equals("true");
        ConfigBean paramCheckBoxConfig = getConfig("log4j", "log4jParamCheckBox");
        enableParam = paramCheckBoxConfig.getValue().equals("true");


        if (enableWhiteDomain) {
            ConfigBean whiteSqlDomain = getConfig("log4j", "log4jWhiteDomain");
            String whiteDomain = whiteSqlDomain.getValue();
            if (whiteDomain.isEmpty()) {
                JOptionPane.showMessageDialog(null, "已开启白名单扫描,请先设置白名单域名", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (!url.contains(whiteDomain)) {
                // 不在白名单域名中，直接返回
                return;
            }
        }

        // 先将payload存储
        Set<String> log4jPayload = new LinkedHashSet<>();
        List<Log4jBean> payloadList = getPayloadList();
        if (payloadList.isEmpty()) {
            JOptionPane.showMessageDialog(null, "请先添加payload", "提示", JOptionPane.ERROR_MESSAGE);
            return;
        }
        // 将数据库中的payload加入到列表
        for (Log4jBean log4j : payloadList) {
            if (originalPayload) {
                log4jPayload.add(log4j.getValue());
            } else {
                if (log4j.getValue().contains("dnslog-url")) {
                    if (getConfig("log4j", "log4jDnsIpCheckBox").getValue().equals("true")) {
                        try {
                            String dns = getConfig("config", "dnslog").getValue();
                            if (dns.isEmpty()) {
                                JOptionPane.showMessageDialog(null, "已勾选dnslog,请先设置dnslog地址", "提示", JOptionPane.ERROR_MESSAGE);
                                return;
                            }
                            String logPrefix = getReqTag(baseRequestResponse, analyzeRequest, "dns");
                            log4jPayload.add(log4j.getValue().replace("dnslog-url", logPrefix + dns));
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(null, "数据库初始化失败,请联系作者", "提示", JOptionPane.ERROR_MESSAGE);
                            return;
                        }
//                        log4jPayload.add(utils.urlEncode(log4j.getValue()).replace("dnslog-url", logPrefix+dns));

                    } else {
                        try {
                            String ip = getConfig("config", "ip").getValue();
                            if (ip.isEmpty()) {
                                JOptionPane.showMessageDialog(null, "已勾选ip,请先设置ip地址", "提示", JOptionPane.ERROR_MESSAGE);
                                return;
                            }
                            String logPrefix = getReqTag(baseRequestResponse, analyzeRequest, "ip");
                            log4jPayload.add(log4j.getValue().replace("dnslog-url", ip + "/" + logPrefix));
                        } catch (Exception e) {
                            JOptionPane.showMessageDialog(null, "数据库初始化失败,请联系作者", "提示", JOptionPane.ERROR_MESSAGE);
                            return;
                        }
//                        log4jPayload.add(utils.urlEncode(log4j.getValue()).replace("dnslog-url", ip+"/"+logPrefix));

                    }
                } else {
                    log4jPayload.add(log4j.getValue());
                }
            }
        }

        // 检测参数
        if (enableParam) {
            for (IParameter para : paraLists) {
                if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON) {
                    String paraName = para.getName();
                    String paraValue = para.getValue();
                    // 判断参数是否在url中
                    if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
                        for (String logPayload : log4jPayload) {
                            IParameter iParameter = Utils.helpers.buildParameter(paraName, logPayload, para.getType());
                            byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameter);
                            IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                            IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                            byte[] sqlresponseBody = newRequestResponse.getResponse();
                            String ParamLength = "";
                            String ParamstatusCode = String.valueOf(analyzeResponse.getStatusCode());
                            if (sqlresponseBody != null) {
                                // 判断有无Content-Length字段
                                IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                                List<String> sqlHeaders = ReqResponse.getHeaders();
                                for (String header : sqlHeaders) {
                                    if (header.contains("Content-Length")) {
                                        ParamLength = header.split(":")[1].trim();
                                        break;
                                    }
                                }
                            }
                            if (ParamLength.isEmpty()) {
                                assert sqlresponseBody != null;
                                ParamLength = String.valueOf(sqlresponseBody.length);
                            }
                            add(method, url, ParamstatusCode, ParamLength, newRequestResponse);
                        }

                    }
                    // 判断参数是否在json中
                    else if (para.getType() == PARAM_JSON) {
                        for (String logPayload : log4jPayload) {
                            String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                            Map<String, Object> request_json = JSON.parseObject(request_data);
                            List<Object> objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(logPayload), 0);
                            String json = "";
                            for (Object o : objectList) {
                                json = JSON.toJSONString(o);
                            }
                            byte[] bytes = Utils.helpers.buildHttpMessage(reqheaders, json.getBytes());
                            IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                            IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                            byte[] sqlresponseBody = newRequestResponse.getResponse();
                            String ParamLength = "";
                            String ParamstatusCode = String.valueOf(analyzeResponse.getStatusCode());
                            if (sqlresponseBody != null) {
                                // 判断有无Content-Length字段
                                IResponseInfo ReqResponse = Utils.helpers.analyzeResponse(sqlresponseBody);
                                List<String> sqlHeaders = ReqResponse.getHeaders();
                                for (String header : sqlHeaders) {
                                    if (header.contains("Content-Length")) {
                                        ParamLength = header.split(":")[1].trim();
                                        break;
                                    }
                                }
                            }
                            if (ParamLength.isEmpty()) {
                                assert sqlresponseBody != null;
                                ParamLength = String.valueOf(sqlresponseBody.length);
                            }
                            add(method, url, ParamstatusCode, ParamLength, newRequestResponse);

                        }
                        break;
                    }
                }
            }
        }


        // 检测header
        boolean enableHeader = getConfig("log4j", "log4jHeaderCheckBox").getValue().equals("true");
        if (enableHeader) {
            byte[] byte_Request = baseRequestResponse.getRequest();
            int bodyOffset = analyzeRequest.getBodyOffset();
            int len = byte_Request.length;
            byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
            List<Log4jBean> headerList = getHeaderList();
            for (String logPayload : log4jPayload) {
                List<String> reqheaders2 = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
                List<String> newReqheaders = new ArrayList<>();
                Iterator<String> iterator = reqheaders2.iterator();
                while (iterator.hasNext()) {
                    String reqheader = iterator.next();
                    for (Log4jBean log4j : headerList) {
                        if (reqheader.contains(log4j.getValue())) {
                            iterator.remove();
                            String newHeader = log4j.getValue() + ": " + logPayload;
                            if (!newReqheaders.contains(newHeader)) {
                                newReqheaders.add(newHeader);
                            }
                        }
                    }
                }
                for (Log4jBean log4j : headerList) {
                    String newHeader = log4j.getValue() + ": " + logPayload;
                    if (!reqheaders2.contains(log4j.getValue()) && !newReqheaders.contains(newHeader)) {
                        newReqheaders.add(newHeader);
                    }
                }

                reqheaders2.addAll(newReqheaders);
                byte[] postMessage = Utils.helpers.buildHttpMessage(reqheaders2, body);
                IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
                byte[] responseBody = originalRequestResponse.getResponse();

                String originallength = "";
                String statusCode = "";
                if (responseBody != null) {
                    IResponseInfo originalReqResponse = Utils.helpers.analyzeResponse(responseBody);
                    List<String> headers = originalReqResponse.getHeaders();
                    statusCode = String.valueOf(originalReqResponse.getStatusCode());
                    for (String header : headers) {
                        if (header.contains("Content-Length")) {
                            originallength = header.split(":")[1].trim();
                            break;
                        }
                    }
                }
                if (originallength.isEmpty()) {
                    assert responseBody != null;
                    originallength = String.valueOf(responseBody.length);
                }
                add(method, url, statusCode, originallength, originalRequestResponse);
            }
        }

    }

    private static String getReqTag(IHttpRequestResponse baseRequestResponse, IRequestInfo req, String type) {
        List<String> requestHeader = req.getHeaders();
        // 循环获取参数，判断类型，进行加密处理后，再构造新的参数，合并到新的请求包中。
        //第一行请求包含请求方法、请求uri、http版本
        String firstrequestHeader = requestHeader.get(0);
        String[] firstheaders = firstrequestHeader.split(" ");
        String uri = firstheaders[1].split("\\?")[0].replace("/", ".");
        if (firstheaders[1].split("\\?")[0].replace("/", ".").length() > 25) {
            uri = uri.substring(0, 25);
            if (uri.endsWith(".")) {
                uri = uri.substring(0, uri.length() - 1);
            }
        }
        if (uri.endsWith(".")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        IHttpService httpService = baseRequestResponse.getHttpService();
        String host = httpService.getHost();
        if (type.equals("dns")) {
            return firstheaders[0].trim() + "." + host + uri + ".";
        } else {
            return firstheaders[0].trim() + "." + host + uri;
        }
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

    public static void add(String extensionMethod, String url, String status, String res, IHttpRequestResponse baseRequestResponse) {
        synchronized (log) {
            int id = log.size();
            log.add(new LogEntry(id, extensionMethod, url, status, res, baseRequestResponse));
            log4jTable.updateUI();
        }

    }

    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new BorderLayout(0, 0));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new BorderLayout(0, 0));
        panel.add(panel2, BorderLayout.CENTER);
        final JPanel panel3 = new JPanel();
        panel3.setLayout(new BorderLayout(0, 0));
        panel2.add(panel3, BorderLayout.CENTER);
        final JPanel panel4 = new JPanel();
        panel4.setLayout(new BorderLayout(0, 0));
        panel3.add(panel4, BorderLayout.EAST);
        final JPanel panel5 = new JPanel();
        panel5.setLayout(new GridLayoutManager(6, 2, new Insets(0, 0, 0, 0), -1, -1));
        panel4.add(panel5, BorderLayout.NORTH);
        passiveBox = new JCheckBox();
        passiveBox.setText("被动扫描");
        panel5.add(passiveBox, new GridConstraints(0, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        headerBox = new JCheckBox();
        headerBox.setText("检测header");
        panel5.add(headerBox, new GridConstraints(0, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        dnsIpCheckBox = new JCheckBox();
        dnsIpCheckBox.setText("dns/ip");
        panel5.add(dnsIpCheckBox, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        orgpayloadCheckBox = new JCheckBox();
        orgpayloadCheckBox.setText("原始payload");
        panel5.add(orgpayloadCheckBox, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        whiteDomainCheckBox = new JCheckBox();
        whiteDomainCheckBox.setText("白名单域名");
        panel5.add(whiteDomainCheckBox, new GridConstraints(2, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        paramBox = new JCheckBox();
        paramBox.setText("检测参数");
        panel5.add(paramBox, new GridConstraints(2, 1, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        saveWhiteDomainButton = new JButton();
        saveWhiteDomainButton.setText("保存域名");
        panel5.add(saveWhiteDomainButton, new GridConstraints(3, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        whiteDomaintextField = new JTextField();
        panel5.add(whiteDomaintextField, new GridConstraints(3, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        refershTableButton = new JButton();
        refershTableButton.setText("刷新");
        panel5.add(refershTableButton, new GridConstraints(4, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        clearTableButton = new JButton();
        clearTableButton.setText("清空");
        panel5.add(clearTableButton, new GridConstraints(4, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        savePayloadButton = new JButton();
        savePayloadButton.setText("保存payload");
        panel5.add(savePayloadButton, new GridConstraints(5, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        saveHeaderButton = new JButton();
        saveHeaderButton.setText("保存header");
        panel5.add(saveHeaderButton, new GridConstraints(5, 0, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel6 = new JPanel();
        panel6.setLayout(new BorderLayout(0, 0));
        panel4.add(panel6, BorderLayout.CENTER);
        final JSplitPane splitPane1 = new JSplitPane();
        splitPane1.setDividerSize(1);
        splitPane1.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane1.setResizeWeight(0.5);
        panel6.add(splitPane1, BorderLayout.CENTER);
        final JPanel panel7 = new JPanel();
        panel7.setLayout(new BorderLayout(0, 0));
        splitPane1.setLeftComponent(panel7);
        final JLabel label1 = new JLabel();
        label1.setText("自定义header");
        panel7.add(label1, BorderLayout.NORTH);
        headertextField = new JEditorPane();
        panel7.add(headertextField, BorderLayout.CENTER);
        final JPanel panel8 = new JPanel();
        panel8.setLayout(new BorderLayout(0, 0));
        splitPane1.setRightComponent(panel8);
        final JLabel label2 = new JLabel();
        label2.setText("payload");
        panel8.add(label2, BorderLayout.NORTH);
        payloadtextField = new JEditorPane();
        panel8.add(payloadtextField, BorderLayout.CENTER);
        final JPanel panel9 = new JPanel();
        panel9.setLayout(new BorderLayout(0, 0));
        panel3.add(panel9, BorderLayout.CENTER);
        final JSplitPane splitPane2 = new JSplitPane();
        splitPane2.setDividerSize(1);
        splitPane2.setOrientation(JSplitPane.VERTICAL_SPLIT);
        splitPane2.setResizeWeight(0.5);
        panel9.add(splitPane2, BorderLayout.CENTER);
        final JScrollPane scrollPane1 = new JScrollPane();
        splitPane2.setLeftComponent(scrollPane1);
        Log4jModel log4jModel = new Log4jModel();
        log4jTable = new URLTable(log4jModel);
        scrollPane1.setViewportView(log4jTable);
        final JSplitPane splitPane3 = new JSplitPane();
        splitPane3.setDividerSize(1);
        splitPane3.setResizeWeight(0.5);
        splitPane2.setRightComponent(splitPane3);
        tabbedPane2 = new JTabbedPane();
        splitPane3.setLeftComponent(tabbedPane2);

        HRequestTextEditor = Utils.callbacks.createMessageEditor(Log4jUI.this, true);
        HResponseTextEditor = Utils.callbacks.createMessageEditor(Log4jUI.this, false);
        tabbedPane2.addTab("request", HRequestTextEditor.getComponent());
        tabbedPane3 = new JTabbedPane();
        splitPane3.setRightComponent(tabbedPane3);

        tabbedPane3.addTab("response", HResponseTextEditor.getComponent());


    }

    private void setupData() {
        Utils.callbacks.registerHttpListener(this);
        try {
            // 检测是否开启被动扫描
            ConfigBean log4jPassiveBox = getConfig("log4j", "log4jPassiveScanBox");
            if (log4jPassiveBox.getValue().equals("true")) {
                passiveScan = true;
                passiveBox.setSelected(true);
            } else {
                passiveScan = false;
                passiveBox.setSelected(false);
            }
            // 检测是否开启header检测
            ConfigBean log4jHeaderBox = getConfig("log4j", "log4jHeaderCheckBox");
            headerBox.setSelected(log4jHeaderBox.getValue().equals("true"));
            // 检测是dns还是ip检测
            ConfigBean log4jDnsIpCheckBox = getConfig("log4j", "log4jDnsIpCheckBox");
            if (log4jDnsIpCheckBox.getValue().equals("true")) {
                dnsIpCheckBox.setText("dns");
                dnsIpCheckBox.setSelected(true);
            } else {
                dnsIpCheckBox.setText("ip");
                dnsIpCheckBox.setSelected(false);
            }
            // 检测是否开启原始payload检测
            ConfigBean log4jOrgpayloadCheckBox = getConfig("log4j", "log4jOrgPayloadCheckBox");
            orgpayloadCheckBox.setSelected(log4jOrgpayloadCheckBox.getValue().equals("true"));
            // 检测是否开启白名单域名检测
            ConfigBean log4jWhiteDomainCheckBox = getConfig("log4j", "log4jWhiteDomainCheckBox");
            whiteDomainCheckBox.setSelected(log4jWhiteDomainCheckBox.getValue().equals("true"));
            // 获取白名单域名
            ConfigBean log4jWhiteDomain = getConfig("log4j", "log4jWhiteDomain");
            whiteDomaintextField.setText(log4jWhiteDomain.getValue());
            // 获取自定义header
            List<Log4jBean> log4jHeader = getHeaderList();
            StringBuilder header = new StringBuilder();
            for (Log4jBean log4j : log4jHeader) {
                header.append(log4j.getValue()).append("\n");
            }
            headertextField.setText(header.toString());

            // 获取自定义payload
            List<Log4jBean> log4jPayload = getPayloadList();
            StringBuilder payload = new StringBuilder();
            for (Log4jBean log4j : log4jPayload) {
                payload.append(log4j.getValue()).append("\n");
            }
            payloadtextField.setText(payload.toString());

        } catch (Exception e) {
            Utils.stderr.println("数据库初始化失败,请联系作者");
        }
        // 保存白名单域名
        saveWhiteDomainButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String whiteDomaintextFieldText = whiteDomaintextField.getText();
                ConfigBean log4jWhiteDomain = new ConfigBean("log4j", "log4jWhiteDomain", whiteDomaintextFieldText);
                saveConfig(log4jWhiteDomain);
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 保存header
        saveHeaderButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String headertextFieldText = headertextField.getText();
                // 先删除原有的header
                deleteHeader();
                // 使用\n分割,然后循环保存
                String[] headers = headertextFieldText.split("\n");
                for (String header : headers) {
                    Log4jBean log4jHeader = new Log4jBean("header", header);
                    saveHeader(log4jHeader);
                }
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        // 保存payload
        savePayloadButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String payloadtextFieldText = payloadtextField.getText();
                // 先删除原有的payload
                deletePayload();
                // 使用\n分割,然后循环保存
                String[] payloads = payloadtextFieldText.split("\n");
                for (String payload : payloads) {
                    Log4jBean log4jPayload = new Log4jBean("payload", payload);
                    savePayload(log4jPayload);
                }
                JOptionPane.showMessageDialog(null, "保存成功", "提示", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        refershTableButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                log4jTable.updateUI();
            }
        });

        clearTableButton.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                log.clear();
                HRequestTextEditor.setMessage(new byte[0], true);
                HResponseTextEditor.setMessage(new byte[0], false);
                urlHashList.clear();
                log4jTable.updateUI();
            }
        });
        passiveBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (passiveBox.isSelected()) {
                    passiveScan = true;
                    ConfigBean log4jPassiveBox = new ConfigBean("log4j", "log4jPassiveScanBox", "true");
                    saveConfig(log4jPassiveBox);
                } else {
                    passiveScan = false;
                    ConfigBean log4jPassiveBox = new ConfigBean("log4j", "log4jPassiveScanBox", "false");
                    saveConfig(log4jPassiveBox);
                }
            }
        });
        headerBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (headerBox.isSelected()) {
                    ConfigBean log4jHeaderBox = new ConfigBean("log4j", "log4jHeaderCheckBox", "true");
                    saveConfig(log4jHeaderBox);
                } else {
                    ConfigBean log4jHeaderBox = new ConfigBean("log4j", "log4jHeaderCheckBox", "false");
                    saveConfig(log4jHeaderBox);
                }
            }
        });
        paramBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (paramBox.isSelected()) {
                    ConfigBean log4jParamBox = new ConfigBean("log4j", "log4jParamCheckBox", "true");
                    saveConfig(log4jParamBox);
                } else {
                    ConfigBean log4jParamBox = new ConfigBean("log4j", "log4jParamCheckBox", "false");
                    saveConfig(log4jParamBox);
                }
            }
        });
        dnsIpCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (dnsIpCheckBox.isSelected()) {
                    dnsIpCheckBox.setText("dns");
                    ConfigBean log4jDnsIpCheckBox = new ConfigBean("log4j", "log4jDnsIpCheckBox", "true");
                    saveConfig(log4jDnsIpCheckBox);
                } else {
                    dnsIpCheckBox.setText("ip");
                    ConfigBean log4jDnsIpCheckBox = new ConfigBean("log4j", "log4jDnsIpCheckBox", "false");
                    saveConfig(log4jDnsIpCheckBox);
                }
            }
        });

        orgpayloadCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (orgpayloadCheckBox.isSelected()) {
                    ConfigBean log4jOrgpayloadCheckBox = new ConfigBean("log4j", "log4jOrgPayloadCheckBox", "true");
                    saveConfig(log4jOrgpayloadCheckBox);
                } else {
                    ConfigBean log4jOrgpayloadCheckBox = new ConfigBean("log4j", "log4jOrgPayloadCheckBox", "false");
                    saveConfig(log4jOrgpayloadCheckBox);
                }
            }
        });
        whiteDomainCheckBox.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (whiteDomainCheckBox.isSelected()) {
                    ConfigBean log4jWhiteDomainCheckBox = new ConfigBean("log4j", "log4jWhiteDomainCheckBox", "true");
                    saveConfig(log4jWhiteDomainCheckBox);
                } else {
                    ConfigBean log4jWhiteDomainCheckBox = new ConfigBean("log4j", "log4jWhiteDomainCheckBox", "false");
                    saveConfig(log4jWhiteDomainCheckBox);
                }
            }
        });

    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, final IHttpRequestResponse iHttpRequestResponse) {

        if (passiveScan && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
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
        return "log4j";
    }

    static class Log4jModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return log.size();
        }

        @Override
        public int getColumnCount() {
            return 5;
        }

        @Override
        public String getColumnName(int column) {
            switch (column) {
                case 0:
                    return "#";
                case 1:
                    return "Method";
                case 2:
                    return "URL";
                case 3:
                    return "Status";
                case 4:
                    return "Length";
                default:
                    return "";
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            LogEntry logEntry = log.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.extensionMethod;
                case 2:
                    return logEntry.url;
                case 3:
                    return logEntry.res;
                case 4:
                    return logEntry.length;
                default:
                    return null;
            }
        }
    }

    public static class LogEntry {
        final int id;
        final String extensionMethod;
        final String url;
        final String length;
        final String res;

        final IHttpRequestResponse requestResponse;

        public LogEntry(int id, String extensionMethod, String url, String res, String length, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.extensionMethod = extensionMethod;
            this.url = url;
            this.length = length;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            LogEntry logEntry = log.get(rowIndex);
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
}
