package burp.ui;

import burp.*;
import burp.bean.Config;
import burp.bean.Log4j;
import burp.bean.Sql;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;

import static burp.IParameter.*;
import static burp.IParameter.PARAM_JSON;
import static burp.dao.ConfigDAO.getValueByModuleAndType;
import static burp.dao.ConfigDAO.updateConfigSetting;
import static burp.dao.Log4jDAO.*;
import static burp.dao.SqlDAO.getSqliList;
import static burp.utils.Utils.getSuffix;

public class Log4jUI extends AbstractTableModel implements UIHandler, IMessageEditorController,IHttpListener {
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    private static final List<Log4jUI.LogEntry> log = new ArrayList<>();
    private IHttpRequestResponse currentlyDisplayedItem;
    private IMessageEditor HRequestTextEditor;
    private IMessageEditor HResponseTextEditor;
    private JPanel panel1;
    private JSplitPane splitPane1;
    private JSplitPane splitPane2;
    private JScrollPane scrollPane1;
    private JTable table1;
    private JSplitPane splitPane3;
    private JTabbedPane ltable;
    private JTabbedPane rtable;
    private JPanel panel2;
    private JSplitPane splitPane11;
    private JPanel panel22;
    private JCheckBox startPluginBox;
    private JCheckBox startHeaderBox;
    private JCheckBox startWhiteBox;
    private JPanel panel11;
    private JButton refershButton;
    private JButton deleteSelectButton;
    private JButton clearTableButton;
    private JButton saveHeaderButton;
    private JButton savePayloadButton;
    private JSplitPane splitPane22;
    private JSplitPane splitPane44;
    private JLabel customHeaderLabel;
    private JTextArea customHeaderText;
    private JSplitPane splitPane33;
    private JLabel log4jPayloadLabel;
    private JTextArea log4jPayloadText;
    private JSplitPane splitPane112;
    private JPanel panel1121;
    private JPanel panel1122;
    private JLabel label1;
    private JScrollPane scrollPane1131;
    private JTextField whiteDomainText;
    private JButton saveDomainButton;
    private JCheckBox originalPayloadBox;
    private JCheckBox dnsSelectBox;
    private boolean enableHeader;
    private boolean startPlugin;
    private boolean enableWhiteDomain;
    private boolean originalPayload;


    @Override
    public void init() {

    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.registerHttpListener(this); // 注册被动扫描监听器
        this.helpers = callbacks.getHelpers();

        panel1 = new JPanel(new BorderLayout());
        splitPane1 = new JSplitPane();
        splitPane2 = new JSplitPane();
        scrollPane1 = new JScrollPane();
        table1 = new URLTable(this);
        splitPane3 = new JSplitPane();
        ltable = new JTabbedPane();
        rtable = new JTabbedPane();
        panel2 = new JPanel();
        BoxLayout boxLayout = new BoxLayout(panel2, BoxLayout.Y_AXIS);
        panel2.setLayout(boxLayout);

        splitPane11 = new JSplitPane();
        panel22 = new JPanel();
        splitPane112 = new JSplitPane();
        panel1121 = new JPanel();
        startPluginBox = new JCheckBox();
        startHeaderBox = new JCheckBox();
        startWhiteBox = new JCheckBox();
        panel1122 = new JPanel();
        label1 = new JLabel();
        scrollPane1131 = new JScrollPane();
        whiteDomainText = new JTextField();
        panel11 = new JPanel();
        refershButton = new JButton();
        deleteSelectButton = new JButton();
        clearTableButton = new JButton();
        saveHeaderButton = new JButton();
        savePayloadButton = new JButton();
        splitPane22 = new JSplitPane();
        splitPane44 = new JSplitPane();
        customHeaderLabel = new JLabel();
        customHeaderText = new JTextArea();
        splitPane33 = new JSplitPane();
        log4jPayloadLabel = new JLabel();
        log4jPayloadText = new JTextArea();
        saveDomainButton = new JButton();
        originalPayloadBox = new JCheckBox();
        dnsSelectBox = new JCheckBox();

        //======== this ========

        //======== splitPane11 ========
        {
            splitPane11.setOrientation(JSplitPane.VERTICAL_SPLIT);
            splitPane11.setResizeWeight(0.5);
            splitPane11.setDividerSize(2);

            //======== panel22 ========
            {
                panel22.setLayout(new BoxLayout(panel22, BoxLayout.X_AXIS));

                //======== splitPane112 ========
                {
                    splitPane112.setOrientation(JSplitPane.VERTICAL_SPLIT);

                    //======== panel1121 ========
                    {
                        panel1121.setLayout(new BoxLayout(panel1121, BoxLayout.X_AXIS));

                        //---- startPluginBox ----
                        startPluginBox.setText("启动插件");
                        panel1121.add(startPluginBox);

                        //---- startHeaderBox ----
                        startHeaderBox.setText("启用header");
                        panel1121.add(startHeaderBox);

                        //---- startWhiteBox ----
                        startWhiteBox.setText("启用白名单");
                        panel1121.add(startWhiteBox);

                        originalPayloadBox.setText("启用原始payload");
                        panel1121.add(originalPayloadBox);

                        dnsSelectBox.setText("dns");
                        panel1121.add(dnsSelectBox);
                    }
                    splitPane112.setTopComponent(panel1121);

                    //======== panel1122 ========
                    {
                        panel1122.setLayout(null);

                        //---- label1 ----
                        label1.setText("填写白名单域名");
                        panel1122.add(label1);
                        label1.setBounds(new Rectangle(new Point(55, 30), label1.getPreferredSize()));

                        //======== scrollPane1131 ========
                        {

                            //---- whiteDomainText ----
                            whiteDomainText.setMinimumSize(new Dimension(20, 30));
                            whiteDomainText.setMaximumSize(new Dimension(20, 20));
                            Config config = getValueByModuleAndType("log4j", "whiteLog4jDomain");
                            whiteDomainText.setText(config.getValue());
                            scrollPane1131.setViewportView(whiteDomainText);
                        }
                        panel1122.add(scrollPane1131);
                        scrollPane1131.setBounds(160, 20, 205, 35);

                        saveDomainButton.setText("保存");
                        panel1122.add(saveDomainButton);
                        saveDomainButton.setBounds(new Rectangle(new Point(390, 25), saveDomainButton.getPreferredSize()));

                        JTextArea textArea2 = new JTextArea();
                        textArea2.setText("启用原始payload时,payload中不能包含dnslog-url\n,需要是可直接执行的,反之");
                        panel1122.add(textArea2);
                        textArea2.setBounds(80, 70, 305, 40);
                        {
                            // compute preferred size
                            Dimension preferredSize = new Dimension();
                            for (int i = 0; i < panel1122.getComponentCount(); i++) {
                                Rectangle bounds = panel1122.getComponent(i).getBounds();
                                preferredSize.width = Math.max(bounds.x + bounds.width, preferredSize.width);
                                preferredSize.height = Math.max(bounds.y + bounds.height, preferredSize.height);
                            }
                            Insets insets = panel1122.getInsets();
                            preferredSize.width += insets.right;
                            preferredSize.height += insets.bottom;
                            panel1122.setMinimumSize(preferredSize);
                            panel1122.setPreferredSize(preferredSize);
                        }
                    }
                    splitPane112.setBottomComponent(panel1122);
                }
                panel22.add(splitPane112);
            }
            splitPane11.setTopComponent(panel22);

            //======== panel11 ========
            {
                panel11.setLayout(new BoxLayout(panel11, BoxLayout.X_AXIS));

                //---- refershButton ----
                refershButton.setText("刷新表格");
                panel11.add(refershButton);

                //---- deleteSelectButton ----
                deleteSelectButton.setText("删除选中数据");
                panel11.add(deleteSelectButton);

                //---- clearTableButton ----
                clearTableButton.setText("清空表格");
                panel11.add(clearTableButton);

                //---- saveHeaderButton ----
                saveHeaderButton.setText("保存header");
                panel11.add(saveHeaderButton);

                //---- savePayloadButton ----
                savePayloadButton.setText("保存payload");
                panel11.add(savePayloadButton);
            }
            splitPane11.setBottomComponent(panel11);
        }

        //======== splitPane22 ========
        {
            splitPane22.setOrientation(JSplitPane.VERTICAL_SPLIT);
            splitPane22.setResizeWeight(0.5);
            splitPane22.setDividerSize(2);

            //======== splitPane44 ========
            {
                splitPane44.setOrientation(JSplitPane.VERTICAL_SPLIT);
                splitPane44.setDividerSize(2);

                //---- customHeaderLabel ----
                customHeaderLabel.setText("自定义header");
                customHeaderLabel.setHorizontalAlignment(SwingConstants.CENTER);
                StringBuilder headerListBuilder = new StringBuilder();
                List<Log4j> headerList = getHeaderList();
                for (Log4j log4j : headerList) {
                    headerListBuilder.append(log4j.getHeader()).append("\n");
                }
                customHeaderText.setText(headerListBuilder.toString());
                customHeaderText.setPreferredSize(new Dimension(500, 100));
                splitPane44.setTopComponent(customHeaderLabel);
                splitPane44.setBottomComponent(customHeaderText);
            }
            splitPane22.setTopComponent(splitPane44);

            //======== splitPane33 ========
            {
                splitPane33.setOrientation(JSplitPane.VERTICAL_SPLIT);
                splitPane33.setDividerSize(2);

                //---- log4jPayloadLabel ----
                log4jPayloadLabel.setText("log4j payload");
                log4jPayloadLabel.setHorizontalAlignment(SwingConstants.CENTER);
                StringBuilder payloadListBuilder = new StringBuilder();
                List<Log4j> payloadList = getPayloadList();
                for (Log4j log4j : payloadList) {
                    payloadListBuilder.append(log4j.getPayload()).append("\n");
                }
                log4jPayloadText.setText(payloadListBuilder.toString());
                log4jPayloadText.setPreferredSize(new Dimension(500, 100));
                splitPane33.setTopComponent(log4jPayloadLabel);
                splitPane33.setBottomComponent(log4jPayloadText);
            }
            splitPane22.setBottomComponent(splitPane33);
        }


        panel2.add(splitPane11);
        panel2.add(splitPane22);

        // 主分隔面板
        splitPane1 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane1.setResizeWeight(0.5D);
        // 任务栏面板上下
        splitPane2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        scrollPane1 = new JScrollPane(table1);

        // 任务栏数据面板左右
        splitPane3 = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane3.setResizeWeight(0.5D);
        HRequestTextEditor = callbacks.createMessageEditor(Log4jUI.this, true);
        HResponseTextEditor = callbacks.createMessageEditor(Log4jUI.this, true);
        ltable.addTab("Request", HRequestTextEditor.getComponent());
        rtable.addTab("Response", HResponseTextEditor.getComponent());
        splitPane3.add(ltable, "left");
        splitPane3.add(rtable, "right");

        splitPane2.add(scrollPane1, "left");
        splitPane2.add(splitPane3, "right");


        splitPane1.add(splitPane2, "left");
        splitPane1.add(panel2, "right");

        panel1.add(splitPane1, BorderLayout.CENTER);

        // 事件
        // 刷新按钮
        refershButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                fireTableDataChanged();
            }
        });

        // 删除选中按钮
        deleteSelectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int[] rows = table1.getSelectedRows();
                for (int i = rows.length - 1; i >= 0; i--) {
                    log.remove(rows[i]);
                    fireTableRowsDeleted(rows[i], rows[i]);
                    HRequestTextEditor.setMessage(new byte[0], false);
                    HResponseTextEditor.setMessage(new byte[0], false);
                }
                fireTableDataChanged();
            }
        });

        // 清空按钮
        clearTableButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                log.clear();
                fireTableDataChanged();
                HRequestTextEditor.setMessage(new byte[0], false);
                HResponseTextEditor.setMessage(new byte[0], false);
            }
        });

        // 保存header按钮
        saveHeaderButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String customHeaderTextText = customHeaderText.getText();
                if (customHeaderTextText.equals("")) {
                    JOptionPane.showMessageDialog(null, "header不能为空", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Log4j log4j = new Log4j();
                if (customHeaderTextText.contains("\\n")) {
                    String[] customHeaders = customHeaderTextText.split("\\n");
                    for (String customHeader : customHeaders) {
                        log4j.setHeader(customHeader);
                    }
                } else {
                    log4j.setHeader(customHeaderTextText);
                }
                saveHeader(log4j);

            }
        });

        // 保存payload按钮
        savePayloadButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String log4jPayloadTextText = log4jPayloadText.getText();
                if (log4jPayloadTextText.equals("")) {
                    JOptionPane.showMessageDialog(null, "payload不能为空", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Log4j log4j = new Log4j();
                if (log4jPayloadTextText.contains("\\n")) {
                    String[] log4jPayloads = log4jPayloadTextText.split("\\n");
                    for (String log4jPayload : log4jPayloads) {
                        log4j.setPayload(log4jPayload);
                    }
                } else {
                    log4j.setPayload(log4jPayloadTextText);
                }
                savePayload(log4j);
            }
        });

        // 保存域名
        saveDomainButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String domainTextText = whiteDomainText.getText();
                if (domainTextText.equals("")) {
                    JOptionPane.showMessageDialog(null, "域名不能为空", "提示", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Config config = new Config();
                config.setModule("log4j");
                config.setType("whiteLog4jDomain");
                config.setValue(domainTextText);
                updateConfigSetting(config);
            }
        });

        // 初始化配置
        // 初始化是否启动插件
        Config log4jStartPlugin = getValueByModuleAndType("log4j", "startPlugin");
        if (log4jStartPlugin.getValue().equals("true")) {
            startPlugin = true;
            startPluginBox.setSelected(true);
            customHeaderText.setEnabled(false);
            log4jPayloadText.setEnabled(false);
        } else {
            startPlugin = false;
            startPluginBox.setSelected(false);
            customHeaderText.setEnabled(true);
            log4jPayloadText.setEnabled(true);
        }
        // 初始化是否启动header
        Config log4jStartHeaderBox = getValueByModuleAndType("log4j", "enableHeader");
        startHeaderBox.setSelected(log4jStartHeaderBox.getValue().equals("true"));
        // 初始化是否启用白名单
        Config log4jStartWhiteBox = getValueByModuleAndType("log4j", "whitedomainStatus");
        startWhiteBox.setSelected(log4jStartWhiteBox.getValue().equals("true"));
        // 初始化是否启用原始payload
        Config log4jOriginalPayloadBox = getValueByModuleAndType("log4j", "originalPayload");
        originalPayloadBox.setSelected(log4jOriginalPayloadBox.getValue().equals("true"));
        // 初始化是否是dns
        Config log4jDnsBox = getValueByModuleAndType("log4j", "dns");
        dnsSelectBox.setSelected(log4jDnsBox.getValue().equals("true"));

        // 启动插件
        startPluginBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (startPluginBox.isSelected()) {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("startPlugin");
                    config.setValue("true");
                    updateConfigSetting(config);
                    startPlugin = true;
                    customHeaderText.setEnabled(false);
                    log4jPayloadText.setEnabled(false);
                } else {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("startPlugin");
                    config.setValue("false");
                    startPlugin = false;
                    updateConfigSetting(config);
                    customHeaderText.setEnabled(true);
                    log4jPayloadText.setEnabled(true);
                }
            }
        });
        // 启用header
        startHeaderBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (startHeaderBox.isSelected()) {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("enableHeader");
                    config.setValue("true");
                    updateConfigSetting(config);
                } else {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("enableHeader");
                    config.setValue("false");
                    updateConfigSetting(config);
                }
            }
        });

        // 启用白名单
        startWhiteBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (startWhiteBox.isSelected()) {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("whitedomainStatus");
                    config.setValue("true");
                    updateConfigSetting(config);
                } else {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("whitedomainStatus");
                    config.setValue("false");
                    updateConfigSetting(config);
                }
            }
        });

        // 启用原始payload
        originalPayloadBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (originalPayloadBox.isSelected()) {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("originalPayload");
                    config.setValue("true");
                    updateConfigSetting(config);
                } else {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("originalPayload");
                    config.setValue("false");
                    updateConfigSetting(config);
                }
            }
        });
        dnsSelectBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (dnsSelectBox.isSelected()) {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("dns");
                    config.setValue("true");
                    updateConfigSetting(config);
                } else {
                    Config config = new Config();
                    config.setModule("log4j");
                    config.setType("dns");
                    config.setValue("false");
                    updateConfigSetting(config);
                }
            }
        });

        return panel1;
    }

    public void CheckLog4j(IHttpRequestResponse[] responses) {
        IHttpRequestResponse baseRequestResponse = responses[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<String> reqheaders = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        String method = analyzeRequest.getMethod();
        String url = analyzeRequest.getUrl().toString();
        List<IParameter> paraLists = analyzeRequest.getParameters();
        Config enableHeaderConfig = getValueByModuleAndType("log4j", "enableHeader");
        enableHeader = enableHeaderConfig.getValue().equals("true");
        Config enableWhiteDomainConfig = getValueByModuleAndType("log4j", "whitedomainStatus");
        enableWhiteDomain = enableWhiteDomainConfig.getValue().equals("true");
        Config originalPayloadConfig = getValueByModuleAndType("log4j", "originalPayload");
        originalPayload = originalPayloadConfig.getValue().equals("true");

        // url 中为静态资源，直接返回
        List<String> suffix = getSuffix();
        for (String s : suffix) {
            if (url.endsWith(s) || url.contains(s)) {
                return;
            }
        }

        // url 不是白名单域名，直接返回
        if (enableWhiteDomain) {
            Config whiteSqlDomain = getValueByModuleAndType("log4j", "whiteLog4jDomain");
            if (!url.contains(whiteSqlDomain.getValue())) {
                JOptionPane.showMessageDialog(null, "url不在白名单域名内", "提示", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        // 先将payload存储
        Set<String> log4jPayload = new LinkedHashSet<>();
        List<Log4j> payloadList = getPayloadList();
        for (Log4j log4j : payloadList) {
            if (originalPayload) {
                log4jPayload.add(log4j.getPayload());
            } else {
                if (log4j.getPayload().contains("dnslog-url")) {
                    if (getValueByModuleAndType("log4j", "dns").getValue().equals("true")) {
                        String dns = getValueByModuleAndType("config", "dnslog").getValue();
                        log4jPayload.add(Utils.urlEncode(log4j.getPayload()).replace("dnslog-url", dns));
                    } else {
                        String ip = getValueByModuleAndType("config", "ip").getValue();
                        log4jPayload.add(Utils.urlEncode(log4j.getPayload()).replace("dnslog-url", ip));
                    }
                }else {
                    log4jPayload.add(log4j.getPayload());
                }
            }
        }

        for (IParameter para : paraLists) {
            if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_COOKIE || para.getType() == PARAM_JSON) {
                String paraName = para.getName();
                String paraValue = para.getValue();


                byte[] byte_Request = baseRequestResponse.getRequest();
                int bodyOffset = analyzeRequest.getBodyOffset();
                int len = byte_Request.length;
                byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);

                for (String logPayload : log4jPayload) {

                    // 判断参数是否在url中
                    if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
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
                        if (ParamLength.equals("")) {
                            ParamLength = String.valueOf(sqlresponseBody.length);
                        }
                        add(method, url, ParamstatusCode, ParamLength, newRequestResponse);
                    } else if (para.getType() == PARAM_JSON) {
                        String data = new String(body);
                        if (Utils.isJSON(data)) {//当参数的值是json格式
                            try {
                                data = Utils.updateJSONValue(data, logPayload);
                                byte[] message = Utils.helpers.buildHttpMessage(reqheaders, data.getBytes());
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), message);
                                IResponseInfo analyzeResponse = Utils.helpers.analyzeResponse(newRequestResponse.getResponse());
                                int statusCode = analyzeResponse.getStatusCode();
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

                                }
                                if (sqlLength == 0) {
                                    sqlLength = Integer.parseInt(String.valueOf(sqlresponseBody.length));
                                }
                                add(method, url, String.valueOf(statusCode), String.valueOf(sqlLength), newRequestResponse);

                            } catch (Exception e) {
                                Utils.stderr.println(e.getMessage());

                            }
                        }
                    }


                }

            }
        }

        boolean enableHeader = getValueByModuleAndType("log4j", "enableHeader").getValue().equals("true");
        if (enableHeader){
            byte[] byte_Request = baseRequestResponse.getRequest();
            int bodyOffset = analyzeRequest.getBodyOffset();
            int len = byte_Request.length;
            byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, len);
            List<Log4j> headerList = getHeaderList();
            for (String logPayload : log4jPayload) {
                List<String> reqheaders2 = Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders();
                List<String> newReqheaders = new ArrayList<>();
                Iterator<String> iterator = reqheaders2.iterator();
                while (iterator.hasNext()) {
                    String reqheader = iterator.next();
                    for (Log4j log4j : headerList) {
                        if (reqheader.contains(log4j.getHeader())) {
                            iterator.remove();
                            String newHeader = log4j.getHeader() + ": " + logPayload;
                            if (!newReqheaders.contains(newHeader)) {
                                newReqheaders.add(newHeader);
                            }
                        }
                    }
                }
                for (Log4j log4j : headerList) {
                    String newHeader = log4j.getHeader() + ": " + logPayload;
                    if (!reqheaders2.contains(log4j.getHeader()) && !newReqheaders.contains(newHeader)) {
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
                if (originallength.equals("")) {
                    originallength = String.valueOf(responseBody.length);
                }
                add(method, url, statusCode, originallength, originalRequestResponse);
            }
        }

    }

    public void add(String extensionMethod, String url, String status, String res, IHttpRequestResponse baseRequestResponse) {
        synchronized (log) {
            int id = log.size();
            log.add(new LogEntry(id, extensionMethod, url, status, res, baseRequestResponse));
            fireTableRowsInserted(id, id);
            fireTableDataChanged();
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
    public String getTabName() {
        return "log4j";
    }

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
        Log4jUI.LogEntry logEntry = log.get(rowIndex);
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

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (startPlugin && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest){
            synchronized (log){
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        CheckLog4j(new IHttpRequestResponse[]{messageInfo});
                    }
                });
                thread.start();
            }
        }
    }

    public class LogEntry {
        final int id;
        final String extensionMethod;
        final String url;
        final String length;
        final String res;

        final IHttpRequestResponse requestResponse;

        public LogEntry(int id, String extensionMethod, String url, String length, String res, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.extensionMethod = extensionMethod;
            this.url = url;
            this.length = length;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    private class URLTable extends JTable {
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
