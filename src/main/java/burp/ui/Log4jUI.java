package burp.ui;

import burp.*;
import burp.bean.Log4jBean;
import burp.utils.I18nUtils;
import burp.utils.JsonUtils;
import burp.utils.Utils;
import burp.utils.UrlCacheUtil;
import com.alibaba.fastjson.JSON;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.net.URL;
import java.util.List;
import java.util.*;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.IParameter.*;
import static burp.dao.ConfigDao.getConfig;
import static burp.dao.Log4jDao.*;

public class Log4jUI extends AbstractScanUI {
    private JCheckBox originalValueCheckBox; // 原始payload值选择框
    private JCheckBox checkHeaderCheckBox; // 检测header选择框
    private JCheckBox isDnsOrIpCheckBox; // 是否是dns或者ip选择框
    private JCheckBox checkWhiteListCheckBox; // 白名单域名检测选择框
    private JCheckBox checkParmamCheckBox; // 检测参数选择框
    private JButton saveWhiteListButton; // 保存白名单域名按钮
    private JButton saveHeaderListButton; // 保存header按钮
    private JButton savePayloadButton; // 保存log4j payload按钮
    private JButton refreshTableButton; // 刷新表格按钮
    private JButton clearTableButton;// 清空表格按钮
    private JTextArea whiteListTextArea; // 白名单域名输入框
    private JTextArea headerTextArea; // header输入框
    private JTextArea payloadTextArea; // payload输入框
    private JScrollPane urltablescrollpane; // url table scroll pane

    private static final List<Log4jUIEntry> log4jlog = new ArrayList<>();
    private static boolean isPassiveScan; // 是否是被动扫描
    private static boolean isOriginalValue; // 是否删除原始值
    private static boolean isCheckHeader; // 是否检测header
    private static boolean isCheckParam; // 是否检测参数
    private static boolean isDnsOrIp; // 是否是dns或者ip
    private static boolean isCheckWhiteList; // 是否检测白名单
    private static Set<String> log4jPayload = new LinkedHashSet<>(); // 存储log4j payload
    private static List<String> payloadList = new ArrayList<>(); // payload列表
    private static List<String> domainList = new ArrayList<>(); // 白名单域名
    private static List<String> headerList = new ArrayList<>(); // header列表
    public static String dns;
    public static String ip;
    private static final Lock lock = new ReentrantLock();

    public static void resetAllCaches() {
        urlHashList.clear();
        parameterList.clear();
        UrlCacheUtil.resetCache("log4j");
    }

    @Override
    protected void setupScanUI() {
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);

        resultTable = new URLTable(new Log4jTableModel(log4jlog));
        urltablescrollpane = new JScrollPane(resultTable);

        // 被动扫描选择框
        passiveScanCheckBox = new JCheckBox(I18nUtils.get("log4j.checkbox.passive"));
        originalValueCheckBox = new JCheckBox(I18nUtils.get("log4j.checkbox.original"));
        checkParmamCheckBox = new JCheckBox(I18nUtils.get("log4j.checkbox.params"));
        checkHeaderCheckBox = new JCheckBox(I18nUtils.get("log4j.checkbox.headers"));
        checkWhiteListCheckBox = new JCheckBox(I18nUtils.get("log4j.checkbox.whitelist"));
        isDnsOrIpCheckBox = new JCheckBox(I18nUtils.get("log4j.checkbox.dns_ip"));

        saveWhiteListButton = new JButton(I18nUtils.get("log4j.button.save_whitelist"));
        saveHeaderListButton = new JButton(I18nUtils.get("log4j.button.save_header"));
        whiteListTextArea = new JTextArea(5, 10);
        whiteListTextArea.setLineWrap(false);
        whiteListTextArea.setWrapStyleWord(false);
        headerTextArea = new JTextArea(5, 10);
        headerTextArea.setLineWrap(false);
        headerTextArea.setWrapStyleWord(false);

        refreshTableButton = new JButton(I18nUtils.get("log4j.button.refresh"));
        clearTableButton = new JButton(I18nUtils.get("log4j.button.clear"));

        JLabel whiteDomainListLabel = new JLabel(I18nUtils.get("log4j.label.whitelist"));
        JLabel headerLabel = new JLabel(I18nUtils.get("log4j.label.header"));

        // 右边的上部分
        JPanel rightTopPanel = new JPanel(new BorderLayout());
        rightTopPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        JPanel scanOptionsPanel = new JPanel(new GridLayout(2, 3, 5, 5));
        scanOptionsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("log4j.border.scan_options")));
        scanOptionsPanel.add(passiveScanCheckBox);
        scanOptionsPanel.add(originalValueCheckBox);
        scanOptionsPanel.add(checkParmamCheckBox);
        scanOptionsPanel.add(checkHeaderCheckBox);
        scanOptionsPanel.add(checkWhiteListCheckBox);
        scanOptionsPanel.add(isDnsOrIpCheckBox);

        JPanel configPanel = new JPanel(new BorderLayout(5, 5));
        configPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("log4j.border.configuration")));

        JPanel whitelistPanel = new JPanel(new BorderLayout(5, 5));
        whitelistPanel.add(whiteDomainListLabel, BorderLayout.NORTH);
        whitelistPanel.add(new JScrollPane(whiteListTextArea), BorderLayout.CENTER);
        JPanel whitelistButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        whitelistButtonPanel.add(saveWhiteListButton);
        whitelistPanel.add(whitelistButtonPanel, BorderLayout.SOUTH);

        JPanel headerConfigPanel = new JPanel(new BorderLayout(5, 5));
        headerConfigPanel.add(headerLabel, BorderLayout.NORTH);
        headerConfigPanel.add(new JScrollPane(headerTextArea), BorderLayout.CENTER);
        JPanel headerButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        headerButtonPanel.add(saveHeaderListButton);
        headerConfigPanel.add(headerButtonPanel, BorderLayout.SOUTH);

        JSplitPane configSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        configSplitPane.setResizeWeight(0.5);
        configSplitPane.setTopComponent(whitelistPanel);
        configSplitPane.setBottomComponent(headerConfigPanel);
        configPanel.add(configSplitPane, BorderLayout.CENTER);

        JPanel actionButtonsPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        actionButtonsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("log4j.border.actions")));
        actionButtonsPanel.add(refreshTableButton);
        actionButtonsPanel.add(clearTableButton);

        JSplitPane mainRightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainRightSplitPane.setResizeWeight(0.3);
        mainRightSplitPane.setTopComponent(scanOptionsPanel);
        JPanel configAndActionsPanel = new JPanel(new BorderLayout(5, 5));
        configAndActionsPanel.add(configPanel, BorderLayout.CENTER);
        configAndActionsPanel.add(actionButtonsPanel, BorderLayout.SOUTH);
        mainRightSplitPane.setBottomComponent(configAndActionsPanel);
        rightTopPanel.add(mainRightSplitPane, BorderLayout.CENTER);

        // payload区域
        JLabel payloadLabel = new JLabel(I18nUtils.get("log4j.label.payload"));
        payloadTextArea = new JTextArea(5, 10);
        payloadTextArea.setLineWrap(false);
        payloadTextArea.setWrapStyleWord(false);
        savePayloadButton = new JButton(I18nUtils.get("log4j.button.save_payload"));
        JPanel payloadPanel = new JPanel(new BorderLayout(5, 5));
        payloadPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        payloadPanel.add(payloadLabel, BorderLayout.NORTH);
        payloadPanel.add(new JScrollPane(payloadTextArea), BorderLayout.CENTER);
        JPanel payloadButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        payloadButtonPanel.add(savePayloadButton);
        payloadPanel.add(payloadButtonPanel, BorderLayout.SOUTH);

        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplitPane.setResizeWeight(0.7);
        rightSplitPane.setTopComponent(rightTopPanel);
        rightSplitPane.setBottomComponent(payloadPanel);

        // 主体：左边表格+编辑器，右边配置
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        leftSplitPane.setResizeWeight(0.65);
        leftSplitPane.setLeftComponent(urltablescrollpane);

        JSplitPane editorSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        editorSplit.setResizeWeight(0.5);
        editorSplit.setLeftComponent(requestTabPane);
        editorSplit.setRightComponent(responseTabPane);
        leftSplitPane.setRightComponent(editorSplit);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.65);
        mainSplit.setLeftComponent(leftSplitPane);
        mainSplit.setRightComponent(rightSplitPane);

        panel.add(mainSplit, BorderLayout.CENTER);
    }

    @Override
    protected void loadSavedData() {
        // 被动扫描选择框
        passiveScanCheckBox.addActionListener(e -> isPassiveScan = passiveScanCheckBox.isSelected());
        originalValueCheckBox.addActionListener(e -> isOriginalValue = originalValueCheckBox.isSelected());
        checkHeaderCheckBox.addActionListener(e -> isCheckHeader = checkHeaderCheckBox.isSelected());
        checkParmamCheckBox.addActionListener(e -> isCheckParam = checkParmamCheckBox.isSelected());
        isDnsOrIpCheckBox.addActionListener(e -> {
            dns = getConfig("config", "dnslog").getValue();
            ip = getConfig("config", "ip").getValue();
            isDnsOrIp = isDnsOrIpCheckBox.isSelected();
            isDnsOrIpCheckBox.setText(isDnsOrIp ? "DNS" : "IP");
        });
        checkWhiteListCheckBox.addActionListener(e -> isCheckWhiteList = checkWhiteListCheckBox.isSelected());

        // 初始化白名单
        List<Log4jBean> domain = getLog4jListsByType("domain");
        for (Log4jBean bean : domain) {
            whiteListTextArea.setText(whiteListTextArea.getText() + bean.getValue() + "\n");
            domainList.add(bean.getValue());
        }
        List<Log4jBean> header = getLog4jListsByType("header");
        for (Log4jBean bean : header) {
            headerTextArea.setText(headerTextArea.getText() + bean.getValue() + "\n");
            headerList.add(bean.getValue());
        }
        List<Log4jBean> payload = getLog4jListsByType("payload");
        for (Log4jBean bean : payload) {
            payloadTextArea.setText(payloadTextArea.getText() + bean.getValue() + "\n");
            payloadList.add(bean.getValue());
        }

        // 按钮事件
        saveWhiteListButton.addActionListener(e -> {
            deleteLog4jByType("domain");
            for (String s : whiteListTextArea.getText().split("\n")) {
                if (s.trim().isEmpty()) continue;
                saveLog4j(new Log4jBean("domain", s.trim()));
            }
            domainList.clear();
            getLog4jListsByType("domain").forEach(b -> domainList.add(b.getValue()));
            whiteListTextArea.updateUI();
            showSaveSuccess();
        });
        saveHeaderListButton.addActionListener(e -> {
            deleteLog4jByType("header");
            for (String s : headerTextArea.getText().split("\n")) {
                if (s.trim().isEmpty()) continue;
                saveLog4j(new Log4jBean("header", s.trim()));
            }
            headerList.clear();
            getLog4jListsByType("header").forEach(b -> headerList.add(b.getValue()));
            headerTextArea.updateUI();
            showSaveSuccess();
        });
        savePayloadButton.addActionListener(e -> {
            deleteLog4jByType("payload");
            for (String s : payloadTextArea.getText().split("\n")) {
                if (s.trim().isEmpty()) continue;
                saveLog4j(new Log4jBean("payload", s.trim()));
            }
            payloadList.clear();
            getLog4jListsByType("payload").forEach(b -> payloadList.add(b.getValue()));
            payloadTextArea.updateUI();
            showSaveSuccess();
        });
        refreshTableButton.addActionListener(e -> resultTable.updateUI());
        clearTableButton.addActionListener(e -> {
            log4jlog.clear();
            clearResults();
            urlHashList.clear();
            UrlCacheUtil.resetCache("log4j");
            resultTable.updateUI();
        });
    }

    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
        Check(requestResponses, isManual);
    }

    @Override
    protected String getScanName() {
        return "Log4j";
    }

    @Override
    public String getTabName() {
        return "Log4jScan";
    }

    // 添加数据
    public static void add(String extensionMethod, String url, String status, String res, IHttpRequestResponse baseRequestResponse) {
        synchronized (log4jlog) {
            int id = log4jlog.size();
            log4jlog.add(new Log4jUIEntry(id, extensionMethod, url, status, res, baseRequestResponse));
        }
        SwingUtilities.invokeLater(() -> resultTable.updateUI());
    }

    // 获取请求包的tag
    private static String getReqTag(IHttpRequestResponse baseRequestResponse, IRequestInfo req, String type) {
        String uri = req.getHeaders().get(0).split(" ")[1].split("\\?")[0].replace("/", ".");
        if (uri.length() > 25) {
            uri = uri.substring(0, uri.endsWith(".") ? uri.length() - 1 : uri.length());
        }
        if (uri.endsWith(".")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        String tag = req.getMethod() + "." + baseRequestResponse.getHttpService().getHost() + uri;
        return "dns".equalsIgnoreCase(type) ? tag + "." : tag;
    }

    // 检测核心方法
    public static void Check(IHttpRequestResponse[] messageInfo, boolean isSend) {
        lock.lock();
        try {
            IHttpRequestResponse baseRequestResponse = messageInfo[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            List<String> reqheaders = analyzeRequest.getHeaders();
            String method = analyzeRequest.getMethod();
            String host = baseRequestResponse.getHttpService().getHost();
            URL rdurlURL = analyzeRequest.getUrl();
            String url = rdurlURL.toString();
            List<IParameter> paraLists = analyzeRequest.getParameters();

            if (!method.equals("GET") && !method.equals("POST")) return;
            if (Utils.isUrlBlackListSuffix(url)) return;
            if (!isCheckParam && !isCheckHeader) return;

            boolean ruleHit = true;
            for (IParameter para : paraLists) {
                if ((para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON)
                        || isCheckHeader) {
                    ruleHit = false;
                    break;
                }
            }
            if (ruleHit) return;

            if (!isSend) {
                if (!UrlCacheUtil.checkUrlUnique("log4j", method, rdurlURL, paraLists)) return;
            } else {
                isCheckWhiteList = false;
            }

            if (isCheckWhiteList && !Utils.isMatchDomainName(host, domainList)) return;

            log4jPayload.clear();
            for (String log4j : payloadList) {
                if (isOriginalValue) {
                    log4jPayload.add(log4j);
                } else if (log4j.contains("dnslog-url")) {
                    if (isDnsOrIp) {
                        String logPrefix = getReqTag(baseRequestResponse, analyzeRequest, "dns");
                        log4jPayload.add(log4j.replace("dnslog-url", logPrefix + "log4j." + dns));
                    } else {
                        String logPrefix = getReqTag(baseRequestResponse, analyzeRequest, "ip");
                        log4jPayload.add(log4j.replace("dnslog-url", ip + "/log4j." + logPrefix));
                    }
                } else {
                    log4jPayload.add(log4j);
                }
            }

            // 检测参数
            if (isCheckParam) {
                for (IParameter para : paraLists) {
                    if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON) {
                        String paraName = para.getName();
                        if (para.getType() == PARAM_URL || para.getType() == PARAM_BODY) {
                            for (String logPayload : log4jPayload) {
                                if (para.getType() == PARAM_URL) logPayload = Utils.UrlEncode(logPayload);
                                IParameter iParameter = Utils.helpers.buildParameter(paraName, logPayload, para.getType());
                                byte[] bytes = Utils.helpers.updateParameter(baseRequestResponse.getRequest(), iParameter);
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                                String ParamLength = getResponseLength(newRequestResponse);
                                add(method, url, String.valueOf(Utils.helpers.analyzeResponse(newRequestResponse.getResponse()).getStatusCode()), ParamLength, newRequestResponse);
                            }
                        }
                        if (para.getType() == PARAM_JSON) {
                            for (String logPayload : log4jPayload) {
                                String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                                Map<String, Object> request_json = JSON.parseObject(request_data);
                                List<Object> objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(logPayload), 0);
                                String json = objectList.stream().map(Object::toString).findFirst().orElse("");
                                byte[] bytes = Utils.callbacks.getHelpers().buildHttpMessage(reqheaders, json.getBytes());
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                                String ParamLength = getResponseLength(newRequestResponse);
                                add(method, url, String.valueOf(Utils.helpers.analyzeResponse(newRequestResponse.getResponse()).getStatusCode()), ParamLength, newRequestResponse);
                            }
                            break;
                        }
                    }
                }
            }

            // 检测header
            if (isCheckHeader) {
                byte[] byte_Request = baseRequestResponse.getRequest();
                int bodyOffset = analyzeRequest.getBodyOffset();
                byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, byte_Request.length);
                for (String logPayload : log4jPayload) {
                    List<String> reqheaders2 = new ArrayList<>(Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders());
                    List<String> newReqheaders = new ArrayList<>();
                    Iterator<String> iterator = reqheaders2.iterator();
                    while (iterator.hasNext()) {
                        String reqheader = iterator.next();
                        for (String header : headerList) {
                            if (reqheader.contains(header)) {
                                iterator.remove();
                                String newHeader = header + ": " + logPayload;
                                if (!newReqheaders.contains(newHeader)) newReqheaders.add(newHeader);
                            }
                        }
                    }
                    for (String header : headerList) {
                        newReqheaders.add(header + ": " + logPayload);
                    }
                    reqheaders2.addAll(newReqheaders);
                    byte[] postMessage = Utils.helpers.buildHttpMessage(reqheaders2, body);
                    IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
                    String originallength = getResponseLength(originalRequestResponse);
                    String statusCode = originalRequestResponse.getResponse() != null ?
                            String.valueOf(Utils.helpers.analyzeResponse(originalRequestResponse.getResponse()).getStatusCode()) : "";
                    add(method, url, statusCode, originallength, originalRequestResponse);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    private static String getResponseLength(IHttpRequestResponse response) {
        if (response.getResponse() != null) {
            IResponseInfo info = Utils.helpers.analyzeResponse(response.getResponse());
            String cl = HelperPlus.getHeaderValueOf(info.getHeaders(), "Content-Length");
            if (cl != null) return cl;
        }
        return response.getResponse() != null ? String.valueOf(response.getResponse().length) : "0";
    }

    private void showSaveSuccess() {
        JOptionPane.showMessageDialog(null, I18nUtils.get("config.message.save_success"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
    }

    // url 表格
    class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            setAutoCreateRowSorter(true);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            int modelRow = rowIndex;
            if (getRowSorter() != null) {
                modelRow = convertRowIndexToModel(rowIndex);
            }
            Log4jUIEntry logEntry = log4jlog.get(modelRow);
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
}

