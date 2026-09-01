package burp.ui;

import burp.*;
import burp.bean.Log4jBean;
import burp.utils.HostThrottle;
import burp.utils.HttpMessageUtils;
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

/**
 * Log4j 漏洞检测面板：对 GET/POST 请求的参数与 Header 注入 JNDI payload（dnslog/IP 回连），
 * 支持白名单过滤、原始值替换与被动扫描（IHttpListener）。检测在静态 lock 内串行执行，
 * 目标主机经 HostThrottle 限速；结果入静态有界 ScanResultsStore。
 */
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

    // 主动检测串行锁（同 FastjsonUI.scanLock 的角色）
    private static final Lock lock = new ReentrantLock();
    // 当前面板实例：静态 Check 入口与 BurpExtender 被动回调经此定位到实例
    private static volatile Log4jUI instance;
    /** 结果列表容量上限，超限淘汰最旧条目。 */
    private static final int MAX_LOG_ENTRIES = 2000;
    private static final ScanResultsStore<Log4jUIEntry> log4jlog = new ScanResultsStore<>(MAX_LOG_ENTRIES, () -> {
        Log4jUI ui = instance;
        if (ui != null) {
            ui.refreshTableModel(ui.resultTable);
        }
    });
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

    public static void resetAllCaches() {
        UrlCacheUtil.resetCache("log4j");
    }

    @Override
    protected void setupScanUI() {
        instance = this;
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);

        // 预加载 dns/ip：此前只在勾选 DNS/IP 复选框或 ConfigUI 保存时才读取，
        // 插件重载后直接右键扫描会拼出 "null/log4j.xxx" 垃圾 payload
        dns = safeConfigValue("dnslog");
        ip = safeConfigValue("ip");

        resultTable = new URLTable(new Log4jTableModel(log4jlog.list()));
        urltablescrollpane = new JScrollPane(resultTable);
        urltablescrollpane.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("common.border.results")));

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
        rightTopPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

        JPanel scanOptionsPanel = createCompactOptionsPanel(
                I18nUtils.get("log4j.border.scan_options"),
                passiveScanCheckBox, originalValueCheckBox, checkParmamCheckBox,
                checkHeaderCheckBox, checkWhiteListCheckBox, isDnsOrIpCheckBox);

        JPanel configPanel = new JPanel(new BorderLayout(3, 3));
        configPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("log4j.border.configuration")));

        JPanel whitelistPanel = new JPanel(new BorderLayout(5, 5));
        whitelistPanel.add(whiteDomainListLabel, BorderLayout.NORTH);
        whitelistPanel.add(new JScrollPane(whiteListTextArea), BorderLayout.CENTER);
        JPanel whitelistButtonPanel = createCompactButtonPanel(saveWhiteListButton);
        whitelistPanel.add(whitelistButtonPanel, BorderLayout.SOUTH);

        JPanel headerConfigPanel = new JPanel(new BorderLayout(5, 5));
        headerConfigPanel.add(headerLabel, BorderLayout.NORTH);
        headerConfigPanel.add(new JScrollPane(headerTextArea), BorderLayout.CENTER);
        JPanel headerButtonPanel = createCompactButtonPanel(saveHeaderListButton);
        headerConfigPanel.add(headerButtonPanel, BorderLayout.SOUTH);

        JSplitPane configSplitPane = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.5);
        configSplitPane.setTopComponent(whitelistPanel);
        configSplitPane.setBottomComponent(headerConfigPanel);
        configPanel.add(configSplitPane, BorderLayout.CENTER);

        JPanel actionButtonsPanel = createCompactButtonPanel(refreshTableButton, clearTableButton);
        actionButtonsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("log4j.border.actions")));

        Dimension scanOptionsSize = scanOptionsPanel.getPreferredSize();
        scanOptionsPanel.setMinimumSize(new Dimension(0, Math.max(78, scanOptionsSize.height)));
        JSplitPane mainRightSplitPane = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.28);
        mainRightSplitPane.setTopComponent(scanOptionsPanel);
        JPanel configAndActionsPanel = new JPanel(new BorderLayout(3, 3));
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
        JPanel payloadPanel = new JPanel(new BorderLayout(3, 3));
        payloadPanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
        payloadPanel.add(payloadLabel, BorderLayout.NORTH);
        payloadPanel.add(new JScrollPane(payloadTextArea), BorderLayout.CENTER);
        JPanel payloadButtonPanel = createCompactButtonPanel(savePayloadButton);
        payloadPanel.add(payloadButtonPanel, BorderLayout.SOUTH);

        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        rightSplitPane.setResizeWeight(0.7);
        rightSplitPane.setTopComponent(rightTopPanel);
        rightSplitPane.setBottomComponent(payloadPanel);

        // 主体：左边（表格在上、编辑器在下），右边配置
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setTopComponent(urltablescrollpane);
        leftSplitPane.setBottomComponent(buildEditorSplit());
        applyWeights(leftSplitPane, WEIGHT_TABLE_EDITOR);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setLeftComponent(leftSplitPane);
        mainSplit.setRightComponent(rightSplitPane);
        applyWeights(mainSplit, WEIGHT_MAIN);

        panel.add(mainSplit, BorderLayout.CENTER);
    }

    /**
     * Log4jUI 的全部布局已在 setupScanUI() 中完成（含自定义右侧配置区），
     * 覆盖此方法为空实现，避免基类 setupCommonUI() 重建 panel 丢弃已构建的界面。
     */
    @Override
    protected void setupCommonUI() {
        // 故意为空：布局由 setupScanUI 负责
    }

    @Override
    protected void loadSavedData() {
        // 被动扫描选择框
        passiveScanCheckBox.addActionListener(e -> {
            isPassiveScan = passiveScanCheckBox.isSelected();
            passiveScanEnabled = isPassiveScan;
        });
        originalValueCheckBox.addActionListener(e -> isOriginalValue = originalValueCheckBox.isSelected());
        checkHeaderCheckBox.addActionListener(e -> isCheckHeader = checkHeaderCheckBox.isSelected());
        checkParmamCheckBox.addActionListener(e -> isCheckParam = checkParmamCheckBox.isSelected());
        isDnsOrIpCheckBox.addActionListener(e -> {
            // 配置行缺失时 getConfig 返回 null，直接 getValue 会 NPE；统一走空安全读取
            dns = safeConfigValue("dnslog");
            ip = safeConfigValue("ip");
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
            whiteListTextArea.repaint();
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
            headerTextArea.repaint();
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
            payloadTextArea.repaint();
            showSaveSuccess();
        });
        refreshTableButton.addActionListener(e -> refreshTableModel(resultTable));
        clearTableButton.addActionListener(e -> {
            // store.clear 内部加锁，与扫描线程的 add 互斥
            log4jlog.clear();
            clearResults();
            UrlCacheUtil.resetCache("log4j");
            refreshTableModel(resultTable);
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

    // 添加数据（容量淘汰与表格刷新由 store 统一处理）
    /** 追加一条扫描结果到有界 store（自动刷新表格）。 */
    public static void add(String extensionMethod, String url, String status, String res, IHttpRequestResponse baseRequestResponse) {
        log4jlog.add(id -> new Log4jUIEntry(id, extensionMethod, url, status, res, baseRequestResponse));
    }

    private static String serviceKey(IHttpRequestResponse requestResponse) {
        IHttpService service = requestResponse.getHttpService();
        return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }

    /** 从 config 表（module=config）读取配置值，失败/未配置返回空串（避免 "null" 拼进 payload）。 */
    private static String safeConfigValue(String key) {
        try {
            burp.bean.ConfigBean config = getConfig("config", key);
            return config == null || config.getValue() == null ? "" : config.getValue();
        } catch (Exception e) {
            Utils.stderr.println("Log4j config load failed for " + key + ": " + e.getMessage());
            return "";
        }
    }

    /** 生成请求的 dnslog 标签（method.host.uri，uri 截断 25 字符；dns 类型追加尾点）。 */
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

    /** Log4j 主动检测核心（ScanTaskExecutor 池线程，经右键菜单/扫描按钮调用）：
     *  按参数/Header 注入 payload 并请求目标，按响应长度变化判定疑似命中。 */
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
            // dns/ip 模式所需配置必须有效，否则会拼出无效 payload
            if (isDnsOrIp && (dns == null || dns.trim().isEmpty())) {
                Utils.stderr.println(I18nUtils.get("log4j.message.missing_dns"));
                return;
            }
            if (!isDnsOrIp && (ip == null || ip.trim().isEmpty())) {
                Utils.stderr.println(I18nUtils.get("log4j.message.missing_dns"));
                return;
            }

            boolean ruleHit = true;
            for (IParameter para : paraLists) {
                if ((para.getType() == PARAM_URL || para.getType() == PARAM_BODY || para.getType() == PARAM_JSON)
                        || isCheckHeader) {
                    ruleHit = false;
                    break;
                }
            }
            if (ruleHit) return;

            // 白名单仅在被动模式下生效；用局部变量表达，避免主动扫描重置静态开关
            boolean respectWhitelist = !isSend && isCheckWhiteList;
            if (!isSend) {
                // 去重只按 method+host+port+path：body 参数（token/时间戳）变化不应触发重复全量探测
                if (!UrlCacheUtil.checkUrlUnique("log4j", method, rdurlURL, Collections.<IParameter>emptyList())) return;
            }

            if (respectWhitelist && !Utils.isMatchDomainName(host, domainList)) return;

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
                                HostThrottle.throttle(serviceKey(baseRequestResponse));
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                                if (newRequestResponse == null || newRequestResponse.getResponse() == null) {
                                    Utils.stderr.println("Log4j scan skipped: target returned no response");
                                    continue;
                                }
                                String ParamLength = getResponseLength(newRequestResponse);
                                add(method, url, String.valueOf(Utils.helpers.analyzeResponse(newRequestResponse.getResponse()).getStatusCode()), ParamLength, newRequestResponse);
                            }
                        }
                        if (para.getType() == PARAM_JSON) {
                            // 请求体解析一次上提，避免每个 payload 重复 bytesToString + JSON.parseObject
                            String request_data = Utils.helpers.bytesToString(baseRequestResponse.getRequest()).split("\r\n\r\n")[1];
                            Map<String, Object> request_json = JSON.parseObject(request_data);
                            for (String logPayload : log4jPayload) {
                                List<Object> objectList = JsonUtils.updateJsonObjectFromStr(request_json, Utils.ReplaceChar(logPayload), 0);
                                String json = objectList.stream().map(Object::toString).findFirst().orElse("");
                                byte[] jsonBytes = json.getBytes(java.nio.charset.StandardCharsets.UTF_8);
                                // body 已替换，Content-Length 必须同步重算，否则目标按旧长度截断
                                HttpMessageUtils.setContentLength(reqheaders, jsonBytes.length);
                                byte[] bytes = Utils.callbacks.getHelpers().buildHttpMessage(reqheaders, jsonBytes);
                                HostThrottle.throttle(serviceKey(baseRequestResponse));
                                IHttpRequestResponse newRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), bytes);
                                if (newRequestResponse == null || newRequestResponse.getResponse() == null) {
                                    Utils.stderr.println("Log4j scan skipped: target returned no response");
                                    continue;
                                }
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
                // 请求头解析一次上提，避免每个 payload 重复 analyzeRequest
                List<String> originalHeaders = new ArrayList<>(analyzeRequest.getHeaders());
                for (String logPayload : log4jPayload) {
                    List<String> reqheaders2 = new ArrayList<>(originalHeaders);
                    List<String> newReqheaders = new ArrayList<>();
                    Iterator<String> iterator = reqheaders2.iterator();
                    while (iterator.hasNext()) {
                        String reqheader = iterator.next();
                        for (String header : headerList) {
                            // 按"名称:"前缀精确匹配（大小写不敏感），contains 会误删含同字样的无关头
                            if (Utils.headerNameMatches(reqheader, header)) {
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
                    HostThrottle.throttle(serviceKey(baseRequestResponse));
                    byte[] postMessage = Utils.helpers.buildHttpMessage(reqheaders2, body);
                    IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
                    // 补全判空：makeHttpRequest 失败返回 null 时，后续 getResponseLength/getResponse 会 NPE
                    if (originalRequestResponse == null || originalRequestResponse.getResponse() == null) {
                        Utils.stderr.println("Log4j scan skipped: target returned no response");
                        continue;
                    }
                    String originallength = getResponseLength(originalRequestResponse);
                    String statusCode = String.valueOf(Utils.helpers.analyzeResponse(originalRequestResponse.getResponse()).getStatusCode());
                    add(method, url, statusCode, originallength, originalRequestResponse);
                }
            }
        } finally {
            lock.unlock();
        }
    }

    /** 响应长度：优先取 Content-Length 头，缺失时用字节数（无响应返回 "0"）。 */
    private static String getResponseLength(IHttpRequestResponse response) {
        if (response.getResponse() != null) {
            IResponseInfo info = Utils.helpers.analyzeResponse(response.getResponse());
            String cl = HelperPlus.getHeaderValueOf(info.getHeaders(), "Content-Length");
            if (cl != null) return cl;
        }
        return response.getResponse() != null ? String.valueOf(response.getResponse().length) : "0";
    }

    /** 保存成功弹窗（EDT）。 */
    private void showSaveSuccess() {
        JOptionPane.showMessageDialog(null, I18nUtils.get("config.message.save_success"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
    }

    // 结果表格：选中行时加载对应请求/响应到编辑器
    class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            setAutoCreateRowSorter(true);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            if (rowIndex < 0 || rowIndex >= getRowCount()) {
                return;
            }
            int modelRow = getRowSorter() == null ? rowIndex : convertRowIndexToModel(rowIndex);
            Log4jUIEntry logEntry;
            // 以 store 的内部列表为监视器，与 add/clear 互斥
            synchronized (log4jlog.list()) {
                if (modelRow < 0 || modelRow >= log4jlog.list().size()) {
                    return;
                }
                logEntry = log4jlog.list().get(modelRow);
            }
            if (logEntry.requestResponse == null) {
                return;
            }
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
}
