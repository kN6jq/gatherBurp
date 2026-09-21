package burp.ui;

import burp.*;
import burp.bean.PermBean;
import burp.utils.HostThrottle;
import burp.utils.I18nUtils;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.dao.PermDao.*;

/**
 * 越权（Perm）检测面板：对选中请求做三态对比——原始/低权限头/移除鉴权头，
 * 状态码对齐后按响应体长度差异记录疑似越权结果；支持白名单过滤、结果导出剪贴板与被动扫描。
 * 被动模式只放行 GET（POST 重放原 body 有写副作用），主动右键可测 GET/POST；
 * 认证/白名单配置以 volatile 快照供扫描线程读取，保存动作在单线程执行器中串行落库。
 * 检测在静态 lock 内串行执行，目标主机经 HostThrottle 限速；
 * 结果入静态有界 ScanResultsStore；编辑器为自行创建的三组消息编辑器（覆盖 createEditors）。
 */
public class PermUI extends AbstractScanUI {
    private JTabbedPane tabbedPanereqresp; // 请求tab
    private JPanel originPane; // 原始请求面板
    private JPanel lowpermPane; // 低权限请求面板
    private JPanel nopermPane; // 无权限请求面板
    private JCheckBox whiteDomainListCheckBox; // 白名单域名选择框
    private JTextArea whiteDomainListTextArea; // 白名单域名输入框
    private JButton saveWhiteDomainButton; // 保存白名单按钮
    private JButton saveAuthDataButton; // 保存认证数据按钮
    private JButton refreshButton; // 刷新按钮
    private JButton clearButton; // 清空数据按钮
    private JButton exportButton; // 导出按钮
    private JTextArea lowPermAuthTextArea; // 低权限认证请求信息输入框
    private JTextArea noPermAuthTextArea; // 无权限认证请求信息输入框
    private IMessageEditor originarequest;
    private IMessageEditor originaresponse;
    private IMessageEditor lowpermrequest;
    private IMessageEditor lowpermresponse;
    private IMessageEditor nopermrequest;
    private IMessageEditor nopermresponse;

    // 主动检测串行锁
    private static final Lock lock = new ReentrantLock();
    // 当前面板实例：静态 Check 入口经此定位到实例
    private static volatile PermUI instance;
    /** 结果列表容量上限，超限淘汰最旧条目。 */
    private static final int MAX_LOG_ENTRIES = 2000;
    private static final ScanResultsStore<PermUIEntry> permlog = new ScanResultsStore<>(MAX_LOG_ENTRIES, () -> {
        PermUI ui = instance;
        if (ui != null) {
            ui.refreshTableModel(ui.resultTable);
        }
    });
    // 开关由 EDT 监听器写入、扫描线程读取，volatile 保证可见性
    private static volatile boolean ispassiveScan;
    private static volatile boolean isWhiteDomainList;
    /** 认证/白名单配置运行时快照：启动与保存后刷新，被动高频流量不再逐条查库。 */
    private static volatile List<String> domainConfig = Collections.emptyList();
    private static volatile List<PermBean> lowAuthConfig = Collections.emptyList();
    private static volatile List<PermBean> noAuthConfig = Collections.emptyList();
    /** 保存按钮专用单线程执行器：DB 删移出 EDT，串行化防止连点先删后插交错。 */
    private static final java.util.concurrent.ExecutorService saveExecutor =
            java.util.concurrent.Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "PermUI-save");
                thread.setDaemon(true);
                return thread;
            });

    public static void resetAllCaches() {
        UrlCacheUtil.resetCache("perm");
    }
    @Override
    protected void setupScanUI() {
        instance = this;
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);

        resultTable = new URLTable(new PermTableModel(permlog.list()));

        passiveScanCheckBox = new JCheckBox(I18nUtils.get("perm.checkbox.passive"));
        whiteDomainListCheckBox = new JCheckBox(I18nUtils.get("perm.checkbox.whitelist"));
        whiteDomainListTextArea = new JTextArea(5, 10);
        whiteDomainListTextArea.setLineWrap(false);
        whiteDomainListTextArea.setWrapStyleWord(false);
        saveWhiteDomainButton = new JButton(I18nUtils.get("perm.button.save_whitelist"));
        saveAuthDataButton = new JButton(I18nUtils.get("perm.button.save_auth"));
        exportButton = new JButton(I18nUtils.get("perm.button.export"));
        lowPermAuthTextArea = new JTextArea(5, 10);
        lowPermAuthTextArea.setLineWrap(false);
        lowPermAuthTextArea.setWrapStyleWord(false);
        noPermAuthTextArea = new JTextArea(5, 10);
        noPermAuthTextArea.setLineWrap(false);
        noPermAuthTextArea.setWrapStyleWord(false);
        refreshButton = new JButton(I18nUtils.get("perm.button.refresh"));
        clearButton = new JButton(I18nUtils.get("perm.button.clear"));
    }

    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        // 左边：表格 + 请求/响应编辑器
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setTopComponent(wrapResultsTable(resultTable));

        // 下方：三个面板（原始/低权限/无权限）
        tabbedPanereqresp = new JTabbedPane();

        originPane = new JPanel(new BorderLayout());
        JSplitPane originSplit = new JSplitPane();
        originSplit.setResizeWeight(0.5);
        originarequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        originaresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        if (originarequest != null && originaresponse != null) {
            originSplit.setLeftComponent(originarequest.getComponent());
            originSplit.setRightComponent(originaresponse.getComponent());
        } else {
            originSplit.setLeftComponent(new JScrollPane(new JTextArea()));
            originSplit.setRightComponent(new JScrollPane(new JTextArea()));
        }
        originPane.add(originSplit, BorderLayout.CENTER);
        tabbedPanereqresp.addTab(I18nUtils.get("perm.tab.original"), originPane);

        lowpermPane = new JPanel(new BorderLayout());
        JSplitPane lowSplit = new JSplitPane();
        lowSplit.setResizeWeight(0.5);
        lowpermrequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        lowpermresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        if (lowpermrequest != null && lowpermresponse != null) {
            lowSplit.setLeftComponent(lowpermrequest.getComponent());
            lowSplit.setRightComponent(lowpermresponse.getComponent());
        } else {
            lowSplit.setLeftComponent(new JScrollPane(new JTextArea()));
            lowSplit.setRightComponent(new JScrollPane(new JTextArea()));
        }
        lowpermPane.add(lowSplit, BorderLayout.CENTER);
        tabbedPanereqresp.addTab(I18nUtils.get("perm.tab.low"), lowpermPane);

        nopermPane = new JPanel(new BorderLayout());
        JSplitPane noSplit = new JSplitPane();
        noSplit.setResizeWeight(0.5);
        nopermrequest = Utils.callbacks.createMessageEditor(PermUI.this, true);
        nopermresponse = Utils.callbacks.createMessageEditor(PermUI.this, false);
        if (nopermrequest != null && nopermresponse != null) {
            noSplit.setLeftComponent(nopermrequest.getComponent());
            noSplit.setRightComponent(nopermresponse.getComponent());
        } else {
            noSplit.setLeftComponent(new JScrollPane(new JTextArea()));
            noSplit.setRightComponent(new JScrollPane(new JTextArea()));
        }
        nopermPane.add(noSplit, BorderLayout.CENTER);
        tabbedPanereqresp.addTab(I18nUtils.get("perm.tab.no"), nopermPane);

        leftSplitPane.setBottomComponent(tabbedPanereqresp);
        applyWeights(leftSplitPane, WEIGHT_TABLE_EDITOR);

        // 右边配置面板
        JPanel rightSplitPane = new JPanel(new BorderLayout());
        rightSplitPane.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));

        JPanel scanOptionsPanel = createCompactOptionsPanel(
                I18nUtils.get("perm.border.scan_options"),
                passiveScanCheckBox, whiteDomainListCheckBox);

        JPanel configPanel = new JPanel(new BorderLayout(3, 3));
        configPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("perm.border.configuration")));

        JPanel whitelistPanel = new JPanel(new BorderLayout(5, 5));
        whitelistPanel.add(new JLabel(I18nUtils.get("perm.label.whitelist")), BorderLayout.NORTH);
        whitelistPanel.add(new JScrollPane(whiteDomainListTextArea), BorderLayout.CENTER);
        JPanel wlBtn = createCompactButtonPanel(saveWhiteDomainButton);
        whitelistPanel.add(wlBtn, BorderLayout.SOUTH);

        JPanel authDataPanel = new JPanel(new BorderLayout(3, 3));
        JPanel authBtnPanel = createCompactButtonPanel(saveAuthDataButton, exportButton);
        authDataPanel.add(authBtnPanel, BorderLayout.NORTH);

        JLabel lowPermAuthLabel = new JLabel(I18nUtils.get("perm.label.low_auth"));
        JLabel noPermAuthLabel = new JLabel(I18nUtils.get("perm.label.no_auth"));
        JSplitPane authSplit = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.5);
        JPanel lp = new JPanel(new BorderLayout(5, 5));
        lp.add(lowPermAuthLabel, BorderLayout.NORTH);
        lp.add(new JScrollPane(lowPermAuthTextArea), BorderLayout.CENTER);
        JPanel np = new JPanel(new BorderLayout(5, 5));
        np.add(noPermAuthLabel, BorderLayout.NORTH);
        np.add(new JScrollPane(noPermAuthTextArea), BorderLayout.CENTER);
        authSplit.setTopComponent(lp);
        authSplit.setBottomComponent(np);
        authDataPanel.add(authSplit, BorderLayout.CENTER);

        JSplitPane configSplit = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.3);
        configSplit.setTopComponent(whitelistPanel);
        configSplit.setBottomComponent(authDataPanel);
        configPanel.add(configSplit, BorderLayout.CENTER);

        JPanel actionButtonsPanel = createCompactButtonPanel(refreshButton, clearButton);
        actionButtonsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("perm.border.actions")));

        // 扫描选项固定在顶部（只占自身 preferred 高度），剩余空间全部给配置区。
        JPanel cfgAct = new JPanel(new BorderLayout(3, 3));
        cfgAct.add(configPanel, BorderLayout.CENTER);
        cfgAct.add(actionButtonsPanel, BorderLayout.SOUTH);
        rightSplitPane.add(stackOptionsAbove(scanOptionsPanel, cfgAct), BorderLayout.CENTER);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setLeftComponent(leftSplitPane);
        mainSplit.setRightComponent(rightSplitPane);
        applyWeights(mainSplit, WEIGHT_MAIN);

        panel.add(mainSplit, BorderLayout.CENTER);
    }

    @Override
    protected void loadSavedData() {
        // 加载白名单域名
        List<PermBean> whiteDomain = getPermListsByType("domain");
        for (PermBean bean : whiteDomain) {
            whiteDomainListTextArea.setText(whiteDomainListTextArea.getText() + bean.getValue() + "\n");
        }
        // 加载认证数据
        List<PermBean> lowAuth = getPermListsByType("permLowAuth");
        for (PermBean bean : lowAuth) {
            lowPermAuthTextArea.setText(lowPermAuthTextArea.getText() + bean.getValue() + "\n");
        }
        List<PermBean> noAuth = getPermListsByType("permNoAuth");
        for (PermBean bean : noAuth) {
            noPermAuthTextArea.setText(noPermAuthTextArea.getText() + bean.getValue() + "\n");
        }
        // 初始化扫描线程使用的配置快照
        refreshConfigSnapshot("domain");
        refreshConfigSnapshot("permLowAuth");
        refreshConfigSnapshot("permNoAuth");

        passiveScanCheckBox.addActionListener(e -> {
            ispassiveScan = passiveScanCheckBox.isSelected();
            passiveScanEnabled = ispassiveScan;
        });
        whiteDomainListCheckBox.addActionListener(e -> isWhiteDomainList = whiteDomainListCheckBox.isSelected());

        saveWhiteDomainButton.addActionListener(e -> {
            String text = whiteDomainListTextArea.getText();
            saveExecutor.execute(() -> {
                savePermType(text, "domain");
                SwingUtilities.invokeLater(() -> {
                    whiteDomainListTextArea.repaint();
                    showSaveSuccess();
                });
            });
        });
        saveAuthDataButton.addActionListener(e -> {
            String lowText = lowPermAuthTextArea.getText();
            String noText = noPermAuthTextArea.getText();
            saveExecutor.execute(() -> {
                savePermType(lowText, "permLowAuth");
                savePermType(noText, "permNoAuth");
                SwingUtilities.invokeLater(() -> {
                    lowPermAuthTextArea.repaint();
                    noPermAuthTextArea.repaint();
                    showSaveSuccess();
                });
            });
        });
        refreshButton.addActionListener(e -> refreshTableModel(resultTable));
        clearButton.addActionListener(e -> {
            // store.clear 内部加锁，与扫描线程的 add 互斥
            permlog.clear();
            originarequest.setMessage(new byte[0], true);
            originaresponse.setMessage(new byte[0], false);
            lowpermrequest.setMessage(new byte[0], true);
            lowpermresponse.setMessage(new byte[0], false);
            nopermrequest.setMessage(new byte[0], true);
            nopermresponse.setMessage(new byte[0], false);
            UrlCacheUtil.resetCache("perm");
            refreshTableModel(resultTable);
        });
        exportButton.addActionListener(e -> exportTableToClipboard());
    }

    /** 文本框内容先删后插写入指定 type（保存线程内调用），完成后刷新运行时快照。 */
    private static void savePermType(String text, String type) {
        deletePerm(type);
        for (String line : text.split("\n")) {
            if (line.trim().isEmpty()) continue;
            savePerm(new PermBean(type, line.trim()));
        }
        refreshConfigSnapshot(type);
    }

    /** 从数据库重建对应类型的运行时快照（保存线程完成后调用）。 */
    private static void refreshConfigSnapshot(String type) {
        if ("domain".equals(type)) {
            List<String> domains = new ArrayList<>();
            for (PermBean bean : getPermListsByType("domain")) {
                if (bean != null && bean.getValue() != null && !bean.getValue().trim().isEmpty()) {
                    domains.add(bean.getValue().trim());
                }
            }
            domainConfig = Collections.unmodifiableList(domains);
        } else if ("permLowAuth".equals(type)) {
            lowAuthConfig = Collections.unmodifiableList(new ArrayList<>(getPermListsByType("permLowAuth")));
        } else if ("permNoAuth".equals(type)) {
            noAuthConfig = Collections.unmodifiableList(new ArrayList<>(getPermListsByType("permNoAuth")));
        }
    }

    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
        Check(requestResponses, isManual);
    }

    @Override
    protected String getScanName() {
        return "Perm";
    }

    @Override
    public String getTabName() {
        return "PermAccess";
    }

    // 导出表格数据到剪切板
    private void exportTableToClipboard() {
        // EDT 上先做加锁快照再遍历，避免与扫描线程的并发修改产生 CME
        List<PermUIEntry> snapshot;
        synchronized (permlog.list()) {
            snapshot = new ArrayList<>(permlog.list());
        }
        if (snapshot.isEmpty()) {
            JOptionPane.showMessageDialog(null, I18nUtils.get("perm.message.no_data"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        StringBuilder content = new StringBuilder();
        content.append("id\tmethod\turl\toriginallength\tlowlength\tnolength\tisSuccess\n");
        for (PermUIEntry entry : snapshot) {
            content.append(entry.id).append("\t")
                   .append(entry.method).append("\t")
                   .append(entry.url).append("\t")
                   .append(entry.originalength).append("\t")
                   .append(entry.lowlength).append("\t")
                   .append(entry.nolength).append("\t")
                   .append(entry.isSuccess).append("\n");
        }
        StringSelection stringSelection = new StringSelection(content.toString());
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        JOptionPane.showMessageDialog(null, I18nUtils.get("perm.message.export_success"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
    }

    /** 越权三态对比检测核心（ScanTaskExecutor 池线程，经右键菜单/扫描按钮调用）。
     *  被动模式只放行 GET（POST 重放原 body 会重复触发写接口）；主动右键确认后可测 GET/POST。 */
    public static void Check(IHttpRequestResponse[] responses, boolean isSend) {
        lock.lock();
        try {
            IHttpRequestResponse baseRequestResponse = responses[0];
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String method = analyzeRequest.getMethod();
            String host = baseRequestResponse.getHttpService().getHost();
            URL rdurlURL = analyzeRequest.getUrl();
            String url = rdurlURL.toString();
            List<IParameter> paraLists = analyzeRequest.getParameters();

            if (!"GET".equals(method) && !(isSend && "POST".equals(method))) return;
            if (Utils.isUrlBlackListSuffix(url)) return;
            // 白名单仅在被动模式下生效；用局部变量表达"本次是否校验白名单"，
            // 不再修改静态开关（旧行为会让主动扫描静默关闭被动白名单）
            if (!isSend && isWhiteDomainList) {
                List<String> domains = domainConfig;
                if (domains.isEmpty()) {
                    // 扫描线程禁止弹模态对话框（会阻塞 ScanTaskExecutor 池线程且非 EDT），
                    // 降级为扩展输出提示
                    Utils.stderr.println(I18nUtils.get("perm.message.fill_whitelist"));
                    return;
                }
                if (!Utils.isMatchDomainName(host, domains)) return;
            }
            // 认证数据未配置时三态请求退化为同一请求，长度恒相等会必然误报"未鉴权"，直接拒测
            List<PermBean> lowAuth = lowAuthConfig;
            List<PermBean> noAuth = noAuthConfig;
            if (lowAuth.isEmpty() || noAuth.isEmpty()) {
                Utils.stderr.println("Perm scan skipped: low/no-permission auth data not configured");
                return;
            }
            // 去重放在全部前置校验之后：被白名单/配置挡下的 URL 不再被"烧掉"
            if (!isSend && !UrlCacheUtil.checkUrlUnique("perm", method, rdurlURL, paraLists)) return;

            // 原始请求
            List<String> originalheaders = analyzeRequest.getHeaders();
            byte[] byte_Request = baseRequestResponse.getRequest();
            int bodyOffset = analyzeRequest.getBodyOffset();
            byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, byte_Request.length);
            byte[] postMessage = Utils.helpers.buildHttpMessage(originalheaders, body);
            HostThrottle.throttle(serviceKey(baseRequestResponse));
            IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
            if (originalRequestResponse == null || originalRequestResponse.getResponse() == null) return;
            String originallength = String.valueOf(getBodyByteLength(originalRequestResponse));
            int originalStatus = getStatusCode(originalRequestResponse);

            // 低权限请求：按头名大小写不敏感替换（与无权限删除同一语义，复用 Utils.headerNameMatches）
            List<String> lowheaders = new ArrayList<>(originalheaders);
            for (PermBean bean : lowAuth) {
                String lowAuthText = bean.getValue();
                if (lowAuthText == null) continue;
                String head = lowAuthText.split(":")[0].trim();
                boolean found = false;
                for (int i = 0; i < lowheaders.size(); i++) {
                    if (Utils.headerNameMatches(lowheaders.get(i), head)) {
                        lowheaders.set(i, lowAuthText);
                        found = true;
                        break;
                    }
                }
                if (!found) lowheaders.add(lowAuthText);
            }
            HostThrottle.throttle(serviceKey(baseRequestResponse));
            IHttpRequestResponse lowRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                    Utils.helpers.buildHttpMessage(lowheaders, body));
            // 补全判空：低权限探测请求失败（返回 null）时直接结束本次判定，
            // 避免把失败响应当作长度 0 参与越权判定
            if (lowRequestResponse == null || lowRequestResponse.getResponse() == null) {
                Utils.stderr.println("Perm scan skipped: low-priv request returned no response");
                return;
            }
            String lowlength = String.valueOf(getBodyByteLength(lowRequestResponse));
            int lowStatus = getStatusCode(lowRequestResponse);

            // 无权限请求：删除配置的鉴权头（头名大小写不敏感，旧精确匹配会漏删导致恒判"安全"）
            List<String> removeHeaderNames = new ArrayList<>();
            for (PermBean bean : noAuth) {
                String name = bean.getValue().split(":")[0].trim();
                if (!name.isEmpty()) removeHeaderNames.add(name);
            }
            List<String> noheaders = new ArrayList<>(originalheaders);
            noheaders.removeIf(h -> {
                for (String name : removeHeaderNames) {
                    if (Utils.headerNameMatches(h, name)) return true;
                }
                return false;
            });
            HostThrottle.throttle(serviceKey(baseRequestResponse));
            IHttpRequestResponse noRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                    Utils.helpers.buildHttpMessage(noheaders, body));
            // 补全判空：无权限探测请求失败（返回 null）时直接结束本次判定
            if (noRequestResponse == null || noRequestResponse.getResponse() == null) {
                Utils.stderr.println("Perm scan skipped: no-priv request returned no response");
                return;
            }
            String nolength = String.valueOf(getBodyByteLength(noRequestResponse));
            int noStatus = getStatusCode(noRequestResponse);

            // 判定要求状态码对齐：等长的 302/错误页不能凭长度相同误报越权
            String isSuccess;
            if (originalStatus == lowStatus && originalStatus == noStatus
                    && originallength.equals(lowlength) && lowlength.equals(nolength)) {
                isSuccess = I18nUtils.get("perm.verdict.unauthorized");
            } else if (originalStatus == lowStatus && originallength.equals(lowlength)) {
                isSuccess = I18nUtils.get("perm.verdict.broken");
            } else {
                isSuccess = I18nUtils.get("perm.verdict.safe");
            }

            add(method, url, originallength, lowlength, nolength, isSuccess,
                    originalRequestResponse, lowRequestResponse, noRequestResponse);
        } finally {
            lock.unlock();
        }
    }

    private static String serviceKey(IHttpRequestResponse requestResponse) {
        IHttpService service = requestResponse.getHttpService();
        return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }

    /** 三态对比统一长度口径：响应体实际字节数（按 bodyOffset 截取；
     *  Content-Length 可能是压缩后长度，回退整包长度又混入响应头，两者互比会失真）。 */
    private static int getBodyByteLength(IHttpRequestResponse response) {
        byte[] raw = response.getResponse();
        if (raw == null) return 0;
        return Math.max(0, raw.length - Utils.helpers.analyzeResponse(raw).getBodyOffset());
    }

    /** 响应状态码（无响应返回 0）。 */
    private static int getStatusCode(IHttpRequestResponse response) {
        byte[] raw = response.getResponse();
        return raw == null ? 0 : Utils.helpers.analyzeResponse(raw).getStatusCode();
    }

    /** 追加一条三态对比结果到有界 store（自动刷新表格）。 */
    private static void add(String method, String url, String origLen, String lowLen, String noLen,
                            String isSuccess, IHttpRequestResponse orig, IHttpRequestResponse low, IHttpRequestResponse no) {
        permlog.add(id -> new PermUIEntry(id, method, url, origLen, lowLen, noLen, isSuccess, orig, low, no));
    }

    /** 保存成功弹窗（EDT）。 */
    private void showSaveSuccess() {
        JOptionPane.showMessageDialog(null, I18nUtils.get("config.message.save_success"),
                I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
    }

    // perm 表格
    private class URLTable extends JTable {
        public URLTable(TableModel tableModel) {
            super(tableModel);
            TableColumnModel columnModel = getColumnModel();
            columnModel.getColumn(0).setMaxWidth(50);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row < 0 || row >= getRowCount()) {
                return;
            }
            int modelRow = getRowSorter() == null ? row : convertRowIndexToModel(row);
            PermUIEntry logEntry;
            // 以 store 的内部列表为监视器，与 add/clear 互斥
            synchronized (permlog.list()) {
                if (modelRow < 0 || modelRow >= permlog.list().size()) {
                    return;
                }
                logEntry = permlog.list().get(modelRow);
            }
            if (logEntry.requestResponse == null) {
                return;
            }
            originarequest.setMessage(logEntry.requestResponse.getRequest(), true);
            originaresponse.setMessage(logEntry.requestResponse.getResponse() == null ? new byte[0] : logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;
            if (logEntry.lowRequestResponse == null || logEntry.noRequestResponse == null) {
                lowpermrequest.setMessage(new byte[0], true);
                lowpermresponse.setMessage(new byte[0], false);
                nopermrequest.setMessage(new byte[0], true);
                nopermresponse.setMessage(new byte[0], false);
            } else {
                lowpermrequest.setMessage(logEntry.lowRequestResponse.getRequest(), true);
                lowpermresponse.setMessage(logEntry.lowRequestResponse.getResponse() == null ? new byte[0] : logEntry.lowRequestResponse.getResponse(), false);
                nopermrequest.setMessage(logEntry.noRequestResponse.getRequest(), true);
                nopermresponse.setMessage(logEntry.noRequestResponse.getResponse() == null ? new byte[0] : logEntry.noRequestResponse.getResponse(), false);
            }
            super.changeSelection(row, col, toggle, extend);
        }
    }
}
