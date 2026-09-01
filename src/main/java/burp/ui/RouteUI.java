package burp.ui;

import burp.*;
import burp.bean.RouteBean;
import burp.utils.CustomScanIssue;
import burp.utils.ExpressionUtils;
import burp.utils.HostThrottle;
import burp.utils.I18nUtils;
import burp.utils.LruCache;
import burp.utils.LruSet;
import burp.utils.RoutePathUtils;
import burp.utils.SmartRequestDetector;
import burp.utils.WafEvidence;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.dao.RouteDao.*;

/**
 * 目录探测（Route）面板：按 route 表规则（默认 Actuator/Druid/Swagger/Nacos 等 + 用户自定义）
 * 对请求路径做组合探测（RoutePathUtils），用 ExpressionUtils 表达式判定命中，
 * 记录 WAF 拦截信号（状态码计数）辅助降误报；支持规则管理与被动扫描。
 * 主动/被动检测在静态 lock 内串行执行，目标主机经 HostThrottle 限速；
 * 命中结果经 LruSet 去重后入静态有界 ScanResultsStore。
 */
public class RouteUI extends AbstractScanUI {
    private RouteIssueTable issusTable;
    private RouteTable ruleTable;
    private JScrollPane issustablescrollpane;
    private JScrollPane ruleTableScrollPane;
    private JButton refreshButton;
    private JButton clearButton;
    private JCheckBox passiveCheckBox;
    private JTextField nameTextField;
    private JTextField pathTextField;
    private JTextField expressTextField;
    private JButton addButton;
    private JButton deleteButton;
    private JButton enableButton;

    /** 单次触发（单个 URL）的探测请求预算：5 条路径 × 11 条默认规则 ≤ 60。 */
    private static final int MAX_REQUESTS_PER_CHECK = 60;
    // 当前面板实例：静态 Check 入口与 BurpExtender 被动回调经此定位到实例
    private static volatile RouteUI instance;
    /** 结果列表容量上限，超限淘汰最旧条目。 */
    private static final int MAX_LOG_ENTRIES = 2000;
    /** issue 去重键容量上限（与 SqlUI 的 issue 键口径一致），防长时间会话内存增长。 */
    private static final int MAX_TRACKED_ISSUE_KEYS = 5000;

    private static final ScanResultsStore<RouteIssueEntry> issuesLog = new ScanResultsStore<>(MAX_LOG_ENTRIES, () -> {
        RouteUI ui = instance;
        if (ui != null) {
            ui.refreshTableModel(ui.resultTable);
        }
    });
    // 规则表格数据源（RouteTableModel 以其为监视器）
    private static final List<RouteUIEntry> routelog = new ArrayList<>();
    /** 探测路径去重：键含协议+主机+端口+路径，容量上限防长时间被动扫描内存增长。 */
    static LruSet<String> uniqueUrl = new LruSet<>(5000);
    // 主动/被动检测串行锁
    private static final Lock lock = new ReentrantLock();
    /** issue 去重键同样有界（旧实现为无界 synchronizedSet，长会话持续增长）。 */
    private static final LruSet<String> discoveredIssues = new LruSet<>(MAX_TRACKED_ISSUE_KEYS);
    /** EDT（规则启用/禁用按钮）重新赋值，扫描线程读取，需 volatile 保证可见性。 */
    private static volatile List<RouteBean> routeList = new ArrayList<>();
    /** WAF 拦截信号计数（host → 各 BLOCKED 状态码计数，LruCache 有界）。 */
    private static final LruCache<String, AtomicInteger> wafBlockCounters = new LruCache<>(2048);

    public static void resetAllCaches() {
        uniqueUrl.clear();
        discoveredIssues.clear();
        wafBlockCounters.clear();
        HostThrottle.reset();
        UrlCacheUtil.resetCache("route");
    }

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        RouteUI ui = instance;
        if (ui != null) ui.currentlyDisplayedItem = item;
    }

    static List<RouteIssueEntry> getIssuesLog() {
        return issuesLog.list();
    }

    @Override
    protected void setupScanUI() {
        instance = this;
        Utils.callbacks.registerHttpListener(this);
        issusTable = new RouteIssueTable(new RouteIssueTableModel(issuesLog.list()), requestEditor, responseEditor);
        resultTable = issusTable;
        issustablescrollpane = new JScrollPane(issusTable);
        issustablescrollpane.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("common.border.results")));
        ruleTable = new RouteTable(new RouteTableModel(routelog));
        ruleTableScrollPane = new JScrollPane(ruleTable);
    }

    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        refreshButton = new JButton(I18nUtils.get("route.button.refresh"));
        topPanel.add(refreshButton);
        clearButton = new JButton(I18nUtils.get("route.button.clear"));
        topPanel.add(clearButton);
        passiveCheckBox = new JCheckBox(I18nUtils.get("route.checkbox.passive"));
        topPanel.add(passiveCheckBox);
        topPanel.add(new JLabel(I18nUtils.get("route.label.tips")));
        topPanel.add(new JLabel(I18nUtils.get("route.label.name")));
        nameTextField = new JTextField(10);
        topPanel.add(nameTextField);
        topPanel.add(new JLabel(I18nUtils.get("route.label.path")));
        pathTextField = new JTextField(10);
        topPanel.add(pathTextField);
        topPanel.add(new JLabel(I18nUtils.get("route.label.express")));
        expressTextField = new JTextField(10);
        topPanel.add(expressTextField);
        addButton = new JButton(I18nUtils.get("route.button.add"));
        topPanel.add(addButton);
        deleteButton = new JButton(I18nUtils.get("route.button.delete"));
        topPanel.add(deleteButton);
        enableButton = new JButton(I18nUtils.get("route.button.enable"));
        topPanel.add(enableButton);

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        JSplitPane topSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        applyWeights(topSplitPane, WEIGHT_EDITORS);
        topSplitPane.setLeftComponent(issustablescrollpane);
        topSplitPane.setRightComponent(ruleTableScrollPane);

        JSplitPane bottomSplitPane = buildEditorSplit();

        splitPane.setTopComponent(topSplitPane);
        splitPane.setBottomComponent(bottomSplitPane);
        applyWeights(splitPane, WEIGHT_TABLE_EDITOR);

        panel.add(topPanel, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);
    }

    @Override
    protected void loadSavedData() {
        setupData();
    }

    private void setupData() {
        loadRouteRules();

        refreshButton.addActionListener(e -> {
            refreshTableModel(issusTable);
            loadRouteRules();
        });

        clearButton.addActionListener(e -> {
            // store.clear 内部加锁，与扫描线程的 add 互斥
            issuesLog.clear();
            uniqueUrl.clear();
            UrlCacheUtil.resetCache("route");
            refreshTableModel(issusTable);
            if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
            if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
        });

        passiveCheckBox.addActionListener(e -> passiveScanEnabled = passiveCheckBox.isSelected());

        addButton.addActionListener(e -> {
            String name = nameTextField.getText() == null ? "" : nameTextField.getText().trim();
            String path = pathTextField.getText() == null ? "" : pathTextField.getText().trim();
            String express = expressTextField.getText() == null ? "" : expressTextField.getText().trim();
            // 保存前校验：空值 / 路径格式 / 表达式语法，避免入库后静默失效
            if (name.isEmpty() || path.isEmpty() || express.isEmpty()) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("route.message.required"),
                        I18nUtils.get("config.title.info"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (!path.startsWith("/")) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("route.message.invalid_path"),
                        I18nUtils.get("config.title.info"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (!ExpressionUtils.isValidExpression(express)) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("route.message.invalid_expression"),
                        I18nUtils.get("config.title.info"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            if (routePathExists(path)) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("route.message.duplicate"),
                        I18nUtils.get("config.title.info"), JOptionPane.WARNING_MESSAGE);
                return;
            }
            RouteBean routeBean = new RouteBean();
            routeBean.setEnable(1);
            routeBean.setName(name);
            routeBean.setPath(path);
            routeBean.setExpress(express);
            addRoute(routeBean);
            loadRouteRules();
        });

        deleteButton.addActionListener(e -> {
            int selectedRow = ruleTable.getSelectedRow();
            if (selectedRow == -1) {
                return;
            }
            int modelRow = ruleTable.getRowSorter() == null ? selectedRow : ruleTable.convertRowIndexToModel(selectedRow);
            RouteUIEntry routeEntry;
            synchronized (routelog) {
                if (modelRow < 0 || modelRow >= routelog.size()) {
                    return;
                }
                routeEntry = routelog.get(modelRow);
            }
            RouteBean routeBean = new RouteBean();
            routeBean.setName(routeEntry.name);
            routeBean.setPath(routeEntry.path);
            routeBean.setExpress(routeEntry.express);
            deleteRoute(routeBean);
            loadRouteRules();
        });

        enableButton.addActionListener(e -> {
            int selectedRow = ruleTable.getSelectedRow();
            if (selectedRow == -1) {
                return;
            }
            int modelRow = ruleTable.getRowSorter() == null ? selectedRow : ruleTable.convertRowIndexToModel(selectedRow);
            RouteUIEntry routeEntry;
            synchronized (routelog) {
                if (modelRow < 0 || modelRow >= routelog.size()) {
                    return;
                }
                routeEntry = routelog.get(modelRow);
            }
            RouteBean routeBean = new RouteBean();
            routeBean.setEnable(routeEntry.enable == 1 ? 0 : 1);
            routeBean.setName(routeEntry.name);
            routeBean.setPath(routeEntry.path);
            routeBean.setExpress(routeEntry.express);
            updateRouteEnable(routeBean);
            routeList = getRouteLists();
            loadRouteRules();
        });
    }

    private void loadRouteRules() {
        ensureDefaultRules();   // 按需补齐精选 Java 路由规则（按 path 去重，幂等）
        routelog.clear();
        List<RouteBean> routeLists = getRouteLists();
        for (int i = 0; i < routeLists.size(); i++) {
            RouteBean routeBean = routeLists.get(i);
            routelog.add(new RouteUIEntry(i, routeBean.getEnable(), routeBean.getName(), routeBean.getPath(), routeBean.getExpress()));
        }
        routeList = getRouteLists();
        refreshTableModel(ruleTable);
    }

    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
        Check(requestResponses, isManual);
    }

    @Override
    public String getScanName() {
        return "Route";
    }

    @Override
    public String getTabName() {
        return "RouteScan";
    }

    // 被动过滤完全交给基类 processHttpMessage：判空 + 多工具来源白名单（排除 EXTENDER 防递归），
    // 旧覆写仅收 TOOL_PROXY 且缺少判空防御，已删除。
    // 路径组合逻辑在 burp.utils.RoutePathUtils（纯函数，带深度上限），便于单元测试。

    /** 目录探测核心（ScanTaskExecutor 池线程，经右键菜单/扫描按钮/被动扫描调用）：
     *  路径组合 × 启用规则逐条请求，ExpressionUtils 判定命中并记录 WAF 信号。 */
    public static void Check(IHttpRequestResponse[] responses, boolean isSend) {
        lock.lock();
        try {
            IHttpRequestResponse baseRequest = responses[0];
            if (baseRequest == null || baseRequest.getRequest() == null
                    || baseRequest.getHttpService() == null) {
                return;
            }

            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequest);
            URL baseUrl = analyzeRequest.getUrl();
            String method = analyzeRequest.getMethod();
            String originalPath = baseUrl.getPath();

            if (!method.equals("GET") && !method.equals("POST")) {
                return;
            }
            if (Utils.isUrlBlackListSuffix(baseUrl.toString())) {
                return;
            }
            // 去重只按 method+scheme+host+port+path：路由探测与业务参数无关，
            // 带参数去重会让同一路径因 ?page=1/?page=2 反复触发全量探测。
            if (!isSend && !UrlCacheUtil.checkUrlUnique("route", method, baseUrl, Collections.<burp.IParameter>emptyList())) {
                return;
            }

            byte[] rawRequest = baseRequest.getRequest();
            List<String> headers = analyzeRequest.getHeaders();
            IHttpService service = baseRequest.getHttpService();
            int sentRequests = 0;
            boolean budgetExhausted = false;

            for (RouteBean routeBean : routeList) {
                if (routeBean.getEnable() != 1) {
                    continue;
                }

                List<String> testPaths = RoutePathUtils.generateTestPaths(originalPath, routeBean.getPath());

                for (String testPath : testPaths) {
                    String dedupKey = service.getProtocol() + "://" + service.getHost()
                            + ":" + service.getPort() + testPath;

                    if (!isSend && uniqueUrl.contains(dedupKey)) {
                        continue;
                    }
                    // 预算检查放在消费去重键之前：预算耗尽时释放该键，下次触发仍可探测
                    if (sentRequests >= MAX_REQUESTS_PER_CHECK) {
                        budgetExhausted = true;
                        break;
                    }
                    uniqueUrl.add(dedupKey);

                    byte[] newRequest = buildNewRequest(
                            service,
                            headers,
                            method,
                            testPath,
                            analyzeRequest.getBodyOffset(),
                            rawRequest
                    );

                    String fullUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() +
                            (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + testPath;
                    IHttpRequestResponse response = sendRequestWithSmartDetect(service, fullUrl, newRequest);
                    sentRequests++;
                    trackWafSignals(service, response);
                    if (response != null && response.getResponse() != null) {
                        processResponse(response, routeBean, baseRequest);
                    }
                }
                if (budgetExhausted) {
                    Utils.stderr.println("[Route] " + I18nUtils.get("route.message.budget")
                            + " (url=" + baseUrl + ", sent=" + sentRequests + ")");
                    break;
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("Error in Check: " + e.getMessage());
        } finally {
            lock.unlock();
        }
    }

    /** 限速后经 SmartRequestDetector 发送探测请求（池线程内调用）。 */
    private static IHttpRequestResponse sendRequestWithSmartDetect(IHttpService httpService, String url, byte[] request) {
        HostThrottle.throttle(serviceKey(httpService));
        SmartRequestDetector detector = new SmartRequestDetector(httpService);
        return detector.smartSendRequest(url, request);
    }

    /** 连续多次 403/406/429 视为受控目标：标记后共享节流器自动放大间隔。 */
    private static void trackWafSignals(IHttpService service, IHttpRequestResponse response) {
        if (response == null || response.getResponse() == null) {
            return;
        }
        int status = Utils.helpers.analyzeResponse(response.getResponse()).getStatusCode();
        boolean wafStatus = false;
        for (int code : WafEvidence.BLOCKED_STATUS_CODES) {
            if (status == code) {
                wafStatus = true;
                break;
            }
        }
        if (!wafStatus) {
            return;
        }
        String hostKey = serviceKey(service);
        if (wafBlockCounters.computeIfAbsent(hostKey, k -> new AtomicInteger()).incrementAndGet() >= 3) {
            HostThrottle.markSlow(hostKey);
        }
    }

    /** 目标主机限流键（HostThrottle 按 host:port 独立限速）。 */
    private static String serviceKey(IHttpService service) {
        return service.getProtocol() + "://" + service.getHost() + ":" + service.getPort();
    }

    /** 基于原始请求替换路径构造新请求（POST 保留 body，GET 置空 body）。 */
    private static byte[] buildNewRequest(
            IHttpService httpService,
            List<String> headers,
            String method,
            String newPath,
            int bodyOffset,
            byte[] originalRequest
    ) {
        List<String> newHeaders = new ArrayList<>();
        for (int i = 0; i < headers.size(); i++) {
            if (i == 0) {
                String firstLine = headers.get(0);
                String[] parts = firstLine.split(" ");
                parts[1] = newPath;
                newHeaders.add(String.join(" ", parts));
            } else {
                newHeaders.add(headers.get(i));
            }
        }

        if (method.equals("POST")) {
            byte[] body = Arrays.copyOfRange(originalRequest, bodyOffset, originalRequest.length);
            return Utils.helpers.buildHttpMessage(newHeaders, body);
        } else {
            return Utils.helpers.buildHttpMessage(newHeaders, null);
        }
    }

    /** 与已加载规则按 path 查重（ensureDefaultRules 同口径），避免同路径重复探测。 */
    private static boolean routePathExists(String path) {
        for (RouteBean bean : routeList) {
            if (bean != null && path.equals(bean.getPath())) {
                return true;
            }
        }
        return false;
    }

    /** 用规则表达式判定响应是否命中：命中则入结果表并上报 Burp Issue（按特征定级）。 */
    private static void processResponse(
            IHttpRequestResponse response,
            RouteBean routeBean,
            IHttpRequestResponse originalRequest
    ) {
        try {
            ExpressionUtils expressionUtils = new ExpressionUtils(response);
            if (expressionUtils.process(routeBean.getExpress())) {
                addIssue(
                        routeBean.getName(),
                        expressionUtils.getUrl(),
                        String.valueOf(expressionUtils.getCode()),
                        response
                );

                String[] level = issueLevel(routeBean.getExpress());
                IScanIssue issue = new CustomScanIssue(
                        originalRequest.getHttpService(),
                        new URL(expressionUtils.getUrl()),
                        new IHttpRequestResponse[]{response},
                        "Directory leakage",
                        "A sensitive directory leak vulnerability was discovered.",
                        level[0],
                        level[1]
                );
                Utils.callbacks.addScanIssue(issue);
            }
        } catch (Exception e) {
            Utils.stderr.println("Error processing response: " + e.getMessage());
        }
    }

    /**
     * 依据规则特征定级，抑制宽松规则的误报等级：
     * 组合条件且带 body/title/headers 上下文特征 → High/Certain；
     * 仅 code 单条件（如网关统一 405）→ Medium/Firm；其余 → High/Firm。
     */
    private static String[] issueLevel(String express) {
        String e = express == null ? "" : express;
        boolean hasContextFeature = e.contains("body=") || e.contains("title=") || e.contains("headers=");
        boolean compound = e.contains("&&") || e.contains("||");
        if (hasContextFeature && compound) {
            return new String[]{"High", "Certain"};
        }
        if (!hasContextFeature) {
            return new String[]{"Medium", "Firm"};
        }
        return new String[]{"High", "Firm"};
    }

    /** 生成 issue 去重键（规则名:URL:状态码）。 */
    private static String generateIssueKey(String name, String url, String status) {
        return String.format("%s:%s:%s", name, url, status);
    }

    /** 追加命中 issue 到有界 store：去重键先判定，重复不占容量也不触发刷新。 */
    public static void addIssue(String name, String url, String status, IHttpRequestResponse requestResponse) {
        // 去重键先判定再入表：重复 issue 不占容量也不触发刷新
        if (!discoveredIssues.add(generateIssueKey(name, url, status))) {
            return;
        }
        issuesLog.add(id -> new RouteIssueEntry(id, name, url, status, requestResponse));
    }
}
