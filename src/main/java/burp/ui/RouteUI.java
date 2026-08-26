package burp.ui;

import burp.*;
import burp.bean.RouteBean;
import burp.utils.CustomScanIssue;
import burp.utils.ExpressionUtils;
import burp.utils.I18nUtils;
import burp.utils.SmartRequestDetector;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.dao.RouteDao.*;

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

    private static final List<RouteIssueEntry> issuslog = new ArrayList<>();
    private static final List<RouteUIEntry> routelog = new ArrayList<>();
    static Set<String> uniqueUrl = new java.util.HashSet<>();
    private static final Lock lock = new ReentrantLock();
    private static final Set<String> discoveredIssues = java.util.Collections.synchronizedSet(new java.util.HashSet<>());
    private static  List<RouteBean> routeList = new ArrayList<>();
    private static volatile RouteUI instance;

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        RouteUI ui = instance;
        if (ui != null) ui.currentlyDisplayedItem = item;
    }

    static List<RouteIssueEntry> getIssuslog() {
        return issuslog;
    }

    public static void resetAllCaches() {
        uniqueUrl.clear();
        discoveredIssues.clear();
        UrlCacheUtil.resetCache("route");
    }

    @Override
    protected void setupScanUI() {
        instance = this;
        Utils.callbacks.registerHttpListener(this);
        issusTable = new RouteIssueTable(new RouteIssueTableModel(issuslog), requestEditor, responseEditor);
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
            issuslog.clear();
            uniqueUrl.clear();
            UrlCacheUtil.resetCache("route");
            refreshTableModel(issusTable);
            if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
            if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
        });

        passiveCheckBox.addActionListener(e -> passiveScanEnabled = passiveCheckBox.isSelected());

        addButton.addActionListener(e -> {
            String name = nameTextField.getText();
            String path = pathTextField.getText();
            String express = expressTextField.getText();
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

    // RouteUI processes both requests and responses, so override the base class filter
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && passiveScanEnabled && !messageIsRequest) {
            startPassiveScan(new IHttpRequestResponse[]{iHttpRequestResponse}, false);
        }
    }

    // 核心方法
    public static void Check(IHttpRequestResponse[] responses, boolean isSend) {
        lock.lock();
        try {
            IHttpRequestResponse baseRequest = responses[0];

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
            if (!isSend && !UrlCacheUtil.checkUrlUnique("route", method, baseUrl, analyzeRequest.getParameters())) {
                return;
            }

            byte[] rawRequest = baseRequest.getRequest();
            String rawRequestStr = Utils.helpers.bytesToString(rawRequest);
            List<String> headers = analyzeRequest.getHeaders();

            for (RouteBean routeBean : routeList) {
                if (routeBean.getEnable() != 1) {
                    continue;
                }

                List<String> testPaths = generateTestPaths(originalPath, routeBean.getPath());

                for (String testPath : testPaths) {
                    String fullTestUrl = baseUrl.getHost() + testPath;

                    if (!isSend && uniqueUrl.contains(fullTestUrl)) {
                        continue;
                    }
                    uniqueUrl.add(fullTestUrl);

                    byte[] newRequest = buildNewRequest(
                            baseRequest.getHttpService(),
                            headers,
                            method,
                            testPath,
                            analyzeRequest.getBodyOffset(),
                            rawRequest
                    );

                    String fullUrl = baseUrl.getProtocol() + "://" + baseUrl.getHost() +
                            (baseUrl.getPort() != -1 ? ":" + baseUrl.getPort() : "") + testPath;
                    IHttpRequestResponse response = sendRequestWithSmartDetect(
                            baseRequest.getHttpService(), fullUrl, newRequest);
                    if (response != null && response.getResponse() != null) {
                        processResponse(response, routeBean, baseRequest);
                    }
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("Error in Check: " + e.getMessage());
        } finally {
            lock.unlock();
        }
    }

    private static IHttpRequestResponse sendRequestWithSmartDetect(IHttpService httpService, String url, byte[] request) {
        SmartRequestDetector detector = new SmartRequestDetector(httpService);
        return detector.smartSendRequest(url, request);
    }

    private static List<String> generateTestPaths(String originalPath, String payload) {
        List<String> testPaths = new ArrayList<>();
        originalPath = cleanPath(originalPath);

        String[] pathSegments = originalPath.split("/");
        StringBuilder currentPath = new StringBuilder();

        testPaths.add(payload);

        for (String segment : pathSegments) {
            if (!segment.isEmpty()) {
                if (currentPath.length() == 0) {
                    currentPath.append("/").append(cleanSegment(segment));
                } else {
                    currentPath.append("/").append(cleanSegment(segment));
                }
                testPaths.add(currentPath + payload);
            }
        }

        return testPaths;
    }

    private static String cleanPath(String path) {
        return path.replaceAll(";[^/]*", "");
    }

    private static String cleanSegment(String segment) {
        int semicolonIndex = segment.indexOf(';');
        if (semicolonIndex != -1) {
            return segment.substring(0, semicolonIndex);
        }
        return segment;
    }

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

    private static void processResponse(
            IHttpRequestResponse response,
            RouteBean routeBean,
            IHttpRequestResponse originalRequest
    ) {
        try {
            ExpressionUtils expressionUtils = new ExpressionUtils(response);
            if (expressionUtils.process(routeBean.getExpress())) {
                addIssus(
                        routeBean.getName(),
                        expressionUtils.getUrl(),
                        String.valueOf(expressionUtils.getCode()),
                        response
                );

                IScanIssue issue = new CustomScanIssue(
                        originalRequest.getHttpService(),
                        new URL(expressionUtils.getUrl()),
                        new IHttpRequestResponse[]{response},
                        "Directory leakage",
                        "A sensitive directory leak vulnerability was discovered.",
                        "High",
                        "Certain"
                );
                Utils.callbacks.addScanIssue(issue);
            }
        } catch (Exception e) {
            Utils.stderr.println("Error processing response: " + e.getMessage());
        }
    }

    private static String generateIssueKey(String name, String url, String status) {
        return String.format("%s:%s:%s", name, url, status);
    }

    public static void addIssus(String name, String url, String Status, IHttpRequestResponse requestResponse) {
        String issueKey = generateIssueKey(name, url, Status);

        synchronized (issuslog) {
            if (discoveredIssues.add(issueKey)) {
                issuslog.add(new RouteIssueEntry(issuslog.size(), name, url, Status, requestResponse));
                SwingUtilities.invokeLater(() -> {
                    RouteUI ui = instance;
                    if (ui != null) refreshTableModel(ui.resultTable);
                });
            }
        }
    }
}
