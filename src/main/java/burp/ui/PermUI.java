package burp.ui;

import burp.*;
import burp.bean.PermBean;
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
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import static burp.dao.PermDao.*;

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

    private static final List<PermUIEntry> permlog = new ArrayList<>();
    private static boolean ispassiveScan;
    private static boolean isWhiteDomainList;
    private static final Lock lock = new ReentrantLock();
    private static volatile PermUI instance;

    public static void resetAllCaches() {
        UrlCacheUtil.resetCache("perm");
    }

    @Override
    protected void setupScanUI() {
        instance = this;
        // 注册被动扫描监听器
        Utils.callbacks.registerHttpListener(this);

        resultTable = new URLTable(new PermTableModel(permlog));

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

        Dimension scanOptionsSize = scanOptionsPanel.getPreferredSize();
        scanOptionsPanel.setMinimumSize(new Dimension(0, Math.max(52, scanOptionsSize.height)));
        JSplitPane mainRightSplit = applyCompactSplit(new JSplitPane(JSplitPane.VERTICAL_SPLIT), 0.24);
        mainRightSplit.setTopComponent(scanOptionsPanel);
        JPanel cfgAct = new JPanel(new BorderLayout(3, 3));
        cfgAct.add(configPanel, BorderLayout.CENTER);
        cfgAct.add(actionButtonsPanel, BorderLayout.SOUTH);
        mainRightSplit.setBottomComponent(cfgAct);
        rightSplitPane.add(mainRightSplit, BorderLayout.CENTER);

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

        passiveScanCheckBox.addActionListener(e -> {
            ispassiveScan = passiveScanCheckBox.isSelected();
            passiveScanEnabled = ispassiveScan;
        });
        whiteDomainListCheckBox.addActionListener(e -> isWhiteDomainList = whiteDomainListCheckBox.isSelected());

        saveWhiteDomainButton.addActionListener(e -> {
            deletePerm("domain");
            for (String s : whiteDomainListTextArea.getText().split("\n")) {
                if (s.trim().isEmpty()) continue;
                savePerm(new PermBean("domain", s.trim()));
            }
            showSaveSuccess();
        });
        saveAuthDataButton.addActionListener(e -> {
            deletePerm("permLowAuth");
            deletePerm("permNoAuth");
            for (String s : lowPermAuthTextArea.getText().split("\n")) {
                if (s.trim().isEmpty()) continue;
                savePerm(new PermBean("permLowAuth", s.trim()));
            }
            for (String s : noPermAuthTextArea.getText().split("\n")) {
                if (s.trim().isEmpty()) continue;
                savePerm(new PermBean("permNoAuth", s.trim()));
            }
            showSaveSuccess();
        });
        refreshButton.addActionListener(e -> refreshTableModel(resultTable));
        clearButton.addActionListener(e -> {
            permlog.clear();
            originarequest.setMessage(new byte[0], true);
            originaresponse.setMessage(new byte[0], false);
            lowpermrequest.setMessage(new byte[0], false);
            lowpermresponse.setMessage(new byte[0], false);
            nopermrequest.setMessage(new byte[0], false);
            nopermresponse.setMessage(new byte[0], false);
            UrlCacheUtil.resetCache("perm");
            refreshTableModel(resultTable);
        });
        exportButton.addActionListener(e -> exportTableToClipboard());
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
        if (permlog.isEmpty()) {
            JOptionPane.showMessageDialog(null, I18nUtils.get("perm.message.no_data"), I18nUtils.get("config.title.info"), JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        StringBuilder content = new StringBuilder();
        content.append("id\tmethod\turl\toriginallength\tlowlength\tnolength\tisSuccess\n");
        for (PermUIEntry entry : permlog) {
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

    // 核心检测方法
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

            if (!method.equals("GET") && !method.equals("POST")) return;
            if (!isSend) {
                if (!UrlCacheUtil.checkUrlUnique("perm", method, rdurlURL, paraLists)) return;
            } else {
                isWhiteDomainList = false;
            }
            if (Utils.isUrlBlackListSuffix(url)) return;
            if (isWhiteDomainList) {
                List<PermBean> domain = getPermListsByType("domain");
                if (domain.isEmpty()) {
                    JOptionPane.showMessageDialog(null, I18nUtils.get("perm.message.fill_whitelist"), I18nUtils.get("config.title.info"), JOptionPane.ERROR_MESSAGE);
                    return;
                }
                List<String> domainList = new ArrayList<>();
                for (PermBean bean : domain) domainList.add(bean.getValue());
                if (!Utils.isMatchDomainName(host, domainList)) return;
            }

            // 原始请求
            List<String> originalheaders = analyzeRequest.getHeaders();
            byte[] byte_Request = baseRequestResponse.getRequest();
            int bodyOffset = analyzeRequest.getBodyOffset();
            byte[] body = Arrays.copyOfRange(byte_Request, bodyOffset, byte_Request.length);
            byte[] postMessage = Utils.helpers.buildHttpMessage(originalheaders, body);
            IHttpRequestResponse originalRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), postMessage);
            String originallength = getResponseLength(originalRequestResponse);
            if (originalRequestResponse.getResponse() == null) return;

            // 低权限请求
            List<String> lowheaders = new ArrayList<>(originalheaders);
            for (PermBean bean : getPermListsByType("permLowAuth")) {
                String lowAuthText = bean.getValue();
                String head = lowAuthText.split(":")[0];
                boolean found = false;
                for (int i = 0; i < lowheaders.size(); i++) {
                    if (lowheaders.get(i).split(":")[0].equals(head)) {
                        lowheaders.set(i, lowAuthText);
                        found = true;
                        break;
                    }
                }
                if (!found) lowheaders.add(lowAuthText);
            }
            IHttpRequestResponse lowRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                    Utils.helpers.buildHttpMessage(lowheaders, body));
            String lowlength = getResponseLength(lowRequestResponse);

            // 无权限请求
            List<String> noheaders = new ArrayList<>(originalheaders);
            List<String> removeHeaders = new ArrayList<>();
            for (PermBean bean : getPermListsByType("permNoAuth")) {
                removeHeaders.add(bean.getValue().split(":")[0]);
            }
            noheaders.removeIf(h -> removeHeaders.contains(h.split(":")[0]));
            IHttpRequestResponse noRequestResponse = Utils.callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),
                    Utils.helpers.buildHttpMessage(noheaders, body));
            String nolength = getResponseLength(noRequestResponse);

            String isSuccess = originallength.equals(lowlength) && lowlength.equals(nolength) ? "未授权"
                    : originallength.equals(lowlength) ? "存在越权" : "不存在";

            add(method, url, originallength, lowlength, nolength, isSuccess,
                    originalRequestResponse, lowRequestResponse, noRequestResponse);
        } finally {
            lock.unlock();
        }
    }

    private static String getResponseLength(IHttpRequestResponse response) {
        if (response.getResponse() != null) {
            for (String header : Utils.helpers.analyzeResponse(response.getResponse()).getHeaders()) {
                if (header.toLowerCase().startsWith("content-length:")) {
                    return header.split(":")[1].trim();
                }
            }
        }
        return response.getResponse() != null ? String.valueOf(response.getResponse().length) : "0";
    }

    private static void add(String method, String url, String origLen, String lowLen, String noLen,
                            String isSuccess, IHttpRequestResponse orig, IHttpRequestResponse low, IHttpRequestResponse no) {
        synchronized (permlog) {
            int id = permlog.size();
            permlog.add(new PermUIEntry(id, method, url, origLen, lowLen, noLen, isSuccess, orig, low, no));
        }
        SwingUtilities.invokeLater(() -> {
            PermUI ui = instance;
            if (ui != null) refreshTableModel(ui.resultTable);
        });
    }

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
            synchronized (permlog) {
                if (modelRow < 0 || modelRow >= permlog.size()) {
                    return;
                }
                logEntry = permlog.get(modelRow);
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
