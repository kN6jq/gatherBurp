package burp.ui;

import burp.*;
import burp.utils.I18nUtils;
import burp.utils.RedirectLocationUtils;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class UrlRedirectUI extends AbstractScanUI {
    private JButton btnClear;
    private JCheckBox chkPassiveScan;

    private static final List<RedirectEntry> redirectLog = new ArrayList<>();
    private final Lock scanLock = new ReentrantLock();
    private static volatile UrlRedirectUI instance;

    /** 配置只属于当前 UI 实例，避免重复初始化时串用其他实例的配置。 */
    private DefaultTableModel payloadModel;
    private DefaultTableModel paramModel;

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        UrlRedirectUI ui = instance;
        if (ui != null) ui.currentlyDisplayedItem = item;
    }

    static List<RedirectEntry> getRedirectLog() {
        return redirectLog;
    }

    @Override
    protected void setupScanUI() {
        instance = this;
        Utils.callbacks.registerHttpListener(this);
        resultTable = new RedirectTable(new RedirectModel(), requestEditor, responseEditor);
    }

    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        JSplitPane horizontalSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

        JPanel leftPanel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        chkPassiveScan = new JCheckBox(I18nUtils.get("redirect.checkbox.passive"), false);
        btnClear = new JButton(I18nUtils.get("redirect.button.clear"));
        topPanel.add(chkPassiveScan);
        topPanel.add(btnClear);
        leftPanel.add(topPanel, BorderLayout.NORTH);

        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setTopComponent(wrapResultsTable(getResultTable()));
        leftSplitPane.setBottomComponent(buildEditorSplit());
        applyWeights(leftSplitPane, WEIGHT_TABLE_EDITOR);

        leftPanel.add(leftSplitPane, BorderLayout.CENTER);

        JPanel rightPanel = setupSettingsPanel();
        rightPanel.setMinimumSize(new Dimension(250, 400));
        rightPanel.setPreferredSize(new Dimension(250, 400));

        horizontalSplitPane.setLeftComponent(leftPanel);
        horizontalSplitPane.setRightComponent(rightPanel);
        applyWeights(horizontalSplitPane, WEIGHT_MAIN);

        panel.add(horizontalSplitPane, BorderLayout.CENTER);
    }

    @Override
    protected void loadSavedData() {
        btnClear.addActionListener(e -> {
            synchronized (redirectLog) {
                redirectLog.clear();
            }
            if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
            if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
            refreshTableModel(getResultTable());
        });

        chkPassiveScan.addActionListener(e -> passiveScanEnabled = chkPassiveScan.isSelected());
    }

    private JPanel setupSettingsPanel() {
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(I18nUtils.get("redirect.border.settings")),
                PADDING_BORDER));

        paramModel = new DefaultTableModel(new String[]{I18nUtils.get("redirect.label.parameter")}, 0);
        payloadModel = new DefaultTableModel(new String[]{I18nUtils.get("redirect.label.payloads")}, 0);

        String[] defaultParams = {
                "redirect","redirect_to","url","jump","target","to","link","goto","return_url","next","returnUrl","return","redirectUrl","callback","toUrl","ReturnUrl","fromUrl","redUrl","request","redirect_url","jump_to","linkto","domain","oauth_callback"
        };
        String[] defaultPayloads = {};

        settingsPanel.add(createInputPanel(I18nUtils.get("redirect.label.parameter"), paramModel, defaultParams));
        settingsPanel.add(createInputPanel(I18nUtils.get("redirect.label.payloads"), payloadModel, defaultPayloads));

        settingsPanel.setMinimumSize(new Dimension(250, 400));
        settingsPanel.setPreferredSize(new Dimension(250, 400));

        return settingsPanel;
    }

    private JPanel createInputPanel(String title, DefaultTableModel model, String... defaultValues) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));

        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));
        inputPanel.setMinimumSize(new Dimension(200, 30));
        inputPanel.setPreferredSize(new Dimension(200, 30));

        final JTextField inputField = new JTextField(20);
        inputField.setMinimumSize(new Dimension(120, 25));
        inputField.setPreferredSize(new Dimension(120, 25));
        inputField.addActionListener(e -> {
            String value = inputField.getText().trim();
            if (!value.isEmpty() && !isDuplicate(model, value)) {
                model.addRow(new Object[]{value});
                inputField.setText("");
            }
        });
        inputPanel.add(inputField);
        inputPanel.add(Box.createHorizontalStrut(5));

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        JButton addBtn = new JButton(I18nUtils.get("redirect.button.add"));
        JButton clearBtn = new JButton(I18nUtils.get("redirect.button.clear"));
        buttonPanel.add(addBtn);
        buttonPanel.add(clearBtn);
        inputPanel.add(buttonPanel);

        JTable table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setMinimumSize(new Dimension(200, 100));
        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(tableScroll, BorderLayout.CENTER);

        addBtn.addActionListener(e -> {
            String value = inputField.getText().trim();
            if (!value.isEmpty() && !isDuplicate(model, value)) {
                model.addRow(new Object[]{value});
                inputField.setText("");
            }
        });

        clearBtn.addActionListener(e -> {
            model.setRowCount(0);
            inputField.setText("");
            if (defaultValues != null) {
                for (String value : defaultValues) {
                    model.addRow(new Object[]{value});
                }
            }
        });

        if (defaultValues != null) {
            for (String value : defaultValues) {
                model.addRow(new Object[]{value});
            }
        }

        return panel;
    }

    private boolean isDuplicate(DefaultTableModel model, String value) {
        for (int i = 0; i < model.getRowCount(); i++) {
            if (value.equals(model.getValueAt(i, 0))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    @Override
    protected String getScanName() {
        return "UrlRedirect";
    }

    @Override
    protected void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual) {
        for (IHttpRequestResponse rr : requestResponses) {
            scanRequest(rr);
        }
    }

    @Override
    public String getTabName() {
        return "UrlRedirect";
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (passiveScanEnabled && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            startPassiveScan(new IHttpRequestResponse[]{iHttpRequestResponse}, false);
        }
    }

    /** 保留静态入口，兼容菜单或旧版本调用方；真正扫描使用当前实例状态。 */
    public static void scan(IHttpRequestResponse baseRequestResponse) {
        UrlRedirectUI ui = instance;
        if (ui != null) {
            ui.scanRequest(baseRequestResponse);
        }
    }

    private void scanRequest(IHttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse == null || Utils.helpers == null || Utils.callbacks == null) {
            return;
        }
        scanLock.lock();
        try {
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            if (analyzeRequest == null || analyzeRequest.getUrl() == null) {
                return;
            }
            String method = analyzeRequest.getMethod();
            URL url = analyzeRequest.getUrl();

            if (Utils.isUrlBlackListSuffix(url.toString())) {
                return;
            }

            List<String> redirectPayloads = generateRedirectPayloads(url.getHost());
            List<String> testParams = snapshotModel(paramModel);
            for (String payload : redirectPayloads) {
                testRedirect(baseRequestResponse, payload, method, testParams);
            }
        } finally {
            scanLock.unlock();
        }
    }

    private List<String> generateRedirectPayloads(String host) {
        List<String> payloads = snapshotModel(payloadModel);

        if (payloads.isEmpty()) {
            payloads.addAll(Arrays.asList(
                    "https://" + host + "%40www.evil.com",
                    "https://www.evil.com%2F" + host,
                    "https://www.evil.com%3F" + host,
                    "https://www.evil.com%23" + host,
                    "https://www.evil.com%5C" + host,
                    "https://www.evil.com%2E" + host,
                    "//www.evil.com",
                    "http://www.evil.com",
                    "https://www.evil.com"
            ));
        }

        return payloads;
    }


    private void testRedirect(IHttpRequestResponse baseRequestResponse, String payload, String method,
                              List<String> testParams) {
        IRequestInfo requestInfo = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<IParameter> parameters = requestInfo.getParameters();

        if (testParams.isEmpty()) {
            testParams.addAll(Arrays.asList(
                    "redirect","redirect_to","url","jump","target","to","link","goto","return_url","next","returnUrl","return","redirectUrl","callback","toUrl","ReturnUrl","fromUrl","redUrl","request","redirect_url","jump_to","linkto","domain","oauth_callback"
            ));
        }

        for (IParameter parameter : parameters) {
            if (parameter.getType() != IParameter.PARAM_URL) {
                continue;
            }

            if (testParams.contains(parameter.getName())) {
                IParameter newParam = Utils.helpers.buildParameter(
                        parameter.getName(), payload, IParameter.PARAM_URL
                );
                byte[] newRequest = Utils.helpers.updateParameter(
                        baseRequestResponse.getRequest(), newParam
                );
                IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(), newRequest
                );
                if (response == null || response.getResponse() == null) {
                    Utils.stderr.println("Redirect scan skipped: target returned no response");
                    continue;
                }
                IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response.getResponse());

                boolean isVulnerable = false;
                if (responseInfo.getStatusCode() == 302 || responseInfo.getStatusCode() == 301) {
                    for (String header : responseInfo.getHeaders()) {
                        if (header != null && header.toLowerCase().startsWith("location:")) {
                            String location = header.substring(9).trim();
                            if (RedirectLocationUtils.isHostOrSubdomain(location, "evil.com")) {
                                isVulnerable = true;
                                break;
                            }
                        }
                    }
                }

                synchronized (redirectLog) {
                    redirectLog.add(new RedirectEntry(
                            redirectLog.size(), method, requestInfo.getUrl().toString(),
                            parameter.getName(), String.valueOf(responseInfo.getStatusCode()),
                            isVulnerable, Utils.callbacks.saveBuffersToTempFiles(response)
                    ));
                    SwingUtilities.invokeLater(() -> {
                        UrlRedirectUI ui = instance;
                        if (ui != null) refreshTableModel(ui.resultTable);
                    });
                }
            }
        }
    }
    /** DefaultTableModel 只在 EDT 上读写，扫描线程使用一次性快照避免并发读写。 */
    private static List<String> snapshotModel(DefaultTableModel model) {
        final List<String> values = new ArrayList<>();
        if (model == null) {
            return values;
        }
        Runnable copy = () -> {
            for (int i = 0; i < model.getRowCount(); i++) {
                Object value = model.getValueAt(i, 0);
                if (value != null) {
                    String text = String.valueOf(value).trim();
                    if (!text.isEmpty()) {
                        values.add(text);
                    }
                }
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            copy.run();
            return values;
        }
        try {
            SwingUtilities.invokeAndWait(copy);
        } catch (Exception e) {
            Utils.stderr.println("Redirect configuration snapshot failed: " + e.getMessage());
        }
        return values;
    }

}
