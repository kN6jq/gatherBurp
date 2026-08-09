package burp.ui;

import burp.*;
import burp.utils.I18nUtils;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class UrlRedirectUI extends AbstractScanUI {
    private JButton btnClear;
    private JTabbedPane requestTabPane;
    private JTabbedPane responseTabPane;
    private JCheckBox chkPassiveScan;

    private static final List<RedirectEntry> redirectLog = new ArrayList<>();
    private static final Lock lock = new ReentrantLock();

    private static DefaultTableModel payloadModel;
    private static DefaultTableModel paramModel;

    static void setCurrentlyDisplayedItem(IHttpRequestResponse item) {
        currentlyDisplayedItem = item;
    }

    static List<RedirectEntry> getRedirectLog() {
        return redirectLog;
    }

    @Override
    protected void setupScanUI() {
        Utils.callbacks.registerHttpListener(this);
        resultTable = new RedirectTable(new RedirectModel(), requestEditor, responseEditor);
    }

    @Override
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        JSplitPane horizontalSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        horizontalSplitPane.setResizeWeight(0.8);

        JPanel leftPanel = new JPanel(new BorderLayout());

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        chkPassiveScan = new JCheckBox(I18nUtils.get("redirect.checkbox.passive"), false);
        btnClear = new JButton(I18nUtils.get("redirect.button.clear"));
        topPanel.add(chkPassiveScan);
        topPanel.add(btnClear);
        leftPanel.add(topPanel, BorderLayout.NORTH);

        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.5);

        leftSplitPane.setTopComponent(new JScrollPane(getResultTable()));

        JSplitPane viewerSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        viewerSplitPane.setResizeWeight(0.5);
        requestTabPane = new JTabbedPane();
        if (requestEditor != null) {
            requestTabPane.addTab("Request", requestEditor.getComponent());
        } else {
            requestTabPane.addTab("Request", new JScrollPane(new JTextArea()));
        }
        responseTabPane = new JTabbedPane();
        if (responseEditor != null) {
            responseTabPane.addTab("Response", responseEditor.getComponent());
        } else {
            responseTabPane.addTab("Response", new JScrollPane(new JTextArea()));
        }
        viewerSplitPane.setLeftComponent(requestTabPane);
        viewerSplitPane.setRightComponent(responseTabPane);
        leftSplitPane.setBottomComponent(viewerSplitPane);

        leftPanel.add(leftSplitPane, BorderLayout.CENTER);

        JPanel rightPanel = setupSettingsPanel();
        rightPanel.setMinimumSize(new Dimension(250, 400));
        rightPanel.setPreferredSize(new Dimension(250, 400));

        horizontalSplitPane.setLeftComponent(leftPanel);
        horizontalSplitPane.setRightComponent(rightPanel);
        horizontalSplitPane.setDividerLocation(0.8);

        panel.add(horizontalSplitPane, BorderLayout.CENTER);
        panel.setPreferredSize(new Dimension(1200, 800));
    }

    @Override
    protected void loadSavedData() {
        btnClear.addActionListener(e -> {
            redirectLog.clear();
            if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
            if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
            getResultTable().updateUI();
        });

        chkPassiveScan.addActionListener(e -> passiveScanEnabled = chkPassiveScan.isSelected());
    }

    private JPanel setupSettingsPanel() {
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("redirect.border.settings")));

        paramModel = new DefaultTableModel(new String[]{I18nUtils.get("redirect.label.parameter")}, 0);
        payloadModel = new DefaultTableModel(new String[]{I18nUtils.get("redirect.label.payloads")}, 0);

        String[] defaultParams = {
                "redirect","redirect_to","url","jump","target","to","link","goto","return_url","next","returnUrl","return","redirectUrl","callback","toUrl","ReturnUrl","fromUrl","redUrl","request","redirect_url","jump_to","linkto","domain","oauth_callback"
        };
        String[] defaultPayloads = {};

        settingsPanel.add(createInputPanel("Parameters", paramModel, defaultParams));
        settingsPanel.add(createInputPanel("Payloads", payloadModel, defaultPayloads));

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
            scan(rr);
        }
    }

    @Override
    public String getTabName() {
        return "UrlRedirect";
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            scan(iHttpRequestResponse);
        }
    }

    public static void scan(IHttpRequestResponse baseRequestResponse) {
        lock.lock();
        try {
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String method = analyzeRequest.getMethod();
            URL url = analyzeRequest.getUrl();

            if (Utils.isUrlBlackListSuffix(url.toString())) {
                return;
            }

            List<String> redirectPayloads = generateRedirectPayloads(url.getHost());
            for (String payload : redirectPayloads) {
                testRedirect(baseRequestResponse, payload, method);
            }
        } finally {
            lock.unlock();
        }
    }

    private static List<String> generateRedirectPayloads(String host) {
        List<String> payloads = new ArrayList<>();

        for (int i = 0; i < payloadModel.getRowCount(); i++) {
            payloads.add((String) payloadModel.getValueAt(i, 0));
        }

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

    private static void testRedirect(IHttpRequestResponse baseRequestResponse, String payload, String method) {
        IRequestInfo requestInfo = Utils.helpers.analyzeRequest(baseRequestResponse);
        List<IParameter> parameters = requestInfo.getParameters();

        List<String> testParams = new ArrayList<>();
        for (int i = 0; i < paramModel.getRowCount(); i++) {
            testParams.add((String) paramModel.getValueAt(i, 0));
        }

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
                IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response.getResponse());

                boolean isVulnerable = false;
                if (responseInfo.getStatusCode() == 302 || responseInfo.getStatusCode() == 301) {
                    for (String header : responseInfo.getHeaders()) {
                        if (header.toLowerCase().startsWith("location:")) {
                            String location = header.substring(9).trim();
                            if (location.contains("evil.com")) {
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
                    SwingUtilities.invokeLater(() -> getResultTable().updateUI());
                }
            }
        }
    }
}
