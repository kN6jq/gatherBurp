package burp.ui;

import burp.*;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.util.*;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * URL重定向扫描UI类
 * 实现了UIHandler和IMessageEditorController接口
 */
public class UrlRedirectUI implements UIHandler, IMessageEditorController, IHttpListener {
    // UI组件
    private JPanel mainPanel;                // 主面板
    private static JTable urlTable;          // URL表格
    private JButton btnClear;                // 清除按钮
    private JTabbedPane requestPane;         // 请求面板
    private JTabbedPane responsePane;        // 响应面板
    private JCheckBox chkPassiveScan;        // 被动扫描开关

    // Burp组件
    private static IHttpRequestResponse currentlyDisplayedItem;  // 当前显示的请求/响应
    private static IMessageEditor requestViewer;                // 请求查看器
    private static IMessageEditor responseViewer;               // 响应查看器

    // 数据存储
    private static final List<RedirectEntry> redirectLog = new ArrayList<>();  // 重定向日志
    private static final Lock lock = new ReentrantLock();                     // 线程锁

    // 设置组件
    private static DefaultTableModel payloadModel;  // payload表格模型
    private static DefaultTableModel paramModel;    // 参数表格模型


    @Override
    public void init() {
        setupUI();    // 初始化UI
        setupData();  // 初始化数据
    }

    /**
     * 初始化UI组件
     */
    private void setupUI() {
        Utils.callbacks.registerHttpListener(this);
        mainPanel = new JPanel(new BorderLayout());

        // 创建主水平分割面板
        JSplitPane horizontalSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        horizontalSplitPane.setResizeWeight(0.8); // 左侧占80%的空间

        // 左侧面板(包含表格和查看器)
        JPanel leftPanel = new JPanel(new BorderLayout());

        // 创建顶部面板，包含清除按钮和被动扫描开关
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        chkPassiveScan = new JCheckBox("被动扫描", false);  // 默认开启
        btnClear = new JButton("清除");
        topPanel.add(chkPassiveScan);
        topPanel.add(btnClear);
        leftPanel.add(topPanel, BorderLayout.NORTH);

        // 设置主要内容区域，包含表格和查看器
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        leftSplitPane.setResizeWeight(0.5);

        // 设置URL表格
        urlTable = new RedirectTable(new RedirectModel());
        urlTable.setAutoCreateRowSorter(true);
        leftSplitPane.setTopComponent(new JScrollPane(urlTable));

        // 设置请求/响应查看器
        JSplitPane viewerSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        viewerSplitPane.setResizeWeight(0.5);
        setupViewers(viewerSplitPane);
        leftSplitPane.setBottomComponent(viewerSplitPane);

        leftPanel.add(leftSplitPane, BorderLayout.CENTER);

        // 右侧设置面板
        JPanel rightPanel = setupSettingsPanel();

        // 设置右侧面板最小宽度
        rightPanel.setMinimumSize(new Dimension(250, 400));
        rightPanel.setPreferredSize(new Dimension(250, 400));

        // 将左右面板添加到水平分割面板
        horizontalSplitPane.setLeftComponent(leftPanel);
        horizontalSplitPane.setRightComponent(rightPanel);

        // 设置分割面板的分隔条位置
        horizontalSplitPane.setDividerLocation(0.8);
        horizontalSplitPane.setResizeWeight(0.8);

        mainPanel.add(horizontalSplitPane, BorderLayout.CENTER);

        // 设置整个面板的首选大小
        mainPanel.setPreferredSize(new Dimension(1200, 800));
    }

    /**
     * 设置请求响应查看器
     */
    private void setupViewers(JSplitPane viewerSplitPane) {
        requestPane = new JTabbedPane();
        responsePane = new JTabbedPane();

        requestViewer = Utils.callbacks.createMessageEditor(this, false);
        responseViewer = Utils.callbacks.createMessageEditor(this, false);

        requestPane.addTab("请求", requestViewer.getComponent());
        responsePane.addTab("响应", responseViewer.getComponent());

        viewerSplitPane.setLeftComponent(requestPane);
        viewerSplitPane.setRightComponent(responsePane);
    }

    /**
     * 生成重定向测试payload
     */
    private static List<String> generateRedirectPayloads(String host) {
        List<String> payloads = new ArrayList<>();

        // 从payload表格中获取所有payload
        for (int i = 0; i < payloadModel.getRowCount(); i++) {
            payloads.add((String) payloadModel.getValueAt(i, 0));
        }

        // 如果没有自定义payload，使用默认payload
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

    /**
     * 设置配置面板
     */
    private JPanel setupSettingsPanel() {
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createTitledBorder("设置"));

        // 创建表格模型
        paramModel = new DefaultTableModel(new String[]{"参数"}, 0);
        payloadModel = new DefaultTableModel(new String[]{"Payload"}, 0);

        // 设置默认参数
        String[] defaultParams = {
                "redirect","redirect_to","url","jump","target","to","link","goto","return_url","next","returnUrl","return","redirectUrl","callback","toUrl","ReturnUrl","fromUrl","redUrl","request","redirect_url","jump_to","linkto","domain","oauth_callback"
        };

        // 设置默认payload
        String[] defaultPayloads = {
        };

        // 创建并添加面板（带默认值）
        settingsPanel.add(createInputPanel("参数", paramModel, defaultParams));
        settingsPanel.add(createInputPanel("Payloads", payloadModel, defaultPayloads));

        // 设置最小宽度以防止组件被压缩
        settingsPanel.setMinimumSize(new Dimension(250, 400));
        settingsPanel.setPreferredSize(new Dimension(250, 400));

        return settingsPanel;
    }

    /**
     * 创建输入面板
     *
     * @param title         面板标题
     * @param model         表格模型
     * @param defaultValues 默认值
     * @return 配置面板
     */
    private JPanel createInputPanel(String title, DefaultTableModel model, String... defaultValues) {
        // 创建主面板，使用BorderLayout布局
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));

        // 创建输入和按钮面板，使用固定大小
        JPanel inputPanel = new JPanel();
        inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.X_AXIS));
        inputPanel.setMinimumSize(new Dimension(200, 30));
        inputPanel.setPreferredSize(new Dimension(200, 30));

        // 创建输入框
        final JTextField inputField = new JTextField(20);
        inputField.setMinimumSize(new Dimension(120, 25));
        inputField.setPreferredSize(new Dimension(120, 25));
        // 添加回车键监听
        inputField.addActionListener(e -> {
            String value = inputField.getText().trim();
            if (!value.isEmpty()) {
                // 检查是否重复
                boolean isDuplicate = false;
                for (int i = 0; i < model.getRowCount(); i++) {
                    if (value.equals(model.getValueAt(i, 0))) {
                        isDuplicate = true;
                        break;
                    }
                }
                if (!isDuplicate) {
                    model.addRow(new Object[]{value});
                    inputField.setText("");
                }
            }
        });
        inputPanel.add(inputField);
        inputPanel.add(Box.createHorizontalStrut(5)); // 添加间隔

        // 创建按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 2, 0));
        JButton addBtn = new JButton("添加");
        JButton clearBtn = new JButton("清除");

        buttonPanel.add(addBtn);
        buttonPanel.add(clearBtn);
        inputPanel.add(buttonPanel);

        // 创建表格面板
        JTable table = new JTable(model);
        // 设置表格可以选择整行
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setMinimumSize(new Dimension(200, 100));

        // 添加组件到主面板
        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(tableScroll, BorderLayout.CENTER);

        // 添加按钮事件监听
        addBtn.addActionListener(e -> {
            String value = inputField.getText().trim();
            if (!value.isEmpty()) {
                // 检查是否重复
                boolean isDuplicate = false;
                for (int i = 0; i < model.getRowCount(); i++) {
                    if (value.equals(model.getValueAt(i, 0))) {
                        isDuplicate = true;
                        break;
                    }
                }
                if (!isDuplicate) {
                    model.addRow(new Object[]{value});
                    inputField.setText("");
                }
            }
        });

        clearBtn.addActionListener(e -> {
            model.setRowCount(0);
            inputField.setText("");
            // 如果有默认值，重新添加
            if (defaultValues != null) {
                for (String value : defaultValues) {
                    model.addRow(new Object[]{value});
                }
            }
        });

        // 添加默认值到表格
        if (defaultValues != null) {
            for (String value : defaultValues) {
                model.addRow(new Object[]{value});
            }
        }

        return panel;
    }

    /**
     * 初始化数据和事件监听
     */
    private void setupData() {
        // 清除按钮事件
        btnClear.addActionListener(e -> {
            redirectLog.clear();
            requestViewer.setMessage(new byte[0], true);
            responseViewer.setMessage(new byte[0], false);
            urlTable.updateUI();
        });
    }

    /**
     * 核心扫描逻辑
     */
    public static void scan(IHttpRequestResponse baseRequestResponse) {
        lock.lock();
        try {
            IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
            String method = analyzeRequest.getMethod();
            URL url = analyzeRequest.getUrl();

            // 检查URL是否在排除列表中
            if (Utils.isUrlBlackListSuffix(url.toString())) {
                return;
            }

            // 生成并测试重定向payload
            List<String> redirectPayloads = generateRedirectPayloads(url.getHost());
            for (String payload : redirectPayloads) {
                testRedirect(baseRequestResponse, payload, method);
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * 测试重定向
     * @param baseRequestResponse 原始的请求响应对
     * @param payload 要测试的payload
     * @param method HTTP方法
     */
    private static void testRedirect(IHttpRequestResponse baseRequestResponse, String payload, String method) {
        IRequestInfo requestInfo = Utils.helpers.analyzeRequest(baseRequestResponse);

        // 获取当前请求中的所有参数
        List<IParameter> parameters = requestInfo.getParameters();

        // 获取配置的测试参数列表
        List<String> testParams = new ArrayList<>();
        for (int i = 0; i < paramModel.getRowCount(); i++) {
            testParams.add((String) paramModel.getValueAt(i, 0));
        }

        // 如果没有配置参数，使用默认参数
        if (testParams.isEmpty()) {
            testParams.addAll(Arrays.asList(
                    "redirect","redirect_to","url","jump","target","to","link","goto","return_url","next","returnUrl","return","redirectUrl","callback","toUrl","ReturnUrl","fromUrl","redUrl","request","redirect_url","jump_to","linkto","domain","oauth_callback"

            ));
        }

        // 遍历当前请求中的所有参数
        for (IParameter parameter : parameters) {
            // 只处理URL参数
            if (parameter.getType() != IParameter.PARAM_URL) {
                continue;
            }

            // 检查参数名是否在测试列表中
            if (testParams.contains(parameter.getName())) {
                // 构建新的参数值（使用payload替换原值）
                IParameter newParam = Utils.helpers.buildParameter(
                        parameter.getName(),
                        payload,
                        IParameter.PARAM_URL
                );

                // 更新请求参数
                byte[] newRequest = Utils.helpers.updateParameter(
                        baseRequestResponse.getRequest(),
                        newParam
                );

                // 发送请求
                IHttpRequestResponse response = Utils.callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(),
                        newRequest
                );

                // 检查响应
                IResponseInfo responseInfo = Utils.helpers.analyzeResponse(response.getResponse());

                // 判断是否存在漏洞：检查状态码和Location头
                boolean isVulnerable = false;
                if (responseInfo.getStatusCode() == 302 || responseInfo.getStatusCode() == 301) {
                    // 获取Location头
                    List<String> headers = responseInfo.getHeaders();
                    for (String header : headers) {
                        if (header.toLowerCase().startsWith("location:")) {
                            String location = header.substring(9).trim();
                            // 检查location是否包含payload
                            if (location.contains("evil.com")) {
                                isVulnerable = true;
                                break;
                            }
                        }
                    }

                    // 记录重定向发现
                    synchronized (redirectLog) {
                        redirectLog.add(new RedirectEntry(
                                redirectLog.size(),
                                method,
                                requestInfo.getUrl().toString(),
                                parameter.getName(),
                                String.valueOf(responseInfo.getStatusCode()),
                                isVulnerable,
                                Utils.callbacks.saveBuffersToTempFiles(response)
                        ));
                        urlTable.updateUI();
                    }
                }
            }
        }
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return mainPanel;
    }

    @Override
    public String getTabName() {
        return "UrlRedirect";
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse iHttpRequestResponse) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            scan(iHttpRequestResponse);
        }

    }

    private static class RedirectTable extends JTable {
        public RedirectTable(TableModel model) {
            super(model);
            // 设置列宽
            getColumnModel().getColumn(0).setMaxWidth(50);  // ID列
            getColumnModel().getColumn(1).setMaxWidth(80);  // 方法列
            getColumnModel().getColumn(4).setMaxWidth(80);  // 状态码列
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // 如果表格已排序，需要将视图索引转换为模型索引
            int modelRow = row;
            if (getRowSorter() != null) {
                modelRow = convertRowIndexToModel(row);
            }
            
            RedirectEntry entry = redirectLog.get(modelRow);
            // 更新请求响应查看器
            requestViewer.setMessage(entry.requestResponse.getRequest(), true);
            responseViewer.setMessage(entry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = entry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }

    private static class RedirectModel extends AbstractTableModel {
        // 将COLUMNS修改为包含是否存在漏洞的列
        private final String[] COLUMNS = {"#", "方法", "URL", "参数", "状态码", "是否存在漏洞"};

        @Override
        public int getRowCount() {
            return redirectLog.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            RedirectEntry entry = redirectLog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return entry.id;
                case 1:
                    return entry.method;
                case 2:
                    return entry.url;
                case 3:
                    return entry.parameter;
                case 4:
                    return entry.statusCode;
                case 5:
                    return entry.isVulnerable ? "是" : "否";
                default:
                    return null;
            }
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }
        
        @Override
        public Class<?> getColumnClass(int column) {
            if (column == 0) {
                return Integer.class;
            }
            return super.getColumnClass(column);
        }
    }

    private static class RedirectEntry {
        private final int id;              // 记录ID
        private final String method;       // HTTP方法
        private final String url;          // URL
        private final String parameter;    // 参数
        private final String statusCode;   // 状态码
        private final boolean isVulnerable;// 是否存在漏洞
        private final IHttpRequestResponse requestResponse;  // 请求响应对象

        public RedirectEntry(int id, String method, String url, String parameter,
                             String statusCode, boolean isVulnerable, IHttpRequestResponse requestResponse) {
            this.id = id;
            this.method = method;
            this.url = url;
            this.parameter = parameter;
            this.statusCode = statusCode;
            this.isVulnerable = isVulnerable;
            this.requestResponse = requestResponse;
        }
    }
}


