package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.utils.I18nUtils;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * 扫描类UI的抽象基类
 * 提供通用的UI组件、被动扫描、URL去重等功能
 */
public abstract class AbstractScanUI implements UIHandler, IMessageEditorController, IHttpListener {
    protected JPanel panel;
    protected static IHttpRequestResponse currentlyDisplayedItem;
    protected IMessageEditor requestEditor;
    protected IMessageEditor responseEditor;
    protected JTabbedPane requestTabPane;
    protected JTabbedPane responseTabPane;
    protected JCheckBox passiveScanCheckBox;
    protected static JTable resultTable;
    protected static JTable getResultTable() { return resultTable; }

    protected static final List<String> urlHashList = new ArrayList<>();
    protected static final List<String> parameterList = new ArrayList<>();
    protected boolean passiveScanEnabled;

    // ===== 主推样式常量（Canonical house style）=====
    /** 结果表 / 编辑器 纵向分割权重 */
    protected static final double WEIGHT_TABLE_EDITOR = 0.6;
    /** 请求 / 响应编辑器横向分割权重 */
    protected static final double WEIGHT_EDITORS = 0.5;
    /** 外层 主区 / 右侧配置 水平分割权重 */
    protected static final double WEIGHT_MAIN = 0.65;
    /** 右侧配置内部（扫描选项 / 配置+操作）纵向分割权重 */
    protected static final double WEIGHT_RIGHT_CONFIG = 0.3;
    /** 配置面板标准内边距 */
    protected static final Border PADDING_BORDER = BorderFactory.createEmptyBorder(5, 5, 5, 5);

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        if (panel == null) {
            panel = new JPanel(new BorderLayout());
        }
        return panel;
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
    public void init() {
        // 预先初始化panel，确保子类setupScanUI()中可以安全使用
        if (panel == null) {
            panel = new JPanel(new BorderLayout());
        }
        // 提前创建消息编辑器，确保所有子类（无论是否覆盖 setupCommonUI）
        // 都能拿到非空的 requestEditor/responseEditor，避免 NPE 与编辑器退化为空文本域。
        createEditors();
        setupScanUI();
        setupCommonUI();
        loadSavedData();
    }

    /**
     * 创建请求/响应消息编辑器。
     * 在 setupScanUI/setupCommonUI 之前调用，作为编辑器的唯一创建点，
     * 避免子类因覆盖 setupCommonUI（且未调用 super）而拿不到编辑器。
     * 若 callbacks 尚不可用（如扩展初始化线程早期）则跳过，子类对编辑器做空值保护即可。
     * 子类如使用自行创建的编辑器（如 PermUI），可覆盖此方法为空实现。
     */
    protected void createEditors() {
        if (Utils.callbacks != null && requestEditor == null && responseEditor == null) {
            requestEditor = Utils.callbacks.createMessageEditor(this, true);
            responseEditor = Utils.callbacks.createMessageEditor(this, false);
        }
    }

    /**
     * 子类实现：设置扫描专用组件（表格、复选框等），在setupCommonUI之前调用
     */
    protected abstract void setupScanUI();

    /**
     * 构建默认的消息编辑器面板（表格 + 请求/响应编辑器），依赖子类已初始化resultTable。
     * 编辑器由 createEditors() 在 init() 阶段提前创建，此处不再负责创建，仅负责装配。
     * 子类如需自定义布局应覆盖此方法（例如 Log4jUI 在 setupScanUI 中完成布局，覆盖此方法为空）。
     */
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        if (resultTable == null) {
            resultTable = new JTable();
        }
        JScrollPane tableScrollPane = wrapResultsTable(resultTable);

        JSplitPane editorSplitPane = buildEditorSplit();

        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setTopComponent(tableScrollPane);
        mainSplitPane.setBottomComponent(editorSplitPane);
        applyWeights(mainSplitPane, WEIGHT_TABLE_EDITOR);

        panel.add(mainSplitPane, BorderLayout.CENTER);
    }

    /**
     * 用主推样式包裹结果表：带 common.border.results 标题的滚动面板。
     */
    protected JScrollPane wrapResultsTable(JTable table) {
        JScrollPane sp = new JScrollPane(table);
        sp.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("common.border.results")));
        return sp;
    }

    /**
     * 构建标准的请求/响应横向编辑器分割（标签走 i18n）。
     * 复用 createEditors() 创建的 requestEditor/responseEditor，同时给
     * requestTabPane/responseTabPane 赋值，保持表格 changeSelection 引用兼容。
     */
    protected JSplitPane buildEditorSplit() {
        requestTabPane = new JTabbedPane();
        requestTabPane.addTab(I18nUtils.get("common.tab.request"),
                requestEditor != null ? requestEditor.getComponent() : fallbackPane());
        responseTabPane = new JTabbedPane();
        responseTabPane.addTab(I18nUtils.get("common.tab.response"),
                responseEditor != null ? responseEditor.getComponent() : fallbackPane());
        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        split.setLeftComponent(requestTabPane);
        split.setRightComponent(responseTabPane);
        return applyWeights(split, WEIGHT_EDITORS);
    }

    private static JScrollPane fallbackPane() {
        return new JScrollPane(new JTextArea());
    }

    /**
     * 同时设置分割面板的 resizeWeight 与初始 dividerLocation，使初始布局确定。
     */
    protected JSplitPane applyWeights(JSplitPane split, double weight) {
        split.setResizeWeight(weight);
        split.setDividerLocation(weight);
        return split;
    }

    /**
     * 子类实现：加载已保存的配置数据到UI组件
     */
    protected abstract void loadSavedData();

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (passiveScanEnabled && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY && !messageIsRequest) {
            startPassiveScan(new IHttpRequestResponse[]{messageInfo}, false);
        }
    }

    /**
     * 被动扫描线程启动模板方法
     */
    protected void startPassiveScan(final IHttpRequestResponse[] requestResponses, final boolean isManual) {
        if (!passiveScanEnabled) return;
        Thread thread = new Thread(() -> {
            try {
                doPassiveScan(requestResponses, isManual);
            } catch (Exception ex) {
                Utils.stderr.println(getScanName() + " scan error: " + ex.getMessage());
            }
        });
        thread.start();
    }

    /**
     * 子类实现被动扫描逻辑
     */
    protected abstract void doPassiveScan(IHttpRequestResponse[] requestResponses, boolean isManual);

    /**
     * 子类提供扫描名称（用于日志）
     */
    protected abstract String getScanName();

    /**
     * URL去重检查
     */
    protected boolean isUrlUnique(String moduleName, String method, java.net.URL url, List<burp.IParameter> parameters) {
        return UrlCacheUtil.checkUrlUnique(moduleName, method, url, parameters);
    }

    /**
     * 重置缓存
     */
    protected void resetCaches(String moduleName) {
        urlHashList.clear();
        parameterList.clear();
        UrlCacheUtil.resetCache(moduleName);
    }

    /**
     * 安全设置请求/响应消息到编辑器
     */
    protected void safeSetMessage(byte[] request, byte[] response) {
        if (requestEditor != null) requestEditor.setMessage(request, true);
        if (responseEditor != null) responseEditor.setMessage(response, false);
    }

    /**
     * 清空结果表格和编辑器
     */
    protected void clearResults() {
        JTable table = getResultTable();
        if (table != null) table.updateUI();
        if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
        if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
    }
}
