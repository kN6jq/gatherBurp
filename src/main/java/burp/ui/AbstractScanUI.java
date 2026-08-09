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
        setupScanUI();
        setupCommonUI();
        loadSavedData();
    }

    /**
     * 子类实现：设置扫描专用组件（表格、复选框等），在setupCommonUI之前调用
     */
    protected abstract void setupScanUI();

    /**
     * 创建通用的消息编辑器面板（表格 + 请求/响应编辑器），依赖子类已初始化resultTable
     */
    protected void setupCommonUI() {
        panel = new JPanel(new BorderLayout());

        if (resultTable == null) {
            resultTable = new JTable();
        }
        JScrollPane tableScrollPane = new JScrollPane(resultTable);
        tableScrollPane.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("common.border.results")));

        if (Utils.callbacks != null) {
            requestEditor = Utils.callbacks.createMessageEditor(this, true);
            responseEditor = Utils.callbacks.createMessageEditor(this, false);
        }

        if (requestEditor != null && responseEditor != null) {
            requestTabPane = new JTabbedPane();
            requestTabPane.addTab("Request", requestEditor.getComponent());
            responseTabPane = new JTabbedPane();
            responseTabPane.addTab("Response", responseEditor.getComponent());

            JSplitPane editorSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            editorSplitPane.setLeftComponent(requestTabPane);
            editorSplitPane.setRightComponent(responseTabPane);
            editorSplitPane.setResizeWeight(0.5);

            JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            mainSplitPane.setTopComponent(tableScrollPane);
            mainSplitPane.setBottomComponent(editorSplitPane);
            mainSplitPane.setResizeWeight(0.6);

            panel.add(mainSplitPane, BorderLayout.CENTER);
        } else {
            panel.add(tableScrollPane, BorderLayout.CENTER);
        }
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
