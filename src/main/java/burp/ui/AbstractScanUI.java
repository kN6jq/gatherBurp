package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import burp.utils.I18nUtils;
import burp.utils.ScanTaskExecutor;
import burp.utils.UrlCacheUtil;
import burp.utils.Utils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.util.List;

/**
 * 扫描类 UI 抽象基类（Sql/Fastjson/Log4j/Auth/Perm/Route/UrlRedirect）：
 * 统一初始化时序（init → createEditors → setupScanUI → setupCommonUI → loadSavedData）、
 * 被动扫描消息过滤、ScanTaskExecutor 提交模板方法与 house-style 布局工具方法。
 *
 * <p>线程模型：init/组件构建/表格刷新均在 EDT（refreshTableModel 自动切 EDT）；
 * processHttpMessage 跑在 Burp 代理监听线程，只做轻量过滤。</p>
 */
public abstract class AbstractScanUI implements UIHandler, IMessageEditorController, IHttpListener {
    protected JPanel panel;
    // 表格选中行时记录（EDT 写）；Burp 消息编辑器控制器回调读取
    protected volatile IHttpRequestResponse currentlyDisplayedItem;
    protected IMessageEditor requestEditor;
    protected IMessageEditor responseEditor;
    protected JTabbedPane requestTabPane;
    protected JTabbedPane responseTabPane;
    protected JCheckBox passiveScanCheckBox;
    protected JTable resultTable;
    protected JTable getResultTable() { return resultTable; }

    protected volatile boolean passiveScanEnabled;


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
    /** JSplitPane 在 UI 尚未显示时无法正确应用比例位置，保存比例供显示后恢复。 */
    private static final String INITIAL_DIVIDER_WEIGHT = "gather.initialDividerWeight";
    private static final String LAYOUT_REPAIR_INSTALLED = "gather.layoutRepairInstalled";

    /** 返回面板（懒创建 + 安装一次性布局修复）。EDT 调用。 */
    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        if (panel == null) {
            panel = new JPanel(new BorderLayout());
        }
        // Burp 2024.x 在主标签切换时可能先完成子面板布局、后完成 JSplitPane
        // 尺寸计算，导致之前保存的比例位置失效。首次返回面板时先挂上延迟修复。
        installLayoutRepair(panel);
        return panel;
    }

    /** 当前选中消息的 HTTP 服务（IMessageEditorController 回调，未选中时返回 null）。 */
    @Override
    public IHttpService getHttpService() {
        IHttpRequestResponse item = currentlyDisplayedItem;
        return item == null ? null : item.getHttpService();
    }

    /** 当前选中消息的请求字节（未选中时返回 null）。 */
    @Override
    public byte[] getRequest() {
        IHttpRequestResponse item = currentlyDisplayedItem;
        return item == null ? null : item.getRequest();
    }

    /** 当前选中消息的响应字节（未选中时返回 null）。 */
    @Override
    public byte[] getResponse() {
        IHttpRequestResponse item = currentlyDisplayedItem;
        return item == null ? null : item.getResponse();
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
        split.putClientProperty(INITIAL_DIVIDER_WEIGHT, weight);
        split.setResizeWeight(weight);
        // 组件还没有加入 Burp 的可见层级时，setDividerLocation(double) 可能
        // 只能记录无效位置。只有在已有尺寸时立即设置，显示后由修复逻辑再设置一次。
        if (split.getWidth() > 0 || split.getHeight() > 0) {
            split.setDividerLocation(weight);
        }
        return split;
    }

    /**
     * 在容器真正加入 Burp 的标签页并完成布局后，递归恢复所有带比例标记的分割线。
     * 该方法同时供 MainUI 的顶层标签切换监听调用。
     */
    public static void restoreInitialSplitLayout(Component root) {
        if (root == null) {
            return;
        }
        if (root instanceof JSplitPane) {
            JSplitPane split = (JSplitPane) root;
            Object weight = split.getClientProperty(INITIAL_DIVIDER_WEIGHT);
            if (weight instanceof Number) {
                int size = split.getOrientation() == JSplitPane.HORIZONTAL_SPLIT
                        ? split.getWidth() : split.getHeight();
                if (size > 0) {
                    split.setDividerLocation(((Number) weight).doubleValue());
                }
            }
            restoreInitialSplitLayout(split.getLeftComponent());
            restoreInitialSplitLayout(split.getRightComponent());
        } else if (root instanceof Container) {
            for (Component child : ((Container) root).getComponents()) {
                restoreInitialSplitLayout(child);
            }
        }
    }

    /** 安装一次性尺寸监听，兼容第一次打开和后续切换主标签两种时序。 */
    private static void installLayoutRepair(final JComponent root) {
        if (Boolean.TRUE.equals(root.getClientProperty(LAYOUT_REPAIR_INSTALLED))) {
            return;
        }
        root.putClientProperty(LAYOUT_REPAIR_INSTALLED, Boolean.TRUE);
        final ComponentAdapter repairListener = new ComponentAdapter() {
            private boolean repaired;

            private void repair() {
                if (repaired || (root.getWidth() <= 0 && root.getHeight() <= 0)) {
                    return;
                }
                repaired = true;
                restoreInitialSplitLayout(root);
                root.revalidate();
                root.repaint();
                root.removeComponentListener(this);
            }

            @Override
            public void componentShown(ComponentEvent e) { repair(); }

            @Override
            public void componentResized(ComponentEvent e) { repair(); }
        };
        root.addComponentListener(repairListener);
        SwingUtilities.invokeLater(() -> {
            restoreInitialSplitLayout(root);
            root.revalidate();
        });
    }

    /**
     * 构造统一的紧凑扫描选项区。
     *
     * <p>旧实现普遍使用 GridLayout + 多层 JSplitPane。GridLayout 会把最后一行
     * 的空白也均分出来，多层分割器又会扩大空白区域，导致右侧配置栏显得松散。
     * 这里使用 GridBagLayout，只保留必要的行高，并让最后一个奇数项横跨两列。</p>
     */
    protected JPanel createCompactOptionsPanel(String title, JComponent... components) {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                BorderFactory.createEmptyBorder(1, 4, 2, 4)));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        GridBagConstraints constraints = new GridBagConstraints();
        constraints.fill = GridBagConstraints.HORIZONTAL;
        constraints.anchor = GridBagConstraints.WEST;
        constraints.weightx = 1.0;
        constraints.insets = new Insets(1, 2, 1, 8);

        if (components != null) {
            for (int i = 0; i < components.length; i++) {
                JComponent component = components[i];
                if (component == null) continue;
                if (component instanceof AbstractButton) {
                    component.setOpaque(false);
                    ((AbstractButton) component).setBorderPainted(false);
                }
                constraints.gridx = i % 2;
                constraints.gridy = i / 2;
                constraints.gridwidth = (i == components.length - 1 && components.length % 2 == 1) ? 2 : 1;
                panel.add(component, constraints);
            }
        }
        return panel;
    }

    /** 统一右侧按钮区的间距，避免 FlowLayout 默认边距造成视觉空洞。 */
    protected JPanel createCompactButtonPanel(Component... components) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 3, 2));
        panel.setBorder(BorderFactory.createEmptyBorder(0, 2, 0, 2));
        if (components != null) {
            for (Component component : components) {
                if (component != null) panel.add(component);
            }
        }
        return panel;
    }

    /** 右侧内部使用的紧凑分割器：去掉默认边框和过宽拖拽条。 */
    protected JSplitPane applyCompactSplit(JSplitPane split, double weight) {
        split.setBorder(null);
        split.setDividerSize(3);
        split.setOneTouchExpandable(false);
        split.setContinuousLayout(true);
        return applyWeights(split, weight);
    }

    /**
     * 子类实现：加载已保存的配置数据到UI组件
     */
    protected abstract void loadSavedData();

    /** 被动扫描监听（Burp 代理监听线程）：过滤开关/方向/工具来源后提交统一有界池。 */
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // 被动扫描只消费真实响应。旧实现只接受 TOOL_PROXY，导致从 Target、Scanner、
        // Repeater、Intruder 等工具产生的响应完全不会进入模块。
        // TOOL_EXTENDER 明确排除，避免插件自己的 makeHttpRequest 触发递归扫描。
        if (!passiveScanEnabled || messageIsRequest || !isPassiveScanSource(toolFlag)) {
            return;
        }
        if (messageInfo == null || messageInfo.getRequest() == null
                || messageInfo.getHttpService() == null || messageInfo.getResponse() == null) {
            return;
        }

        // 正常被动流量不写扩展输出，避免大量代理流量刷屏。
        startPassiveScan(new IHttpRequestResponse[]{messageInfo}, false);
    }

    /**
     * 被动扫描允许处理的 Burp 工具来源。
     * EXTENDER 不在此处列出：扫描模块通过 callbacks 发出的探测请求不应再次进入被动扫描。
     */
    protected boolean isPassiveScanSource(int toolFlag) {
        return toolFlag == IBurpExtenderCallbacks.TOOL_PROXY
                || toolFlag == IBurpExtenderCallbacks.TOOL_TARGET
                || toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER
                || toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER
                || toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER
                || toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER;
    }

    private String toolName(int toolFlag) {
        if (toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) return "PROXY";
        if (toolFlag == IBurpExtenderCallbacks.TOOL_TARGET) return "TARGET";
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER) return "SCANNER";
        if (toolFlag == IBurpExtenderCallbacks.TOOL_INTRUDER) return "INTRUDER";
        if (toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) return "REPEATER";
        if (toolFlag == IBurpExtenderCallbacks.TOOL_SPIDER) return "SPIDER";
        return String.valueOf(toolFlag);
    }

    /**
     * 被动扫描线程启动模板方法。任务拒绝和执行异常都明确写入扩展输出，避免“点击后无反应”。
     */
    protected void startPassiveScan(final IHttpRequestResponse[] requestResponses, final boolean isManual) {
        if (!passiveScanEnabled || requestResponses == null || requestResponses.length == 0
                || requestResponses[0] == null) {
            return;
        }
        boolean accepted = ScanTaskExecutor.execute(getScanName() + " passive scan", () ->
                doPassiveScan(requestResponses, isManual));
        if (!accepted) {
            logPassiveEvent("not queued: executor unavailable or queue full");
        }
    }

    protected void logPassiveEvent(String message) {
        if (Utils.stderr != null) {
            Utils.stderr.println("[" + getScanName() + "][passive] " + message);
        }
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
     * URL 去重检查（命中返回 true 并消费键，重复返回 false）。
     */
    protected boolean isUrlUnique(String moduleName, String method, java.net.URL url, List<burp.IParameter> parameters) {
        return UrlCacheUtil.checkUrlUnique(moduleName, method, url, parameters);
    }

    /**
     * 重置指定模块的去重缓存。
     */
    protected void resetCaches(String moduleName) {
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
     * 在 EDT 上通知表格模型数据已刷新。不要使用 JTable.updateUI() 刷新业务数据，
     * updateUI 会重新安装 UI delegate，代价高且可能丢失排序/选择状态。
     */
    protected static void refreshTableModel(JTable table) {
        if (table == null) {
            return;
        }
        Runnable refresh = () -> {
            if (table.getModel() instanceof AbstractTableModel) {
                ((AbstractTableModel) table.getModel()).fireTableDataChanged();
            } else {
                table.revalidate();
                table.repaint();
            }
        };
        if (SwingUtilities.isEventDispatchThread()) {
            refresh.run();
        } else {
            SwingUtilities.invokeLater(refresh);
        }
    }

    /**
     * 清空结果表格和编辑器。
     */
    protected void clearResults() {
        refreshTableModel(getResultTable());
        if (requestEditor != null) requestEditor.setMessage(new byte[0], true);
        if (responseEditor != null) responseEditor.setMessage(new byte[0], false);
    }

}


