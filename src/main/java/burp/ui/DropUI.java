package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.bean.DropPackRule;
import burp.dao.DropPackDao;
import burp.ui.UIHelper.GridBagConstraintsHelper;
import burp.utils.DropPackMatcher;
import burp.utils.I18nUtils;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * DropPack 丢弃数据包面板：维护丢弃/自动放行规则表，展示命中计数。
 *
 * <p>线程模型：EDT（组件构建/规则编辑/表格刷新）/ Burp 代理监听线程（只读规则快照）。
 * 规则改动即落库并重建快照（DropPackMatcher.rebuild）；命中计数由代理线程累加，
 * 本面板用 Swing Timer 每 2 秒刷新展示，不阻塞代理。</p>
 */
public class DropUI implements UIHandler {
    /** 当前面板实例：DropMenu 加/删规则后经 {@link #reloadAndRefresh()} 刷新表格。 */
    private static volatile DropUI instance;

    private JPanel panel;
    private JCheckBox enableCheckBox;
    private JLabel totalLabel;
    private JComboBox<String> actionCombo;
    private JComboBox<String> matchCombo;
    private JTextField patternField;
    private JButton addButton;
    private JButton deleteButton;
    private JTable ruleTable;
    private DropPackTableModel tableModel;
    /** 规则列表：EDT 独占访问，保存时整体 JSON 落库并重建匹配快照。 */
    private List<DropPackRule> rules = new ArrayList<>();
    /** 命中计数与总数标签的定时刷新器（EDT 回调）。 */
    private final Timer refreshTimer = new Timer(2000, e -> refreshCounts());

    // 动作/匹配方式的取值与展示文案一一对应，组合框按索引取规范值
    private static final String[] ACTIONS = {DropPackRule.ACTION_DROP, DropPackRule.ACTION_FORWARD};
    private static final String[] MATCH_TYPES = {DropPackRule.MATCH_HOST, DropPackRule.MATCH_URL,
            DropPackRule.MATCH_KEYWORD, DropPackRule.MATCH_REGEX};
    private static final String[] ACTION_KEYS = {"droppack.action.drop", "droppack.action.forward"};
    private static final String[] MATCH_KEYS = {"droppack.match.host", "droppack.match.url",
            "droppack.match.keyword", "droppack.match.regex"};

    @Override
    public String getTabName() {
        return I18nUtils.get("droppack.tab.title");
    }

    @Override
    public void init() {
        DropPackMatcher.loadConfig();
        setupUI();
        loadState();
        setupListeners();
        instance = this;
        refreshTimer.start();
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    /** 右键菜单改动规则后调用：从库重新加载并刷新表格（切到 EDT 执行）。 */
    public static void reloadAndRefresh() {
        DropUI ui = instance;
        if (ui != null) {
            SwingUtilities.invokeLater(ui::reloadFromDao);
        }
    }

    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        // 顶部：总开关 + 总计数
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        enableCheckBox = new JCheckBox(I18nUtils.get("droppack.checkbox.enable"));
        totalLabel = new JLabel();
        topPanel.add(enableCheckBox);
        topPanel.add(totalLabel);
        panel.add(topPanel, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5)
                .setWeight(1, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.HORIZONTAL));

        // 添加规则区：动作 + 匹配方式 + 规则内容 + 按钮
        JPanel addPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        addPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("droppack.border.add")));
        actionCombo = new JComboBox<>(displayNames(ACTION_KEYS));
        matchCombo = new JComboBox<>(displayNames(MATCH_KEYS));
        patternField = new JTextField(28);
        addButton = new JButton(I18nUtils.get("droppack.button.add"));
        deleteButton = new JButton(I18nUtils.get("droppack.button.delete"));
        addPanel.add(actionCombo);
        addPanel.add(matchCombo);
        addPanel.add(patternField);
        addPanel.add(addButton);
        addPanel.add(deleteButton);
        panel.add(addPanel, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5)
                .setWeight(1, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.HORIZONTAL));

        // 规则表：启用 | 动作 | 匹配方式 | 规则内容 | 命中 | 备注
        tableModel = new DropPackTableModel();
        ruleTable = new JTable(tableModel);
        ruleTable.setRowHeight(22);
        // 备注列给足宽度，其余按内容自适应
        ruleTable.getColumnModel().getColumn(3).setPreferredWidth(260);
        ruleTable.getColumnModel().getColumn(5).setPreferredWidth(160);
        JScrollPane scrollPane = new JScrollPane(ruleTable);
        scrollPane.setPreferredSize(new Dimension(100, 220));
        panel.add(scrollPane, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5)
                .setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));

        JLabel tipLabel = new JLabel(I18nUtils.get("droppack.tip"));
        tipLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        panel.add(tipLabel, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(0, 8, 5, 5)
                .setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        // 双击"规则内容"列快速编辑，省去单独的编辑按钮
        ruleTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2 && ruleTable.getSelectedColumn() == 3) {
                    ruleTable.editCellAt(ruleTable.getSelectedRow(), 3);
                    patternFocus(ruleTable.getEditorComponent());
                }
            }
        });
    }

    /** 双击进入编辑后把焦点交给编辑器，可直接改字。 */
    private void patternFocus(Component editor) {
        if (editor instanceof JTextField) {
            JTextField field = (JTextField) editor;
            field.requestFocusInWindow();
            field.setCaretPosition(field.getDocument().getLength());
        }
    }

    /** 把 DropPackMatcher 当前状态回填到控件。 */
    private void loadState() {
        enableCheckBox.setSelected(DropPackMatcher.isEnabled());
        rules = DropPackDao.loadRules();
        tableModel.fireTableDataChanged();
        refreshCounts();
    }

    private void setupListeners() {
        enableCheckBox.addActionListener(e -> {
            DropPackMatcher.setEnabled(enableCheckBox.isSelected());
            DropPackDao.saveEnabled(enableCheckBox.isSelected());
        });
        addButton.addActionListener(e -> addRuleFromInput());
        deleteButton.addActionListener(e -> deleteSelectedRules());
    }

    /** 添加规则：校验非空与正则合法性，添加后立即落库并生效。 */
    private void addRuleFromInput() {
        String pattern = patternField.getText().trim();
        if (pattern.isEmpty()) {
            JOptionPane.showMessageDialog(panel, I18nUtils.get("droppack.error.empty_pattern"));
            return;
        }
        String matchType = MATCH_TYPES[matchCombo.getSelectedIndex()];
        if (DropPackRule.MATCH_REGEX.equals(matchType)) {
            try {
                Pattern.compile(pattern);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(panel,
                        I18nUtils.get("droppack.error.bad_regex") + e.getMessage());
                return;
            }
        }
        DropPackRule rule = new DropPackRule();
        rule.setId(nextRuleId());
        rule.setAction(ACTIONS[actionCombo.getSelectedIndex()]);
        rule.setMatchType(matchType);
        rule.setPattern(pattern);
        rules.add(rule);
        persist();
        tableModel.fireTableRowsInserted(rules.size() - 1, rules.size() - 1);
        patternField.setText("");
    }

    /** 删除选中行（支持多选），按行号倒序删避免索引位移。 */
    private void deleteSelectedRules() {
        int[] selectedRows = ruleTable.getSelectedRows();
        if (selectedRows.length == 0) {
            return;
        }
        for (int i = selectedRows.length - 1; i >= 0; i--) {
            rules.remove(selectedRows[i]);
        }
        persist();
        tableModel.fireTableDataChanged();
    }

    /** 规则列表落库并重建匹配快照（EDT 调用）。 */
    private void persist() {
        DropPackDao.saveRules(rules);
        DropPackMatcher.rebuild(rules);
    }

    /** 从库重载规则（右键菜单改动后的同步入口）。 */
    private void reloadFromDao() {
        rules = DropPackDao.loadRules();
        enableCheckBox.setSelected(DropPackMatcher.isEnabled());
        tableModel.fireTableDataChanged();
        refreshCounts();
    }

    /** 新规则 id 取现有最大 id + 1，保证命中计数跨保存稳定。 */
    private long nextRuleId() {
        long max = 0;
        for (DropPackRule rule : rules) {
            if (rule.getId() > max) {
                max = rule.getId();
            }
        }
        return max + 1;
    }

    /** 刷新命中计数列与总计数标签（EDT，Timer 回调）。 */
    private void refreshCounts() {
        totalLabel.setText(I18nUtils.format("droppack.label.total",
                DropPackMatcher.getTotalDropped(), DropPackMatcher.getTotalForwarded()));
        for (int row = 0; row < rules.size(); row++) {
            tableModel.fireTableCellUpdated(row, 4);
        }
    }

    private static String[] displayNames(String[] keys) {
        String[] names = new String[keys.length];
        for (int i = 0; i < keys.length; i++) {
            names[i] = I18nUtils.get(keys[i]);
        }
        return names;
    }

    /** DropPack 规则表格模型：启用/动作/匹配方式/规则内容/命中/备注六列，启用与备注列可编辑。 */
    private static class DropPackTableModel extends AbstractTableModel {
        private static final String[] COLUMN_KEYS = {"droppack.column.enabled", "droppack.column.action",
                "droppack.column.match", "droppack.column.pattern", "droppack.column.hits",
                "droppack.column.comment"};

        @Override
        public int getRowCount() {
            DropUI ui = instance;
            return ui == null ? 0 : ui.rules.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMN_KEYS.length;
        }

        @Override
        public String getColumnName(int column) {
            return I18nUtils.get(COLUMN_KEYS[column]);
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 0) {
                return Boolean.class;
            }
            if (columnIndex == 4) {
                return Long.class;
            }
            return String.class;
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            // 启用开关即时生效；备注可随手记录，其余列走添加区维护
            return columnIndex == 0 || columnIndex == 5;
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            DropPackRule rule = instance.rules.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return rule.isEnabled();
                case 1:
                    return actionDisplay(rule.getAction());
                case 2:
                    return matchDisplay(rule.getMatchType());
                case 3:
                    return rule.getPattern();
                case 4:
                    return DropPackMatcher.getHitCount(rule.getId());
                case 5:
                    return rule.getComment();
                default:
                    return "";
            }
        }

        @Override
        public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
            DropUI ui = instance;
            if (ui == null || rowIndex >= ui.rules.size()) {
                return;
            }
            DropPackRule rule = ui.rules.get(rowIndex);
            if (columnIndex == 0) {
                rule.setEnabled(Boolean.TRUE.equals(aValue));
            } else if (columnIndex == 5) {
                rule.setComment(aValue == null ? "" : aValue.toString());
            } else {
                return;
            }
            ui.persist();
        }

        private static String actionDisplay(String action) {
            return DropPackRule.ACTION_FORWARD.equals(action)
                    ? I18nUtils.get(ACTION_KEYS[1]) : I18nUtils.get(ACTION_KEYS[0]);
        }

        private static String matchDisplay(String matchType) {
            for (int i = 0; i < MATCH_TYPES.length; i++) {
                if (MATCH_TYPES[i].equals(matchType)) {
                    return I18nUtils.get(MATCH_KEYS[i]);
                }
            }
            return matchType;
        }
    }
}
