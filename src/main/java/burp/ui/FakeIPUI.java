package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ui.SimilarHelper.ThreadManager;
import burp.ui.UIHelper.GridBagConstraintsHelper;
import burp.utils.FakeIPUtils;
import burp.utils.I18nUtils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** FakeIP 标签页：开关 / 应用范围 / 伪造 IP / 伪造头多选。改动即时生效并后台落库；
 *  enabled 不持久化，重启默认关，其余配置保留。 */
public class FakeIPUI implements UIHandler {
    private JPanel panel;
    private JCheckBox enableCheckBox;
    private final Map<String, JCheckBox> scopeCheckBoxes = new LinkedHashMap<>();
    private JRadioButton randomRadioButton;
    private JRadioButton localhostRadioButton;
    private JRadioButton customRadioButton;
    private JTextField customIpField;
    private final Map<String, JCheckBox> headerCheckBoxes = new LinkedHashMap<>();
    /** 构建/回填界面期间为 true，监听器不触发保存。 */
    private boolean building = true;

    @Override
    public String getTabName() {
        return I18nUtils.get("fakeip.tab.title");
    }

    @Override
    public void init() {
        FakeIPUtils.loadConfig();
        setupUI();
        loadState();
        setupListeners();
        building = false;
    }

    @Override
    public JPanel getPanel(IBurpExtenderCallbacks callbacks) {
        return panel;
    }

    private void setupUI() {
        panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        enableCheckBox = new JCheckBox(I18nUtils.get("fakeip.checkbox.enable"));
        panel.add(enableCheckBox, new GridBagConstraintsHelper(0, 0, 1, 1).setInsets(5)
                .setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        // 应用范围：一行工具勾选
        JPanel scopePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        scopePanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("fakeip.scope.border")));
        for (String toolName : FakeIPUtils.SCOPE_TOOLS.keySet()) {
            JCheckBox checkBox = new JCheckBox(toolName);
            scopeCheckBoxes.put(toolName, checkBox);
            scopePanel.add(checkBox);
        }
        panel.add(scopePanel, new GridBagConstraintsHelper(0, 1, 1, 1).setInsets(5)
                .setWeight(1, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.HORIZONTAL));

        // 伪造 IP：三选一 + 自定义输入
        JPanel ipPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        ipPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("fakeip.ip.border")));
        randomRadioButton = new JRadioButton(I18nUtils.get("fakeip.ip.random"));
        localhostRadioButton = new JRadioButton("127.0.0.1");
        customRadioButton = new JRadioButton(I18nUtils.get("fakeip.ip.custom"));
        ButtonGroup ipGroup = new ButtonGroup();
        ipGroup.add(randomRadioButton);
        ipGroup.add(localhostRadioButton);
        ipGroup.add(customRadioButton);
        customIpField = new JTextField(14);
        ipPanel.add(randomRadioButton);
        ipPanel.add(localhostRadioButton);
        ipPanel.add(customRadioButton);
        ipPanel.add(customIpField);
        panel.add(ipPanel, new GridBagConstraintsHelper(0, 2, 1, 1).setInsets(5)
                .setWeight(1, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.HORIZONTAL));

        // 伪造头：3 列网格多选，可滚动
        JPanel headersPanel = new JPanel(new BorderLayout());
        headersPanel.setBorder(BorderFactory.createTitledBorder(I18nUtils.get("fakeip.headers.border")));
        JPanel headerGrid = new JPanel(new GridLayout(0, 3, 5, 2));
        for (String header : FakeIPUtils.FAKE_IP_HEADERS) {
            JCheckBox checkBox = new JCheckBox(header);
            headerCheckBoxes.put(header, checkBox);
            headerGrid.add(checkBox);
        }
        JScrollPane scrollPane = new JScrollPane(headerGrid);
        scrollPane.setPreferredSize(new Dimension(100, 160));
        scrollPane.setBorder(BorderFactory.createEmptyBorder());
        headersPanel.add(scrollPane, BorderLayout.CENTER);
        panel.add(headersPanel, new GridBagConstraintsHelper(0, 3, 1, 1).setInsets(5)
                .setWeight(1, 1).setAnchor(GridBagConstraints.CENTER).setFill(GridBagConstraints.BOTH));

        // 头快捷按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JButton selectAllButton = new JButton(I18nUtils.get("fakeip.button.select_all"));
        JButton clearButton = new JButton(I18nUtils.get("fakeip.button.clear"));
        JButton resetButton = new JButton(I18nUtils.get("fakeip.button.reset_default"));
        buttonPanel.add(selectAllButton);
        buttonPanel.add(clearButton);
        buttonPanel.add(resetButton);
        panel.add(buttonPanel, new GridBagConstraintsHelper(0, 4, 1, 1).setInsets(0, 5, 5, 5)
                .setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        JLabel tipLabel = new JLabel(I18nUtils.get("fakeip.tip"));
        tipLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        panel.add(tipLabel, new GridBagConstraintsHelper(0, 5, 1, 1).setInsets(0, 8, 5, 5)
                .setWeight(0, 0).setAnchor(GridBagConstraints.WEST).setFill(GridBagConstraints.NONE));

        selectAllButton.addActionListener(e -> {
            setAllHeaderChecks(true);
            applyUiToState();
        });
        clearButton.addActionListener(e -> {
            setAllHeaderChecks(false);
            applyUiToState();
        });
        resetButton.addActionListener(e -> {
            resetToDefaults();
            applyUiToState();
        });
    }

    /** 把 FakeIPUtils 当前状态回填到控件。 */
    private void loadState() {
        enableCheckBox.setSelected(FakeIPUtils.isFakeIpEnabled());
        Set<String> scopeNames = FakeIPUtils.getScopeNames();
        for (Map.Entry<String, JCheckBox> entry : scopeCheckBoxes.entrySet()) {
            entry.getValue().setSelected(scopeNames.contains(entry.getKey().toLowerCase()));
        }
        String ipMode = FakeIPUtils.getIpMode();
        randomRadioButton.setSelected(FakeIPUtils.IP_MODE_RANDOM.equals(ipMode));
        localhostRadioButton.setSelected(FakeIPUtils.IP_MODE_LOCALHOST.equals(ipMode));
        customRadioButton.setSelected(FakeIPUtils.IP_MODE_CUSTOM.equals(ipMode));
        customIpField.setText(FakeIPUtils.getCustomIp());
        customIpField.setEnabled(customRadioButton.isSelected());
        Set<String> selected = FakeIPUtils.getSelectedHeaders();
        for (Map.Entry<String, JCheckBox> entry : headerCheckBoxes.entrySet()) {
            entry.getValue().setSelected(selected.contains(entry.getKey()));
        }
    }

    private void setupListeners() {
        enableCheckBox.addActionListener(e -> applyUiToState());
        for (JCheckBox checkBox : scopeCheckBoxes.values()) {
            checkBox.addActionListener(e -> applyUiToState());
        }
        randomRadioButton.addActionListener(e -> applyUiToState());
        localhostRadioButton.addActionListener(e -> applyUiToState());
        customRadioButton.addActionListener(e -> {
            customIpField.setEnabled(customRadioButton.isSelected());
            applyUiToState();
        });
        customIpField.addActionListener(e -> applyUiToState());
        for (JCheckBox checkBox : headerCheckBoxes.values()) {
            checkBox.addActionListener(e -> applyUiToState());
        }
    }

    /** 控件状态写回 FakeIPUtils 并后台落库。 */
    private void applyUiToState() {
        if (building) {
            return;
        }
        FakeIPUtils.setFakeIpEnabled(enableCheckBox.isSelected());

        Set<String> scopeNames = new LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> entry : scopeCheckBoxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                scopeNames.add(entry.getKey().toLowerCase());
            }
        }
        FakeIPUtils.setScopeNames(scopeNames);

        if (localhostRadioButton.isSelected()) {
            FakeIPUtils.setIpMode(FakeIPUtils.IP_MODE_LOCALHOST);
        } else if (customRadioButton.isSelected()) {
            FakeIPUtils.setIpMode(FakeIPUtils.IP_MODE_CUSTOM);
        } else {
            FakeIPUtils.setIpMode(FakeIPUtils.IP_MODE_RANDOM);
        }
        FakeIPUtils.setCustomIp(customIpField.getText());

        Set<String> headers = new LinkedHashSet<>();
        for (Map.Entry<String, JCheckBox> entry : headerCheckBoxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                headers.add(entry.getKey());
            }
        }
        FakeIPUtils.setSelectedHeaders(headers);

        ThreadManager.execute(FakeIPUtils::saveConfig);
    }

    private void setAllHeaderChecks(boolean selected) {
        for (JCheckBox checkBox : headerCheckBoxes.values()) {
            checkBox.setSelected(selected);
        }
    }

    /** 恢复默认：范围 proxy+repeater、随机 IP、头 X-Forwarded-For/X-Real-IP（不改启用开关）。 */
    private void resetToDefaults() {
        List<String> defaultScope = new ArrayList<>(Arrays.asList("proxy", "repeater"));
        for (Map.Entry<String, JCheckBox> entry : scopeCheckBoxes.entrySet()) {
            entry.getValue().setSelected(defaultScope.contains(entry.getKey().toLowerCase()));
        }
        randomRadioButton.setSelected(true);
        customIpField.setText("");
        customIpField.setEnabled(false);
        for (Map.Entry<String, JCheckBox> entry : headerCheckBoxes.entrySet()) {
            entry.getValue().setSelected("X-Forwarded-For".equals(entry.getKey())
                    || "X-Real-IP".equals(entry.getKey()));
        }
    }
}
