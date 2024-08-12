package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class MainUI extends JPanel implements ITab {
    private static JTabbedPane mainPanel;
    IBurpExtenderCallbacks callbacks;
    public static Map<String, Boolean> moduleStatus;

    static {
        moduleStatus = new HashMap<>();
        List<String> uiList = initStatic();
        for (String uiClassName : uiList) {
            // Default value is true (enabled) for all modules
            moduleStatus.put(uiClassName, false);
        }
    }

    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        try {
            mainPanel = new JTabbedPane();
            JPanel modulePanel = new JPanel();
            modulePanel.setLayout(new BoxLayout(modulePanel, BoxLayout.Y_AXIS));

            JLabel tipsLabel = new JLabel("需要使用到dnslog的模块必须开启burp.ui.ConfigUI\n注意: 此处的模块卸载为伪卸载,请务必保证关闭被动扫描关闭");
            modulePanel.add(tipsLabel);

            List<JCheckBox> checkBoxes = new ArrayList<>();
            for (String uiClassName : init()) {
                JCheckBox checkBox = new JCheckBox(uiClassName, moduleStatus.get(uiClassName));
                checkBoxes.add(checkBox);
                modulePanel.add(checkBox);
            }

            JButton loadButton = new JButton("ReLoad Selected Modules");
            loadButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    loadModules(checkBoxes);
                    mainPanel.addTab("Modules", modulePanel); // Re-add modulePanel
                }
            });

            modulePanel.add(loadButton);
            mainPanel.addTab("Modules", modulePanel);
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    private static List<String> initStatic() {
        List<String> uiList = new ArrayList<>();
        uiList.add("burp.ui.AuthUI");
        uiList.add("burp.ui.SqlUI");
        uiList.add("burp.ui.PermUI");
        uiList.add("burp.ui.FastjsonUI");
        uiList.add("burp.ui.Log4jUI");
        uiList.add("burp.ui.RouteUI");
        uiList.add("burp.ui.SocksUI");
        uiList.add("burp.ui.SimilarUI");
        uiList.add("burp.ui.ConfigUI");
        return uiList;
    }

    private void loadModules(List<JCheckBox> checkBoxes) {
        // 重新加载模块
        for (JCheckBox checkBox : checkBoxes) {
            String className = checkBox.getText();
            if (checkBox.isSelected() && !moduleStatus.get(className)) {
                try {
                    Class<?> clazz = Class.forName(className);
                    UIHandler ui = (UIHandler) clazz.newInstance();
                    ui.init();
                    JPanel panel = ui.getPanel(callbacks);
                    String tabName = ui.getTabName();
                    mainPanel.addTab(tabName, panel);
                    moduleStatus.put(className, true);
                } catch (Exception e) {
                    Utils.stderr.println(e.getMessage());
                }
            }
        }
    }


    public List<String> init() {
        return initStatic();
    }

    @Override
    public String getTabCaption() {
        return Utils.name;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // Static method to get module status
    public static boolean isModuleEnabled(String moduleName) {
        return moduleStatus.getOrDefault(moduleName, false);
    }
}