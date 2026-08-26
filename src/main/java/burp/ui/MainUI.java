package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;


public class MainUI extends JPanel implements ITab {
    private static JTabbedPane mainPanel;
    IBurpExtenderCallbacks callbacks;

    private static final List<Supplier<UIHandler>> UI_SUPPLIERS = Arrays.asList(
        AuthUI::new,
        SqlUI::new,
        PermUI::new,
        FastjsonUI::new,
        Log4jUI::new,
        RouteUI::new,
        SocksUI::new,
        UrlRedirectUI::new,
        SimilarUI::new,
        ConfigUI::new
    );

    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        try {
            mainPanel = new JTabbedPane();
            for (Supplier<UIHandler> supplier : UI_SUPPLIERS) {
                try {
                    UIHandler uiHandler = supplier.get();
                    uiHandler.init();
                    mainPanel.add(uiHandler.getTabName(), uiHandler.getPanel(callbacks));
                } catch (Exception e) {
                    Utils.stderr.println("Module init failed: " + e.getMessage());
                    e.printStackTrace(Utils.stderr);
                }
            }
            // Burp 2024.x 切换扩展主标签后，子面板的第一次布局可能发生在
            // JSplitPane 比例位置初始化之前。下一轮 EDT 重新应用各面板的比例。
            mainPanel.addChangeListener(e -> {
                Component selected = mainPanel.getSelectedComponent();
                if (selected == null) {
                    return;
                }
                SwingUtilities.invokeLater(() -> {
                    AbstractScanUI.restoreInitialSplitLayout(selected);
                    selected.revalidate();
                    selected.repaint();
                });
            });
        } catch (Exception e) {
            Utils.stderr.println("MainUI init failed: " + e.getMessage());
            e.printStackTrace(Utils.stderr);
        }
    }

    @Override
    public String getTabCaption() {
        return Utils.NAME;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

}

