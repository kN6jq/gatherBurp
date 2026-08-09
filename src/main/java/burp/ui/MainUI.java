package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;


public class MainUI extends JPanel implements ITab {
    private static JTabbedPane mainPanel;
    IBurpExtenderCallbacks callbacks;
    public static Map<String, Boolean> moduleStatus;

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
                UIHandler uiHandler = supplier.get();
                uiHandler.init();
                mainPanel.add(uiHandler.getTabName(), uiHandler.getPanel(callbacks));
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
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

