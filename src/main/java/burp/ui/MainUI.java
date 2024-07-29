package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class MainUI extends JPanel implements ITab {
    private static JTabbedPane mainPanel;
    IBurpExtenderCallbacks callbacks;

    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        try {
            mainPanel = new JTabbedPane();
            for (int i = 0; i < init().size(); i++) {
                try {
                    Class<?> clazz = Class.forName(init().get(i));
                    UIHandler ui = (UIHandler) clazz.newInstance();
                    ui.init();
                    mainPanel.addTab(ui.getTabName(), ui.getPanel(callbacks));
                } catch (Exception e) {
                    Utils.stderr.println(e.getMessage());
                }
            }
        } catch (Exception e) {
            Utils.stderr.println(e.getMessage());
        }
    }

    public List<String> init() {
        List<String> UiList = new ArrayList<String>();

        UiList.add("burp.ui.AuthUI");
        UiList.add("burp.ui.SqlUI");
        UiList.add("burp.ui.PermUI");
        UiList.add("burp.ui.FastjsonUI");
        UiList.add("burp.ui.Log4jUI");
        UiList.add("burp.ui.RouteUI");
        UiList.add("burp.ui.SocksUI");
        UiList.add("burp.ui.SimilarUI");
        UiList.add("burp.ui.ConfigUI");

        return UiList;
    }

    @Override
    public String getTabCaption() {
        return Utils.name;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
