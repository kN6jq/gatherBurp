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


    public MainUI(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        try {
            mainPanel = new JTabbedPane();
            for (int i = 0; i < init().size(); i++) {
                Class<?> clazz = Class.forName(init().get(i));
                UIHandler uiHandler = (UIHandler) clazz.newInstance();
                uiHandler.init();
                mainPanel.add(uiHandler.getTabName(), uiHandler.getPanel(callbacks));
            }
        }catch (Exception e ){
            Utils.stderr.println(e.getMessage());
        }
    }

    public static List<String> init() {
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

    @Override
    public String getTabCaption() {
        return Utils.name;
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

}