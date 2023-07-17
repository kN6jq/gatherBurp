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
    public MainUI(IBurpExtenderCallbacks callbacks) {
        try {
            InitUi(callbacks);
        }catch (Exception e){
            e.printStackTrace();
        }
    }
    public List<String> init(){
        List<String> UiList = new ArrayList<String>();

        UiList.add("burp.ui.FastJsonUI");
        UiList.add("burp.ui.AuthUI");
        UiList.add("burp.ui.PermUI");
        UiList.add("burp.ui.SqlUI");
        UiList.add("burp.ui.ConfigUI");
        return UiList;
    }

    private void InitUi(IBurpExtenderCallbacks callbacks) {
        mainPanel = new JTabbedPane();
        for (int i = 0; i < init().size(); i++) {
            try {
                Class<?> clazz = Class.forName(init().get(i));
                UIHandler ui = (UIHandler) clazz.newInstance();
                mainPanel.addTab(ui.getTabName(), ui.getPanel(callbacks));
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
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
