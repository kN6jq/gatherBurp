package burp.ui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;

public interface UIHandler {

        public void init();
        public JPanel getPanel(IBurpExtenderCallbacks callbacks);
        public String getTabName();
}
