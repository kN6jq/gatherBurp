package burp.ui;

import burp.IBurpExtenderCallbacks;

import javax.swing.*;

public interface UIHandler {
    void init();

    JPanel getPanel(IBurpExtenderCallbacks callbacks);

    String getTabName();
}
