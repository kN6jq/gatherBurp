package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.AuthUI;
import burp.ui.RouteUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class RouteMenu extends JMenuItem {
    public RouteMenu(IHttpRequestResponse[] requestResponses) {
        this.setText("^_^ Route Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        RouteUI.Check(requestResponses,true);
                    }
                });
                thread.start();

            }
        });
    }
}
