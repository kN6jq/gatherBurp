package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.AuthUI;
import burp.ui.Log4jUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class Log4jCheckMenu extends JMenuItem {
    public Log4jCheckMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ Log4j Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new Log4jUI().CheckLog4j(responses);
                    }
                });
                thread.start();

            }
        });
    }
}
