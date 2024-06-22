package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.Log4jUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class Log4jMenu extends JMenuItem {
    public Log4jMenu(IHttpRequestResponse[] requestResponses) {
        this.setText("^_^ Log4j Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Log4jUI.Check(requestResponses,true);
                    }
                });
                thread.start();

            }
        });
    }
}
