package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.AuthUI;
import burp.ui.PermUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class PermBypassMenu extends JMenuItem {
    public PermBypassMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ PermBypass Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new PermUI().CheckPermBypass(responses);
                    }
                });
                thread.start();

            }
        });
    }
}
