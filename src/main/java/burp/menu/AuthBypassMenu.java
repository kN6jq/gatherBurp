package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.AuthUI;
import burp.ui.FastJsonUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class AuthBypassMenu extends JMenuItem {
    public AuthBypassMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ AuthBypass Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new AuthUI().CheckAuthBypass(responses);
                    }
                });
                thread.start();

            }
        });
    }
}
