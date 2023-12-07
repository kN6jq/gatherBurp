package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.AuthUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class AuthMenu extends JMenuItem {
    public AuthMenu(IHttpRequestResponse[] requestResponses) {
        this.setText("^_^ AuthBypass Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        AuthUI.Check(requestResponses);
                    }
                });
                thread.start();

            }
        });
    }
}
