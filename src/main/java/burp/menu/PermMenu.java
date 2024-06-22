package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.PermUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class PermMenu extends JMenuItem {
    public PermMenu(IHttpRequestResponse[] requestResponses) {
        this.setText("^_^ Perm Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        PermUI.Check(requestResponses,true);
                    }
                });
                thread.start();

            }
        });
    }
}
