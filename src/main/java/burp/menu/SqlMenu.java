package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.PermUI;
import burp.ui.SqlUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class SqlMenu extends JMenuItem {
    public SqlMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ SQLi Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new SqlUI().CheckSQLi(responses);
                    }
                });
                thread.start();

            }
        });
    }
}
