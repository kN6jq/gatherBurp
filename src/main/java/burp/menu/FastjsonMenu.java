package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.FastjsonUI;

import javax.swing.*;
import java.awt.event.ActionListener;

public class FastjsonMenu extends JMenuItem {
    public JMenuItem FastjsonDnslogMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ FastJson Dnslog Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckDnslog(responses);
                    }
                });
                thread.start();

            }
        });
        return this;
    }

    public JMenuItem FastjsonEchoMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ FastJson Echo Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckEchoVul(responses);
                    }
                });
                thread.start();

            }
        });
        return this;
    }

    public JMenuItem FastjsonJNDIMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ FastJson JNDI Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckJNDIVul(responses);
                    }
                });
                thread.start();

            }
        });
        return this;
    }

    public JMenuItem FastjsonVersionMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ FastJson Version Check");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckVersion(responses);
                    }
                });
                thread.start();

            }
        });
        return this;
    }
}
