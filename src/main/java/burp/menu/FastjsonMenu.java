package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.FastjsonUI;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class FastjsonMenu {

    public static JMenuItem FastjsonDnslogMenu(IHttpRequestResponse[] responses) {
        JMenuItem item = new JMenuItem("^_^ FastJson Dnslog Check");
        item.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckDnslog(responses);
                    }
                });
                thread.start();
            }
        });
        return item;
    }

    public static JMenuItem FastjsonEchoMenu(IHttpRequestResponse[] responses) {
        JMenuItem item = new JMenuItem("^_^ FastJson Echo Check");
        item.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckEchoVul(responses);
                    }
                });
                thread.start();
            }
        });
        return item;
    }

    public static JMenuItem FastjsonJNDIMenu(IHttpRequestResponse[] responses) {
        JMenuItem item = new JMenuItem("^_^ FastJson JNDI Check");
        item.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckJNDIVul(responses);
                    }
                });
                thread.start();
            }
        });
        return item;
    }

    public static JMenuItem FastjsonVersionMenu(IHttpRequestResponse[] responses) {
        JMenuItem item = new JMenuItem("^_^ FastJson Version Check");
        item.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new FastjsonUI().CheckVersion(responses);
                    }
                });
                thread.start();
            }
        });
        return item;
    }
}
