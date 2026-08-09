package burp.menu;

import burp.IHttpRequestResponse;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.event.ActionEvent;

public abstract class AbstractScanMenu extends JMenuItem {
    protected final IHttpRequestResponse[] requestResponses;

    public AbstractScanMenu(String name, IHttpRequestResponse[] requestResponses) {
        super(name);
        this.requestResponses = requestResponses;
        this.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            doScan();
                        } catch (Exception ex) {
                            Utils.stderr.println(ex.getMessage());
                        }
                    }
                });
                thread.start();
            }
        });
    }

    /** Override to perform the actual scan logic. */
    protected abstract void doScan();
}
