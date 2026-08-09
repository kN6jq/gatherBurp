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
        this.addActionListener(e -> new Thread(() -> {
            try {
                doScan();
            } catch (Exception ex) {
                Utils.stderr.println(getScanName() + " scan error: " + ex.getMessage());
            }
        }).start());
    }

    protected abstract void doScan();

    protected String getScanName() {
        return getClass().getSimpleName().replace("Menu", "");
    }
}
