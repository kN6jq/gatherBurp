package burp.menu;

import burp.IHttpRequestResponse;
import burp.utils.ScanTaskExecutor;
import javax.swing.*;

public abstract class AbstractScanMenu extends JMenuItem {
    protected final IHttpRequestResponse[] requestResponses;

    public AbstractScanMenu(String name, IHttpRequestResponse[] requestResponses) {
        super(name);
        this.requestResponses = requestResponses;
        this.addActionListener(e -> ScanTaskExecutor.execute(
                getScanName() + " manual scan", this::doScan));
    }

    protected abstract void doScan();

    protected String getScanName() {
        return getClass().getSimpleName().replace("Menu", "");
    }
}
