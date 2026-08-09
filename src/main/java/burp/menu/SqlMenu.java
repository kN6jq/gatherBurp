package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.SqlUI;

public class SqlMenu extends AbstractScanMenu {
    public SqlMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Sql Check", requestResponses);
    }

    @Override
    protected void doScan() {
        SqlUI.Check(requestResponses, true);
    }
}
