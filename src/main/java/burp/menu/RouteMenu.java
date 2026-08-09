package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.RouteUI;

public class RouteMenu extends AbstractScanMenu {
    public RouteMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Route Check", requestResponses);
    }

    @Override
    protected void doScan() {
        RouteUI.Check(requestResponses, true);
    }
}
