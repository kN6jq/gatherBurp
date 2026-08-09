package burp.menu;

import burp.IHttpRequestResponse;
import burp.ui.FastjsonUI;

import javax.swing.*;

public abstract class FastjsonMenu extends AbstractScanMenu {
    private FastjsonMenu(IHttpRequestResponse[] requestResponses, String name) {
        super(name, requestResponses);
    }

    public static JMenuItem FastjsonDnslogMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson Dnslog Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckDnslog(requestResponses);
            }
        };
    }

    public static JMenuItem FastjsonEchoMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson Echo Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckEchoVul(requestResponses);
            }
        };
    }

    public static JMenuItem FastjsonJNDIMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson JNDI Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckJNDIVul(requestResponses);
            }
        };
    }

    public static JMenuItem FastjsonVersionMenu(IHttpRequestResponse[] responses) {
        return new FastjsonMenu(responses, "^_^ FastJson Version Check") {
            @Override
            protected void doScan() {
                FastjsonUI.CheckVersion(requestResponses);
            }
        };
    }
}
