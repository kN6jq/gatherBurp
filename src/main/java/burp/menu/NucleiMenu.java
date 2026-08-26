package burp.menu;

import burp.IHttpRequestResponse;
import burp.utils.Nuclei;
import burp.utils.ScanTaskExecutor;

import javax.swing.*;

public class NucleiMenu extends JMenuItem {
    public NucleiMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Nuclei Template");
        addActionListener(e -> ScanTaskExecutor.execute(
                "Nuclei template generation", () -> Nuclei.Generate(requestResponses)));
    }
}
