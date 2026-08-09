package burp.menu;

import burp.IHttpRequestResponse;
import burp.utils.Nuclei;
import burp.utils.Utils;

import javax.swing.*;

public class NucleiMenu extends JMenuItem {
    public NucleiMenu(IHttpRequestResponse[] requestResponses) {
        super("^_^ Nuclei Template");
        addActionListener(e -> new Thread(() -> {
            try {
                Nuclei.Generate(requestResponses);
            } catch (Exception ex) {
                Utils.stderr.println("Nuclei template generation error: " + ex.getMessage());
            }
        }).start());
    }
}
