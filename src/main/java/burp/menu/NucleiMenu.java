package burp.menu;

import burp.IHttpRequestResponse;
import burp.utils.Nuclei;

import javax.swing.*;
import java.awt.event.ActionListener;

public class NucleiMenu extends JMenuItem {
    public NucleiMenu(IHttpRequestResponse[] requestResponses) {
        this.setText("^_^ Nuclei Template");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Nuclei.Generate(requestResponses);
                    }
                });
                thread.start();

            }
        });
    }
}
