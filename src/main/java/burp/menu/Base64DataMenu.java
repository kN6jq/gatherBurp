package burp.menu;

import burp.IHttpRequestResponse;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

public class Base64DataMenu  extends JMenuItem {
    public Base64DataMenu() {
    }

    public Base64DataMenu(IHttpRequestResponse[] responses) {
        this.setText("^_^ Insert Base64 Data");
        this.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        new Base64DataMenu().CheckBase64Data(responses);
                    }
                });
                thread.start();

            }
        });
    }

    private void CheckBase64Data(IHttpRequestResponse[] responses) {
        StringSelection stringSelection = null;
        stringSelection = new StringSelection("<datab64></datab64>");
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        // 弹窗
        JOptionPane.showMessageDialog(null, "请在需要的位置粘贴", "Tips", JOptionPane.INFORMATION_MESSAGE);
    }

}
