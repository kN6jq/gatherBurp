package burp.menu;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionListener;
import java.security.SecureRandom;

/**
 * @Author Xm17
 * @Date 2024-05-29 22:27
 * 脏数据生成
 */
public class DirtyMenu extends JMenuItem {
    public DirtyMenu() {
        this.setText("^_^ Insert DirtyData");
        this.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        dirtyGetRandomString();
                    }
                });
                thread.start();

            }
        });
    }
    // 根据传入的参数,返回指定数量的随机字符
    public static String getRandomString(int number) {
        SecureRandom random = new SecureRandom();
        StringBuilder str = new StringBuilder("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < number; i++) {
            int index = random.nextInt(str.length());
            result.append(str.charAt(index));
        }
        return result.toString();
    }

    // 弹窗获取用户输入的多少字符
    public static void dirtyGetRandomString() {
        String s =  JOptionPane.showInputDialog("Please Input Data Size(n*kb): ");
        if (s != null) {
            int size = Integer.parseInt(s);
            String dirtyData = getRandomString(size*1024);
            StringSelection stringSelection = new StringSelection(dirtyData);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(null, "请在需要的位置粘贴", "Tips", JOptionPane.INFORMATION_MESSAGE);
        }else {
            JOptionPane.showMessageDialog(null, "Please Input Data Size", "Tips", JOptionPane.INFORMATION_MESSAGE);
        }
    }



}
