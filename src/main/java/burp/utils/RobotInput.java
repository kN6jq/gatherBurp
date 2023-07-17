package burp.utils;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.awt.event.KeyEvent;

public class RobotInput extends Robot {
    public RobotInput() throws AWTException {
        super();
    }

    /*public static void startCmdConsole() {
        try {
            Process process = null;
            if (Commons.isWindows()) {
                process = Runtime.getRuntime().exec("cmd /c start cmd.exe");
            } else if (Commons.isMac()) {
                ///System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal
                process = Runtime.getRuntime().exec("open -n -F -a /System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal");
            } else if (Commons.isUnix()) {
                process = Runtime.getRuntime().exec("/usr/bin/gnome-terminal");//kali和Ubuntu测试通过
                //				if(new File("/usr/bin/gnome-terminal").exists()) {
                //					process = Runtime.getRuntime().exec("/usr/bin/gnome-terminal");
                //				}else {
                //					process = Runtime.getRuntime().exec("/usr/bin/xterm");//只能使用shift+insert 进行粘贴操作，但是修改剪切板并不能修改它粘贴的内容。
                //貌似和使用了openjdk有关，故暂时只支持gnome-terminal.
                //				}
            }
            process.waitFor();//等待执行完成
        } catch (Exception e) {
            e.printStackTrace();
        }
    }*/

    public void inputString(String str) {
        delay(100);
        Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();//获取剪切板
//        Transferable origin = clip.getContents(null);//备份之前剪切板的内容
        StringSelection tText = new StringSelection(str);
        clip.setContents(tText, tText); //设置剪切板内容,在Linux中这会修改ctrl+shift+v的内容

//        if (Commons.isWindows10()) {//粘贴的不同实现方式
//            inputWithCtrl(KeyEvent.VK_V);
//        } else if (Commons.isWindows()) {
//            inputWithAlt(KeyEvent.VK_SPACE);//
//            InputChar(KeyEvent.VK_E);
//            InputChar(KeyEvent.VK_P);
//
//        } else if (Commons.isMac()) {
//            delay(100);
//            keyPress(KeyEvent.VK_META);
//            keyPress(KeyEvent.VK_V);
//            delay(100);
//            keyRelease(KeyEvent.VK_V);
//            keyRelease(KeyEvent.VK_META);
//            delay(100);
//        } else if (Commons.isUnix()) {
//
//            inputWithCtrlAndShift(KeyEvent.VK_V);
//
//        }
//        clip.setContents(origin, null);//恢复之前剪切板的内容
        delay(100);
    }

    // shift+ 按键
    public void inputWithShift(int key) {
        delay(100);
        keyPress(KeyEvent.VK_SHIFT);
        keyPress(key);
        keyRelease(key);
        keyRelease(KeyEvent.VK_SHIFT);
        delay(100);
    }

    // ctrl+ 按键
    public void inputWithCtrl(int key) {
        delay(100);
        keyPress(KeyEvent.VK_CONTROL);
        keyPress(key);
        keyRelease(key);
        keyRelease(KeyEvent.VK_CONTROL);
        delay(100);
    }

    // alt+ 按键
    public void inputWithAlt(int key) {
        delay(100);
        keyPress(KeyEvent.VK_ALT);
        keyPress(key);
        keyRelease(key);
        keyRelease(KeyEvent.VK_ALT);
        delay(100);
    }

    // ctrl+shift+ 按键
    public void inputWithCtrlAndShift(int key) {
        delay(100);
        keyPress(KeyEvent.VK_CONTROL);
        keyPress(KeyEvent.VK_SHIFT);
        keyPress(key);
        keyRelease(key);
        keyRelease(KeyEvent.VK_SHIFT);
        keyRelease(KeyEvent.VK_CONTROL);
        delay(100);
    }

    //这个函数单独测试的时候没毛病，但是 一用到burp右键中，获得的结果始终是上一次复制的内容！
    public final String getSelectedString() {
        try {
            Clipboard clip = Toolkit.getDefaultToolkit().getSystemClipboard();//获取剪切板
            Transferable origin = clip.getContents(null);//备份之前剪切板的内容

            String selectedString = (String) clip.getData(DataFlavor.stringFlavor);
            System.out.println("复制之前剪切板中的内容：" + selectedString);

            inputWithCtrl(KeyEvent.VK_C);
            final String result = (String) clip.getData(DataFlavor.stringFlavor);
            //selectedString = (String)clip.getData(DataFlavor.stringFlavor);
            System.out.println("复制之后剪切板中的内容：" + result);

            clip.setContents(origin, null);//恢复之前剪切板的内容

            selectedString = (String) clip.getData(DataFlavor.stringFlavor);
            System.out.println("恢复之后剪切板中的内容：" + selectedString);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
        //		复制之前剪切板中的内容：printStackTrace
        //		复制之后剪切板中的内容：null
        //		恢复之后剪切板中的内容：printStackTrace
        //		printStackTrace//最后的值随着剪切板的恢复而改变了，应该是引用传递的原因。所有需要将复制后的值设置为final。
    }

    //单个 按键

    public void InputChar(int key) {
        delay(100);
        keyPress(key);
        keyRelease(key);
        delay(100);
    }
}
