package burp.menu;

import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.utils.Utils;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * 文本处理菜单
 * 提供各种文本转换功能
 */
public class TextProcessMenu extends JMenu {
    private final IContextMenuInvocation invocation;
    private final Random random = new Random();
    private final SecureRandom secureRandom = new SecureRandom();

    public TextProcessMenu(IContextMenuInvocation invocation) {
        super("Helper");
        this.invocation = invocation;
        initMenu();
    }

    /**
     * 初始化菜单项
     */
    private void initMenu() {
        // Unicode解码菜单项
        JMenuItem unicodeDecode = new JMenuItem("Unicode Decode");
        unicodeDecode.addActionListener(e -> processSelectedText(this::unicodeDecode));

        // URL解码菜单项
        JMenuItem urlDecode = new JMenuItem("URL Decode");
        urlDecode.addActionListener(e -> processSelectedText(this::urlDecode));

        // 关键字拆分菜单项
        JMenuItem splitKeyword = new JMenuItem("Split Keyword");
        splitKeyword.addActionListener(e -> processSelectedText(this::splitKeyword));

        // 随机大小写菜单项
        JMenuItem randomCase = new JMenuItem("Random Case");
        randomCase.addActionListener(e -> processSelectedText(this::randomCase));

        // 添加生成脏数据菜单项
        JMenuItem dirtyData = new JMenuItem("Generate Dirty Data");
        dirtyData.addActionListener(e -> dirtyGetRandomString());

        // 添加Base64数据标签菜单项
        JMenuItem base64Tag = new JMenuItem("Insert Base64 Tag");
        base64Tag.addActionListener(e -> checkBase64Data());

        add(unicodeDecode);
        add(urlDecode);
        add(splitKeyword);
        add(randomCase);
        add(dirtyData);
        add(base64Tag);
    }

    /**
     * 处理选中的文本
     */
    private void processSelectedText(TextProcessor processor) {
        try {
            // 获取选中的文本
            byte[] selectedText = invocation.getSelectedMessages()[0].getRequest();
            int[] bounds = invocation.getSelectionBounds();

            if (bounds == null || bounds[0] == bounds[1]) {
                JOptionPane.showMessageDialog(null, "Please select text first!");
                return;
            }

            // 提取选中的文本部分
            String fullText = new String(selectedText);
            String selected = fullText.substring(bounds[0], bounds[1]);
            String processed = processor.process(selected);

            // 构建新的请求
            String newText = fullText.substring(0, bounds[0]) + processed + fullText.substring(bounds[1]);

            // 更新请求
            invocation.getSelectedMessages()[0].setRequest(newText.getBytes());

        } catch (Exception ex) {
            Utils.stderr.println("Error processing text: " + ex.getMessage());
            JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage());
        }
    }

    /**
     * URL解码并在弹出框中显示结果
     */
    private String urlDecode(String text) {
        try {
            // URL解码，使用UTF-8编码支持中文
            String decoded = URLDecoder.decode(text, StandardCharsets.UTF_8.name());

            // 创建一个可复制的文本区域
            JTextArea textArea = new JTextArea(decoded);
            textArea.setEditable(false);
            textArea.setWrapStyleWord(true);
            textArea.setLineWrap(true);

            // 创建滚动面板
            JScrollPane scrollPane = new JScrollPane(textArea);
            scrollPane.setPreferredSize(new Dimension(400, 300));

            // 显示对话框
            JOptionPane.showMessageDialog(
                    null,
                    scrollPane,
                    "URL Decode Result",
                    JOptionPane.INFORMATION_MESSAGE
            );

            // 返回原文本，不修改原内容
            return text;
        } catch (Exception e) {
            Utils.stderr.println("Error decoding URL: " + e.getMessage());
            JOptionPane.showMessageDialog(null, "Error decoding URL: " + e.getMessage());
            return text;
        }
    }

    /**
     * Unicode解码并在弹出框中显示结果
     */
    private String unicodeDecode(String text) {
        StringBuilder result = new StringBuilder();
        int i = 0;
        while (i < text.length()) {
            if (text.startsWith("\\u", i) && i + 6 <= text.length()) {
                String hex = text.substring(i + 2, i + 6);
                try {
                    result.append((char) Integer.parseInt(hex, 16));
                    i += 6;
                    continue;
                } catch (NumberFormatException ignored) {
                }
            }
            result.append(text.charAt(i));
            i++;
        }

        // 创建一个可复制的文本区域
        JTextArea textArea = new JTextArea(result.toString());
        textArea.setEditable(false);
        textArea.setWrapStyleWord(true);
        textArea.setLineWrap(true);

        // 创建滚动面板
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(400, 300));

        // 显示对话框
        JOptionPane.showMessageDialog(
                null,
                scrollPane,
                "Unicode Decode Result",
                JOptionPane.INFORMATION_MESSAGE
        );

        // 返回原文本，不修改原内容
        return text;
    }

    /**
     * 关键字拆分
     */
    private String splitKeyword(String text) {
        StringBuilder result = new StringBuilder();
        int chunkSize = 2;  // 每段的默认长度

        for (int i = 0; i < text.length(); i += chunkSize) {
            if (i > 0) {
                result.append("+");
            }
            int end = Math.min(i + chunkSize, text.length());
            String chunk = text.substring(i, end);
            result.append("'").append(chunk).append("'");
        }

        return result.toString();
    }

    /**
     * 随机大小写转换
     */
    private String randomCase(String text) {
        return IntStream.range(0, text.length())
                .mapToObj(i -> {
                    char c = text.charAt(i);
                    return random.nextBoolean() ?
                            Character.toUpperCase(c) :
                            Character.toLowerCase(c);
                })
                .map(String::valueOf)
                .collect(Collectors.joining());
    }

    /**
     * 生成指定数量的随机字符
     */
    private String getRandomString(int number) {
        StringBuilder str = new StringBuilder("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < number; i++) {
            int index = secureRandom.nextInt(str.length());
            result.append(str.charAt(index));
        }
        return result.toString();
    }

    /**
     * 弹窗获取用户输入并生成脏数据
     */
    private void dirtyGetRandomString() {
        String s = JOptionPane.showInputDialog("Please Input Data Size(n*kb): ");
        if (s != null && !s.trim().isEmpty()) {
            try {
                int size = Integer.parseInt(s);
                String dirtyData = getRandomString(size * 1024);
                StringSelection stringSelection = new StringSelection(dirtyData);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(stringSelection, null);
                JOptionPane.showMessageDialog(null, "请在需要的位置粘贴", "Tips", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(null, "Please input a valid number", "Error", JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(null, "Please Input Data Size", "Tips", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /**
     * 插入Base64数据标签
     */
    private void checkBase64Data() {
        StringSelection stringSelection = new StringSelection("<datab64></datab64>");
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        JOptionPane.showMessageDialog(null, "请在需要的位置粘贴", "Tips", JOptionPane.INFORMATION_MESSAGE);
    }

    /**
     * 文本处理接口
     */
    @FunctionalInterface
    private interface TextProcessor {
        String process(String text);
    }
}