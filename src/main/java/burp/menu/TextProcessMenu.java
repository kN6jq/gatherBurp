package burp.menu;

import burp.IContextMenuInvocation;
import burp.utils.I18nUtils;
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
 * 文本处理菜单（"工具"菜单）：对消息编辑器中选中文本提供解码/转换/脏数据生成，
 * 结果经弹窗展示或写入剪贴板；全部交互在 EDT 完成。
 */
public class TextProcessMenu extends JMenu {
    private final IContextMenuInvocation invocation;
    private final Random random = new Random();
    private final SecureRandom secureRandom = new SecureRandom();

    public TextProcessMenu(IContextMenuInvocation invocation) {
        super(I18nUtils.get("common.menu.helper"));
        this.invocation = invocation;
        initMenu();
    }

    /** 构建全部文本处理菜单项（EDT）。 */
    private void initMenu() {
        // Unicode解码菜单项
        JMenuItem unicodeDecode = new JMenuItem(I18nUtils.get("textprocess.menu.unicode_decode"));
        unicodeDecode.addActionListener(e -> processSelectedText(this::unicodeDecode));

        // URL解码菜单项
        JMenuItem urlDecode = new JMenuItem(I18nUtils.get("textprocess.menu.url_decode"));
        urlDecode.addActionListener(e -> processSelectedText(this::urlDecode));

        // 关键字拆分菜单项
        JMenuItem splitKeyword = new JMenuItem(I18nUtils.get("textprocess.menu.split_keyword"));
        splitKeyword.addActionListener(e -> processSelectedText(this::splitKeyword));

        // 随机大小写菜单项
        JMenuItem randomCase = new JMenuItem(I18nUtils.get("textprocess.menu.random_case"));
        randomCase.addActionListener(e -> processSelectedText(this::randomCase));

        // 添加生成脏数据菜单项
        JMenuItem dirtyData = new JMenuItem(I18nUtils.get("textprocess.menu.dirty_data"));
        dirtyData.addActionListener(e -> dirtyGetRandomString());

        // 添加Base64数据标签菜单项
        JMenuItem base64Tag = new JMenuItem(I18nUtils.get("textprocess.menu.base64_tag"));
        base64Tag.addActionListener(e -> checkBase64Data());


        add(unicodeDecode);
        add(urlDecode);
        add(splitKeyword);
        add(randomCase);
        add(dirtyData);
        add(base64Tag);
    }

    /** 读取消息编辑器选中范围、执行给定转换并以弹窗展示结果（EDT）。 */
    private void processSelectedText(TextProcessor processor) {
        try {
            // 检查消息选择
            if (invocation.getSelectedMessages() == null || invocation.getSelectedMessages().length == 0) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.no_message"));
                return;
            }

            // 获取选择范围
            int[] bounds = invocation.getSelectionBounds();
            if (bounds == null || bounds[0] == bounds[1]) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.no_selection"));
                return;
            }

            // 获取当前选中的文本所在的字节数据
            byte[] contextBytes;
            int context = invocation.getInvocationContext();
            if (context == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST ||
                    context == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
                contextBytes = invocation.getSelectedMessages()[0].getRequest();
            } else {
                contextBytes = invocation.getSelectedMessages()[0].getResponse();
            }

            if (contextBytes == null) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.no_content"));
                return;
            }

            // 提取选中的文本部分
            String fullText = new String(contextBytes);
            String selected = fullText.substring(bounds[0], bounds[1]);

            // 处理选中的文本
            String processed = processor.process(selected);

            // 在弹窗中显示结果
            showProcessedResult(processed);

        } catch (Exception ex) {
            Utils.stderr.println("Error processing text: " + ex.getMessage());
            JOptionPane.showMessageDialog(null, String.format(I18nUtils.get("textprocess.message.error"), ex.getMessage()));
        }
    }

    /** 弹窗展示处理结果，附"复制"按钮（EDT）。 */
    private void showProcessedResult(String result) {
        // 创建一个可复制的文本区域
        JTextArea textArea = new JTextArea(result);
        textArea.setEditable(false);
        textArea.setWrapStyleWord(true);
        textArea.setLineWrap(true);

        // 创建滚动面板
        JScrollPane scrollPane = new JScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(400, 300));

        // 创建复制按钮
        JButton copyButton = new JButton(I18nUtils.get("textprocess.button.copy"));
        copyButton.addActionListener(e -> {
            StringSelection stringSelection = new StringSelection(result);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
            JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.copied"));
        });

        // 创建包含文本区域和按钮的面板
        JPanel panel = new JPanel(new BorderLayout());
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(copyButton, BorderLayout.SOUTH);

        // 显示对话框
        JOptionPane.showMessageDialog(
                null,
                panel,
                I18nUtils.get("textprocess.dialog.title"),
                JOptionPane.INFORMATION_MESSAGE
        );
    }

    /** URL 解码（UTF-8，支持中文百分号编码）；失败时弹窗提示并返回原文。 */
    private String urlDecode(String text) {
        try {
            // URL解码，使用UTF-8编码支持中文
            return URLDecoder.decode(text, StandardCharsets.UTF_8.name());
        } catch (Exception e) {
            Utils.stderr.println("Error decoding URL: " + e.getMessage());
            JOptionPane.showMessageDialog(null, String.format(I18nUtils.get("textprocess.message.url_decode_error"), e.getMessage()));
            return text;
        }
    }

    /** 解码 &#92;uXXXX 形式的 Unicode 转义序列为字符；非合法十六进制的片段原样保留。 */
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
        return result.toString();
    }

    /** 关键字拆分：按每段 2 字符切分并加引号、用 + 连接（如 select → 'se'+'le'+'ct'），用于绕过 WAF 关键字匹配。 */
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

    /** 逐字符随机大小写转换（绕过区分大小写的 WAF 关键字匹配）。 */
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

    /** 生成指定长度的随机字符串：字符集 0-9A-Za-z，使用 SecureRandom。 */
    private String getRandomString(int number) {
        StringBuilder str = new StringBuilder("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < number; i++) {
            int index = secureRandom.nextInt(str.length());
            result.append(str.charAt(index));
        }
        return result.toString();
    }

    /** 弹窗输入 KB 数，生成 数量×1024 的随机脏数据并复制进剪贴板（EDT）。 */
    private void dirtyGetRandomString() {
        String s = JOptionPane.showInputDialog(I18nUtils.get("textprocess.dialog.input_size"));
        if (s != null && !s.trim().isEmpty()) {
            try {
                int size = Integer.parseInt(s);
                String dirtyData = getRandomString(size * 1024);
                StringSelection stringSelection = new StringSelection(dirtyData);
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(stringSelection, null);
                JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.paste_here"), I18nUtils.get("textprocess.dialog.title"), JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.invalid_number"), I18nUtils.get("textprocess.dialog.title"), JOptionPane.ERROR_MESSAGE);
            }
        } else {
            JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.input_size"), I18nUtils.get("textprocess.dialog.title"), JOptionPane.INFORMATION_MESSAGE);
        }
    }

    /** 把 &lt;datab64&gt;&lt;/datab64&gt; 标签复制进剪贴板，供 Nuclei 模板内嵌 Base64 载荷使用（EDT）。 */
    private void checkBase64Data() {
        StringSelection stringSelection = new StringSelection("<datab64></datab64>");
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        clipboard.setContents(stringSelection, null);
        JOptionPane.showMessageDialog(null, I18nUtils.get("textprocess.message.paste_here"), I18nUtils.get("textprocess.dialog.title"), JOptionPane.INFORMATION_MESSAGE);
    }

    /** 单函数文本转换器。 */
    @FunctionalInterface
    private interface TextProcessor {
        String process(String text);
    }
}