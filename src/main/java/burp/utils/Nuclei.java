package burp.utils;

import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.bean.NucleiBean;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;

import javax.swing.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Nuclei 模板生成工具：把选中请求按 SpEL 模板渲染为 Nuclei 模板文本并复制进剪贴板。 */
public class Nuclei {
    /** Nuclei 模板骨架（SpEL 占位符 #{[xxx]} 由 SpelExpressionParser 渲染）。 */
    private static final String TemplatePost = "id: #{[id]}\n" +
            "\n" +
            "info:\n" +
            "  name: #{[name]}\n" +
            "  author: #{[author]}\n" +
            "  severity: #{[severity]}\n" +
            "  description: #{[description]}\n" +
            "  reference:\n" +
            "    - #{[reference]}\n" +
            "  tags: #{[tags]}\n" +
            "\n" +
            "requests:\n" +
            "  - raw:\n" +
            "      - |\n" +
            "        #{[raw]}\n" +
            "\n" +
            "    matchers:\n" +
            "      - type: dsl\n" +
            "        dsl:\n" +
            "          - \"#{[dsl]}\"\n";
    public static String[] severitys = {"critical", "high", "medium", "low", "info"};
    public static String[] dslStr = {"status_code == 200 && contains(body, 'bingo')", "status_code_1 == 200 && !contains(body_3, 'bingo')", "regex('root:.*:0:0:', body)", "contains(body, 'bingo')", "contains(all_headers_1, 'text/html')"};

    /** 模板生成入口（ScanTaskExecutor 池线程）：弹窗收集元数据后渲染模板写入剪贴板。 */
    public static void Generate(IHttpRequestResponse[] iContextMenuInvocation) {
        IHttpRequestResponse baseRequestResponse = iContextMenuInvocation[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);

        // 菜单扫描线程不是 EDT：对话框必须经 invokeAndWait 切回 EDT，
        // 直接弹 Swing 对话框属于线程违规（可能渲染异常或死锁）
        String name = showInputDialog(I18nUtils.get("nuclei.dialog.input_name"), null);
        if (name == null || name.trim().isEmpty()) {
            return;
        }
        String author = showInputDialog(I18nUtils.get("nuclei.dialog.input_author"), null);
        if (author == null || author.trim().isEmpty()) {
            return;
        }
        String severity = showComboBoxDialog(I18nUtils.get("nuclei.dialog.select_severity"), severitys, severitys[0]);
        if (severity == null) {
            return;
        }
        String dsl = showComboBoxDialog(I18nUtils.get("nuclei.dialog.select_dsl"), dslStr, dslStr[0]);
        if (dsl == null) {
            return;
        }

        String template = buildTemplate(name, author, severity, dsl, analyzeRequest, baseRequestResponse);

        StringSelection stringSelection = new StringSelection(template);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, stringSelection);

        showMessageDialog(I18nUtils.get("nuclei.message.copied"));
    }

    private static String showInputDialog(String message, Object initialValue) {
        final String[] result = new String[1];
        Runnable dialog = () -> result[0] = (String) JOptionPane.showInputDialog(
                null, message, I18nUtils.get("nuclei.dialog.select_box"),
                JOptionPane.PLAIN_MESSAGE, null, null, initialValue);
        return runOnEdt(dialog) ? result[0] : null;
    }

    private static String showComboBoxDialog(String message, Object[] options, Object initialValue) {
        final String[] result = new String[1];
        Runnable dialog = () -> result[0] = (String) JOptionPane.showInputDialog(
                null, message, I18nUtils.get("nuclei.dialog.select_box"),
                JOptionPane.INFORMATION_MESSAGE, null, options, initialValue);
        return runOnEdt(dialog) ? result[0] : null;
    }

    private static void showMessageDialog(String message) {
        Runnable dialog = () -> JOptionPane.showMessageDialog(null, message);
        runOnEdt(dialog);
    }

    private static boolean runOnEdt(Runnable dialog) {
        if (SwingUtilities.isEventDispatchThread()) {
            dialog.run();
            return true;
        }
        try {
            SwingUtilities.invokeAndWait(dialog);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        } catch (java.lang.reflect.InvocationTargetException e) {
            Utils.stderr.println("Nuclei dialog failed: " + e.getCause());
            return false;
        }
    }

    private static String buildTemplate(String name, String author, String severity, String dsl,
                                        IRequestInfo analyzeRequest, IHttpRequestResponse baseRequestResponse) {
        NucleiBean nuclei = new NucleiBean();
        nuclei.setId(name);
        nuclei.setName(name);
        nuclei.setAuthor(author);
        nuclei.setSeverity(severity);
        nuclei.setReference("Reference");
        nuclei.setDescription("description");
        nuclei.setTags("tags");

        StringBuilder rawPost = new StringBuilder();
        List<String> headers = analyzeRequest.getHeaders();
        for (String header : headers) {
            // 按 "Host:" 前缀精确排除；contains 会误删 X-Forwarded-Host、值里含 host 的 Cookie 等
            if (!header.regionMatches(true, 0, "Host:", 0, 5)) {
                rawPost.append(header).append("\n        ");
            }
        }
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] byteRequest = baseRequestResponse.getRequest();
        // 报文字节按 ISO-8859-1 保真解码，避免默认平台字符集破坏非 ASCII 字节
        String request = new String(byteRequest, java.nio.charset.StandardCharsets.ISO_8859_1);
        String body = "        " + request.substring(bodyOffset);
        rawPost.append("\n").append(body.replace("\r\n", "\r\n        "));
        nuclei.setRaw(rawPost.toString());

        Map<String, Object> params = new HashMap<>();
        params.put("id", nuclei.getId());
        params.put("name", nuclei.getName());
        params.put("author", nuclei.getAuthor());
        params.put("severity", nuclei.getSeverity());
        params.put("reference", nuclei.getReference());
        params.put("description", nuclei.getDescription());
        params.put("tags", nuclei.getTags());
        params.put("raw", nuclei.getRaw());
        params.put("dsl", dsl);

        ExpressionParser parser = new SpelExpressionParser();
        TemplateParserContext parserContext = new TemplateParserContext();
        return parser.parseExpression(TemplatePost, parserContext).getValue(params, String.class);
    }
}
