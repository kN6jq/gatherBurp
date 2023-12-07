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

public class Nuclei {
    private static final String Template_post = "id: #{[id]}\n" +
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
    public static String[] dslStr = {"contains(body_1, 'bingo')", "status_code_1 == 200 && !contains(body_3, 'bingo')", "regex('root:.*:0:0:', body)", "contains(body, 'bingo')", "contains(all_headers_1, 'text/html')"};
    private static String dsl;
    private static String severity;
    private static String name;
    private static String author;
    private static IRequestInfo analyzeRequest;
    private static IHttpRequestResponse baseRequestResponse;


    public static void Generate(IHttpRequestResponse[] iContextMenuInvocation) {
        baseRequestResponse = iContextMenuInvocation[0];
        analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);
        name = JOptionPane.showInputDialog(null, "请输入模板名称");
        author = JOptionPane.showInputDialog(null, "请输入作者名称");
        severity = JOptionPane.showInputDialog(null, "请选择漏洞等级", "选择框", JOptionPane.INFORMATION_MESSAGE, null, severitys, severitys[0]).toString();
        dsl = JOptionPane.showInputDialog(null, "请选择表达式demo", "选择框", JOptionPane.INFORMATION_MESSAGE, null, dslStr, dslStr[0]).toString();
        JOptionPane.showMessageDialog(null, "模板数据已复制到粘贴板,请自行更改其他参数");

        StringSelection template = new StringSelection(NucleiPost());
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(template, template);
    }

    public static String NucleiPost() {
        Map<String, Object> params = new HashMap<>();
        NucleiBean nuclei = new NucleiBean();
        nuclei.setId(Utils.getTimeNow());
        nuclei.setName(name);
        nuclei.setAuthor(author);
        nuclei.setSeverity(severity);
        nuclei.setReference("Reference");
        nuclei.setDescription("description");
        nuclei.setTags("tags");
        StringBuilder raw_post = new StringBuilder();
        List<String> headers = analyzeRequest.getHeaders();
        for (String header : headers) {
            if (!header.contains("Host")) {
                raw_post.append(header).append("\n        ");
            }
        }
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] byte_Request = baseRequestResponse.getRequest();

        String request = new String(byte_Request);
        String body = "        " + request.substring(bodyOffset);
        raw_post.append("\n").append(body.replace("\r\n", "\r\n        "));
        nuclei.setRaw(raw_post.toString());
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
        return parser.parseExpression(Template_post, parserContext).getValue(params, String.class);
    }

}
