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

    public static void Generate(IHttpRequestResponse[] iContextMenuInvocation) {
        IHttpRequestResponse baseRequestResponse = iContextMenuInvocation[0];
        IRequestInfo analyzeRequest = Utils.helpers.analyzeRequest(baseRequestResponse);

        String name = JOptionPane.showInputDialog(null, "请输入模板名称");
        String author = JOptionPane.showInputDialog(null, "请输入作者名称");
        String severity = (String) JOptionPane.showInputDialog(null, "请选择漏洞等级", "选择框",
                JOptionPane.INFORMATION_MESSAGE, null, severitys, severitys[0]);
        String dsl = (String) JOptionPane.showInputDialog(null, "请选择表达式demo", "选择框",
                JOptionPane.INFORMATION_MESSAGE, null, dslStr, dslStr[0]);

        String template = buildTemplate(name, author, severity, dsl, analyzeRequest, baseRequestResponse);

        StringSelection stringSelection = new StringSelection(template);
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(stringSelection, stringSelection);

        JOptionPane.showMessageDialog(null, "模板数据已复制到粘贴板,请自行更改其他参数");
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
            if (!header.contains("Host")) {
                rawPost.append(header).append("\n        ");
            }
        }
        int bodyOffset = analyzeRequest.getBodyOffset();
        byte[] byteRequest = baseRequestResponse.getRequest();
        String request = new String(byteRequest);
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
