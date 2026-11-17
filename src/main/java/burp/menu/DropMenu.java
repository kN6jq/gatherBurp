package burp.menu;

import burp.IHttpRequestResponse;
import burp.bean.DropPackRule;
import burp.dao.DropPackDao;
import burp.ui.DropUI;
import burp.utils.DropPackMatcher;
import burp.utils.I18nUtils;
import burp.utils.Utils;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/** DropPack 丢弃右键菜单：把选中请求的 Host/URL 快速加为丢弃/放行规则，或撤销命中
 *  此包的规则。菜单在 EDT 构建与执行（仅读写规则配置，无网络请求），改动即落库并
 *  重建匹配快照，无需打开 DropPack 页签。 */
public class DropMenu extends JMenu {

    /** 构建菜单：无选中消息时不添加子项（父级 createMenuItems 已整体判空，此处兜底）。 */
    public DropMenu(IHttpRequestResponse[] requestResponses) {
        super(I18nUtils.get("droppack.menu.title"));
        if (requestResponses == null || requestResponses.length == 0 || requestResponses[0] == null
                || requestResponses[0].getHttpService() == null) {
            return;
        }
        IHttpRequestResponse message = requestResponses[0];
        String host = message.getHttpService().getHost();
        String url = extractUrl(message);

        add(item("droppack.menu.drop_host", new AddRuleAction(DropPackRule.ACTION_DROP,
                DropPackRule.MATCH_HOST, host)));
        add(item("droppack.menu.drop_url", new AddRuleAction(DropPackRule.ACTION_DROP,
                DropPackRule.MATCH_URL, url)));
        add(item("droppack.menu.drop_keyword", new KeywordDropAction()));
        add(item("droppack.menu.forward_host", new AddRuleAction(DropPackRule.ACTION_FORWARD,
                DropPackRule.MATCH_HOST, host)));
        addSeparator();
        add(item("droppack.menu.cancel", new CancelRulesAction(host, url)));
    }

    /** 构建带 i18n 文案的菜单项。 */
    private JMenuItem item(String key, ActionListener action) {
        JMenuItem menuItem = new JMenuItem(I18nUtils.get(key));
        menuItem.addActionListener(action);
        return menuItem;
    }

    /** 从消息提取完整 URL，异常时降级为 host 拼接（菜单构建阶段不应打断右键）。 */
    private static String extractUrl(IHttpRequestResponse message) {
        try {
            return Utils.helpers.analyzeRequest(message).getUrl().toString();
        } catch (Exception e) {
            return message.getHttpService().getHost();
        }
    }

    /** 加规则动作：同条件旧规则先删（避免重复叠加），再追加、落库、生效、刷新 UI。 */
    private static class AddRuleAction implements ActionListener {
        private final String action;
        private final String matchType;
        private final String pattern;

        AddRuleAction(String action, String matchType, String pattern) {
            this.action = action;
            this.matchType = matchType;
            this.pattern = pattern;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            addRule(action, matchType, pattern);
        }
    }

    /** 关键字丢弃动作：弹框输入关键字后按 keyword 方式加丢弃规则。 */
    private static class KeywordDropAction implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            String keyword = JOptionPane.showInputDialog(I18nUtils.get("droppack.dialog.keyword"));
            if (keyword == null) {
                return;
            }
            addRule(DropPackRule.ACTION_DROP, DropPackRule.MATCH_KEYWORD, keyword.trim());
        }
    }

    /** 撤销规则动作：删除条件命中当前 host/url 的全部规则（含未启用的），加错规则一键撤销。 */
    private static class CancelRulesAction implements ActionListener {
        private final String host;
        private final String url;

        CancelRulesAction(String host, String url) {
            this.host = host;
            this.url = url;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            List<DropPackRule> rules = DropPackDao.loadRules();
            List<DropPackRule> keep = new ArrayList<>();
            int removed = 0;
            for (DropPackRule rule : rules) {
                if (DropPackMatcher.matchesRule(rule, host, url)) {
                    removed++;
                } else {
                    keep.add(rule);
                }
            }
            if (removed == 0) {
                return;
            }
            DropPackDao.saveRules(keep);
            DropPackMatcher.rebuild(keep);
            Utils.stdout.println(I18nUtils.format("droppack.log.removed", removed));
            DropUI.reloadAndRefresh();
        }
    }

    /** 追加规则并整体落库 + 重建快照 + 刷新面板（若已打开）。 */
    private static void addRule(String action, String matchType, String pattern) {
        if (pattern == null || pattern.trim().isEmpty()) {
            return;
        }
        List<DropPackRule> rules = DropPackDao.loadRules();
        // 同条件（动作+匹配方式+匹配串）旧规则先删，重复右键不叠加重复行
        List<DropPackRule> cleaned = new ArrayList<>();
        for (DropPackRule rule : rules) {
            boolean duplicate = action.equals(rule.getAction())
                    && matchType.equals(rule.getMatchType())
                    && pattern.equals(rule.getPattern());
            if (!duplicate) {
                cleaned.add(rule);
            }
        }
        DropPackRule rule = new DropPackRule();
        rule.setId(nextRuleId(cleaned));
        rule.setAction(action);
        rule.setMatchType(matchType);
        rule.setPattern(pattern.trim());
        cleaned.add(rule);
        DropPackDao.saveRules(cleaned);
        DropPackMatcher.rebuild(cleaned);
        Utils.stdout.println(I18nUtils.format("droppack.log.added", pattern.trim()));
        DropUI.reloadAndRefresh();
    }

    /** 新规则 id 取现有最大 id + 1，与 DropUI 的编号规则保持一致。 */
    private static long nextRuleId(List<DropPackRule> rules) {
        long max = 0;
        for (DropPackRule rule : rules) {
            if (rule.getId() > max) {
                max = rule.getId();
            }
        }
        return max + 1;
    }
}
