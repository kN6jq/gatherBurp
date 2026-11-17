package burp.dao;

import burp.bean.ConfigBean;
import burp.bean.DropPackRule;
import burp.utils.Utils;
import com.alibaba.fastjson.JSON;

import java.util.ArrayList;
import java.util.List;

/**
 * DropPack 丢弃规则数据访问：规则整体序列化为 JSON 存 config 表（module='droppack'，
 * type='rules'），启用开关存 type='enabled'。config 表 (module, type) 唯一，规则列表
 * 无法按行拆分存储，故整体一行 JSON（与 SocksUI 代理池的存储方式一致）。
 *
 * <p>异常统一打 stderr 并降级：读返回空列表/false，写静默失败。</p>
 */
public class DropPackDao {
    private static final String MODULE = "droppack";
    private static final String TYPE_RULES = "rules";
    private static final String TYPE_ENABLED = "enabled";

    /** 查询：读取全部丢弃规则。无记录或 JSON 解析失败返回空列表。 */
    public static List<DropPackRule> loadRules() {
        List<DropPackRule> rules = new ArrayList<>();
        try {
            ConfigBean config = ConfigDao.getConfig(MODULE, TYPE_RULES);
            String value = config.getValue();
            if (value != null && !value.trim().isEmpty()) {
                List<DropPackRule> parsed = JSON.parseArray(value, DropPackRule.class);
                if (parsed != null) {
                    rules.addAll(parsed);
                }
            }
        } catch (Exception e) {
            Utils.stderr.println("DropPack load rules failed: " + e.getMessage());
        }
        return rules;
    }

    /** 写入：规则列表整体覆盖存储（JSON 全量替换，非增量更新）。 */
    public static void saveRules(List<DropPackRule> rules) {
        try {
            ConfigBean config = new ConfigBean();
            config.setModule(MODULE);
            config.setType(TYPE_RULES);
            config.setValue(JSON.toJSONString(rules));
            ConfigDao.saveConfig(config);
        } catch (Exception e) {
            Utils.stderr.println("DropPack save rules failed: " + e.getMessage());
        }
    }

    /** 查询：读取模块总开关。无记录时默认关闭。 */
    public static boolean isEnabled() {
        try {
            ConfigBean config = ConfigDao.getConfig(MODULE, TYPE_ENABLED);
            return "true".equalsIgnoreCase(config.getValue());
        } catch (Exception e) {
            Utils.stderr.println("DropPack load enabled failed: " + e.getMessage());
            return false;
        }
    }

    /** 写入：模块总开关。 */
    public static void saveEnabled(boolean enabled) {
        try {
            ConfigBean config = new ConfigBean();
            config.setModule(MODULE);
            config.setType(TYPE_ENABLED);
            config.setValue(String.valueOf(enabled));
            ConfigDao.saveConfig(config);
        } catch (Exception e) {
            Utils.stderr.println("DropPack save enabled failed: " + e.getMessage());
        }
    }
}
