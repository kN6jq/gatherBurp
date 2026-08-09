package burp.utils;

import burp.bean.ConfigBean;
import burp.dao.ConfigDao;

import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;

/**
 * 国际化工具类
 * 用于管理插件的中英文切换功能
 */
public class I18nUtils {
    public enum Language {
        ENGLISH("en"),
        CHINESE("zh");

        private final String code;

        Language(String code) {
            this.code = code;
        }

        public String getCode() {
            return code;
        }
    }

    private static Language currentLanguage = Language.ENGLISH;

    static {
        loadLanguageFromConfig();
    }

    private static void loadLanguageFromConfig() {
        try {
            ConfigBean config = ConfigDao.getConfig("config", "language");
            if (config != null && "zh".equals(config.getValue())) {
                currentLanguage = Language.CHINESE;
            }
        } catch (Exception e) {
            currentLanguage = Language.ENGLISH;
        }
    }

    public static Language getCurrentLanguage() {
        return currentLanguage;
    }

    public static void setLanguage(Language language) {
        currentLanguage = language;
    }

    public static String get(String key) {
        try {
            Locale locale = currentLanguage == Language.CHINESE ? Locale.CHINESE : Locale.ENGLISH;
            ResourceBundle bundle = ResourceBundle.getBundle("i18n.messages", locale);
            return bundle.getString(key);
        } catch (Exception e) {
            return key;
        }
    }

    public static void toggleLanguage() {
        currentLanguage = currentLanguage == Language.ENGLISH ? Language.CHINESE : Language.ENGLISH;
    }

    public static boolean isChinese() {
        return currentLanguage == Language.CHINESE;
    }

    public static void setChinese(boolean isChinese) {
        currentLanguage = isChinese ? Language.CHINESE : Language.ENGLISH;
    }
}
