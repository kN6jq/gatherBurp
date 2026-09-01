package burp.utils;

import burp.bean.ConfigBean;
import burp.dao.ConfigDao;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URL;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

/**
 * 国际化工具类：管理插件中英文切换。资源为 UTF-8 properties（messages_zh/messages_en），
 * 当前语言持久化在 config 表；get(key) 未命中时回退 key 本身。
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

    /** UTF-8 properties ResourceBundle 控制：解决 Java 默认 ISO-8859-1 读取 properties 的中文乱码问题。 */
    private static final ResourceBundle.Control UTF8_CONTROL = new ResourceBundle.Control() {
        @Override
        public ResourceBundle newBundle(String baseName, Locale locale, String format,
                                        ClassLoader loader, boolean reload)
                throws IllegalAccessException, InstantiationException, IOException {
            String bundleName = toBundleName(baseName, locale);
            String resourceName = toResourceName(bundleName, "properties");
            InputStream stream;
            if (reload) {
                URL resource = loader.getResource(resourceName);
                if (resource == null) {
                    return null;
                }
                stream = resource.openConnection().getInputStream();
            } else {
                stream = loader.getResourceAsStream(resourceName);
            }
            if (stream == null) {
                return null;
            }
            try (Reader reader = new InputStreamReader(stream, "UTF-8")) {
                return new PropertyResourceBundle(reader);
            }
        }
    };

    static {
        loadLanguageFromConfig();
    }

    /** 从 config 表加载持久化的语言设置，失败默认英文。 */
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

    /** 返回当前语言。 */
    public static Language getCurrentLanguage() {
        return currentLanguage;
    }

    /** 设置当前语言（内存态，不持久化）。 */
    public static void setLanguage(Language language) {
        currentLanguage = language;
    }

    /** 按 key 获取当前语言对应的资源串；未命中回退 key 本身。 */
    public static String get(String key) {
        try {
            Locale locale = currentLanguage == Language.CHINESE ? Locale.CHINESE : Locale.ENGLISH;
            ResourceBundle bundle = ResourceBundle.getBundle("i18n.messages", locale, UTF8_CONTROL);
            return bundle.getString(key);
        } catch (Exception e) {
            return key;
        }
    }

    /**
     * 格式化带 {0} {1} 占位的本地化消息。
     */
    public static String format(String key, Object... arguments) {
        Locale locale = currentLanguage == Language.CHINESE ? Locale.CHINESE : Locale.ENGLISH;
        return new MessageFormat(get(key), locale).format(arguments == null ? new Object[0] : arguments);
    }

    /** 切换语言（英文↔中文）。 */
    public static void toggleLanguage() {
        currentLanguage = currentLanguage == Language.ENGLISH ? Language.CHINESE : Language.ENGLISH;
    }

    /** 判断当前是否中文。 */
    public static boolean isChinese() {
        return currentLanguage == Language.CHINESE;
    }

    /** 设置中文/英文。 */
    public static void setChinese(boolean isChinese) {
        currentLanguage = isChinese ? Language.CHINESE : Language.ENGLISH;
    }
}

