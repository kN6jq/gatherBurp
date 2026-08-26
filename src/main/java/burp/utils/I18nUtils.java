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

    /** Resource bundles in this project are stored as UTF-8 properties files. */
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
            ResourceBundle bundle = ResourceBundle.getBundle("i18n.messages", locale, UTF8_CONTROL);
            return bundle.getString(key);
        } catch (Exception e) {
            return key;
        }
    }

    /**
     * Formats a localized message that uses MessageFormat placeholders such as {0} and {1}.
     */
    public static String format(String key, Object... arguments) {
        Locale locale = currentLanguage == Language.CHINESE ? Locale.CHINESE : Locale.ENGLISH;
        return new MessageFormat(get(key), locale).format(arguments == null ? new Object[0] : arguments);
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

