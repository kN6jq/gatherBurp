package burp.ui;

import burp.utils.I18nUtils;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** Log4j 结果表格模型：读 Log4jUI store 的内部列表引用（以其为监视器加锁，
 *  与扫描线程 add/淘汰互斥）；JTable 读取发生在 EDT。 */
public class Log4jTableModel extends AbstractTableModel {

    private final List<Log4jUIEntry> log4jlog;

    public Log4jTableModel(List<Log4jUIEntry> log4jlog) {
        this.log4jlog = log4jlog;
    }

    @Override
    public int getRowCount() {
        synchronized (log4jlog) {
            return log4jlog.size();
        }
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "#";
            case 1:
                return I18nUtils.get("table.method");
            case 2:
                return I18nUtils.get("table.url");
            case 3:
                return I18nUtils.get("table.status");
            case 4:
                return I18nUtils.get("table.length");
            default:
                return "";
        }
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (log4jlog) {
            // 淘汰最旧条目的瞬间 EDT 可能拿着旧行数来取，越界直接返回空
            if (rowIndex < 0 || rowIndex >= log4jlog.size()) {
                return null;
            }
            Log4jUIEntry logEntry = log4jlog.get(rowIndex);
            switch (columnIndex) {
                case 0:
                    return logEntry.id;
                case 1:
                    return logEntry.extensionMethod;
                case 2:
                    return logEntry.url;
                case 3:
                    return logEntry.res;
                case 4:
                    return logEntry.length;
                default:
                    return null;
            }
        }
    }

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) {
            return Integer.class;
        }
        return super.getColumnClass(column);
    }
}
