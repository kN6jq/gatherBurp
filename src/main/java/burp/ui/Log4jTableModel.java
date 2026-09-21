package burp.ui;

import burp.utils.I18nUtils;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** Log4j 结果表格模型：读 Log4jUI store 的内部列表引用（写入方在 store 监视器内修改；
 *  JTable 读取在 EDT，与刷新路径一致）。 */
public class Log4jTableModel extends AbstractTableModel {

    private final List<Log4jUIEntry> log4jlog;

    public Log4jTableModel(List<Log4jUIEntry> log4jlog) {
        this.log4jlog = log4jlog;
    }

    @Override
    public int getRowCount() {
        return log4jlog.size();
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

    @Override
    public Class<?> getColumnClass(int column) {
        if (column == 0) {
            return Integer.class;
        }
        return super.getColumnClass(column);
    }
}
