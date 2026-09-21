package burp.ui;

import burp.utils.I18nUtils;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** 越权结果表格模型：读 PermUI store 的内部列表引用（以其为监视器加锁）；
 *  JTable 读取发生在 EDT。 */
public class PermTableModel extends AbstractTableModel {

    private final List<PermUIEntry> permlog;

    public PermTableModel(List<PermUIEntry> permlog) {
        this.permlog = permlog;
    }

    @Override
    public int getRowCount() {
        synchronized (permlog) {
            return permlog.size();
        }
    }

    @Override
    public int getColumnCount() {
        return 7;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (permlog) {
            if (rowIndex < 0 || rowIndex >= permlog.size()) {
                return null;
            }
            switch (columnIndex) {
                case 0:
                    return permlog.get(rowIndex).id;
                case 1:
                    return permlog.get(rowIndex).method;
                case 2:
                    return permlog.get(rowIndex).url;
                case 3:
                    return permlog.get(rowIndex).originalength;
                case 4:
                    return permlog.get(rowIndex).lowlength;
                case 5:
                    return permlog.get(rowIndex).nolength;
                case 6:
                    return permlog.get(rowIndex).isSuccess;
                default:
                    return null;
            }
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return I18nUtils.get("table.id");
            case 1:
                return I18nUtils.get("table.method");
            case 2:
                return I18nUtils.get("table.url");
            case 3:
                return I18nUtils.get("table.original_length");
            case 4:
                return I18nUtils.get("table.low_length");
            case 5:
                return I18nUtils.get("table.no_length");
            case 6:
                return I18nUtils.get("table.success");
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
