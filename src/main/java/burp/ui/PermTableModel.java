package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

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
                return "id";
            case 1:
                return "method";
            case 2:
                return "url";
            case 3:
                return "originalength";
            case 4:
                return "lowlength";
            case 5:
                return "nolength";
            case 6:
                return "isSuccess";
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
