package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

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
                return "Method";
            case 2:
                return "URL";
            case 3:
                return "Status";
            case 4:
                return "Length";
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
