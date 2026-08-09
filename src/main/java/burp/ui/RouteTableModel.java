package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class RouteTableModel extends AbstractTableModel {
    private final List<RouteUIEntry> routelog;

    public RouteTableModel(List<RouteUIEntry> routelog) {
        this.routelog = routelog;
    }

    @Override
    public int getRowCount() {
        return routelog.size();
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RouteUIEntry logEntry = routelog.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.enable == 1 ? "开启" : "关闭";
            case 2:
                return logEntry.name;
            case 3:
                return logEntry.path;
            case 4:
                return logEntry.express;
            default:
                return "";
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "id";
            case 1:
                return "enable";
            case 2:
                return "name";
            case 3:
                return "path";
            case 4:
                return "express";
            default:
                return "";
        }
    }
}
