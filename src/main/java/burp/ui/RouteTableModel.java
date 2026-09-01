package burp.ui;

import burp.utils.I18nUtils;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** 目录探测规则表格模型：读 RouteUI 的 routeList 引用（以其为监视器加锁）；
 *  JTable 读取发生在 EDT。 */
public class RouteTableModel extends AbstractTableModel {
    private final List<RouteUIEntry> routelog;

    public RouteTableModel(List<RouteUIEntry> routelog) {
        this.routelog = routelog;
    }

    @Override
    public int getRowCount() {
        synchronized (routelog) {
            return routelog.size();
        }
    }

    @Override
    public int getColumnCount() {
        return 5;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (routelog) {
            if (rowIndex < 0 || rowIndex >= routelog.size()) {
                return null;
            }
            RouteUIEntry logEntry = routelog.get(rowIndex);
            switch (columnIndex) {
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.enable == 1 ? I18nUtils.get("route.value.enabled") : I18nUtils.get("route.value.disabled");
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
