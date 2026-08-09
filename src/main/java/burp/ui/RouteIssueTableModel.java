package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

public class RouteIssueTableModel extends AbstractTableModel {
    private final List<RouteIssueEntry> issuslog;

    public RouteIssueTableModel(List<RouteIssueEntry> issuslog) {
        this.issuslog = issuslog;
    }

    @Override
    public int getRowCount() {
        return issuslog.size();
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        RouteIssueEntry logEntry = issuslog.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return logEntry.id;
            case 1:
                return logEntry.issueName;
            case 2:
                return logEntry.url;
            case 3:
                return logEntry.status;
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
                return "Issus name";
            case 2:
                return "url";
            case 3:
                return "status";
            default:
                return "";
        }
    }
}
