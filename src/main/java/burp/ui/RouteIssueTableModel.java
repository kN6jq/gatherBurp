package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** 目录探测命中问题表格模型：读 RouteUI store 的内部列表引用（以其为监视器加锁）；
 *  JTable 读取发生在 EDT。 */
public class RouteIssueTableModel extends AbstractTableModel {
    private final List<RouteIssueEntry> issuesLog;

    public RouteIssueTableModel(List<RouteIssueEntry> issuesLog) {
        this.issuesLog = issuesLog;
    }

    @Override
    public int getRowCount() {
        synchronized (issuesLog) {
            return issuesLog.size();
        }
    }

    @Override
    public int getColumnCount() {
        return 4;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (issuesLog) {
            if (rowIndex < 0 || rowIndex >= issuesLog.size()) {
                return null;
            }
            RouteIssueEntry logEntry = issuesLog.get(rowIndex);
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
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0:
                return "id";
            case 1:
                return "Issue name";
            case 2:
                return "url";
            case 3:
                return "status";
            default:
                return "";
        }
    }
}
