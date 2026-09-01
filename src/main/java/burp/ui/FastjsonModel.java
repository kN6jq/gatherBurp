package burp.ui;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/** Fastjson 结果表格模型：读 FastjsonUI 静态有界 store 的内部列表（以其为监视器加锁，
 *  与 store 的写入线程互斥）；JTable 读取发生在 EDT。 */
public class FastjsonModel extends AbstractTableModel {

    @Override
    public int getRowCount() {
        synchronized (FastjsonUI.getFastjsonlog()) {
            return FastjsonUI.getFastjsonlog().size();
        }
    }

    @Override
    public int getColumnCount() {
        return 6;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        synchronized (FastjsonUI.getFastjsonlog()) {
            List<FastjsonEntry> log = FastjsonUI.getFastjsonlog();
            if (rowIndex >= 0 && rowIndex < log.size()) {
                FastjsonEntry logEntry = log.get(rowIndex);
                switch (columnIndex) {
                    case 0: return logEntry.id;
                    case 1: return logEntry.extensionMethod;
                    case 2: return logEntry.url;
                    case 3: return logEntry.status;
                    case 4: return logEntry.res;
                    case 5: return logEntry.req;
                    default: return "";
                }
            }
            return "";
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0: return "id";
            case 1: return "method";
            case 2: return "url";
            case 3: return "status";
            case 4: return "res";
            case 5: return "req";
            default: return "";
        }
    }
}
