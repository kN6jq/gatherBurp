package burp.ui;

import burp.IHttpRequestResponse;
import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import java.util.List;

/** 开放重定向结果表格：选中行时同步刷新请求/响应编辑器并更新当前显示项。 */
public class RedirectTable extends JTable {
    private final IMessageEditor requestEditor;
    private final IMessageEditor responseEditor;

    public RedirectTable(TableModel model, IMessageEditor requestEditor, IMessageEditor responseEditor) {
        super(model);
        this.requestEditor = requestEditor;
        this.responseEditor = responseEditor;
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setMaxWidth(50);
        columnModel.getColumn(1).setMaxWidth(80);
        columnModel.getColumn(4).setMaxWidth(80);
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
        if (row < 0 || row >= getRowCount()) {
            return;
        }
        int modelRow = getRowSorter() == null ? row : convertRowIndexToModel(row);
        List<RedirectEntry> entries = UrlRedirectUI.getRedirectLog();
        RedirectEntry entry;
        synchronized (entries) {
            if (modelRow < 0 || modelRow >= entries.size()) {
                return;
            }
            entry = entries.get(modelRow);
        }
        IHttpRequestResponse message = entry.requestResponse;
        if (message == null) {
            return;
        }
        if (requestEditor != null) {
            requestEditor.setMessage(message.getRequest(), true);
        }
        if (responseEditor != null) {
            responseEditor.setMessage(message.getResponse() == null ? new byte[0] : message.getResponse(), false);
        }
        UrlRedirectUI.setCurrentlyDisplayedItem(message);
        super.changeSelection(row, col, toggle, extend);
    }
}
