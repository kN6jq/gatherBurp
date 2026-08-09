package burp.ui;

import burp.IMessageEditor;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

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
        int modelRow = row;
        if (getRowSorter() != null) {
            modelRow = convertRowIndexToModel(row);
        }

        RedirectEntry entry = UrlRedirectUI.getRedirectLog().get(modelRow);
        if (requestEditor != null) {
            requestEditor.setMessage(entry.requestResponse.getRequest(), true);
        }
        if (responseEditor != null) {
            if (entry.requestResponse.getResponse() == null) {
                responseEditor.setMessage(new byte[0], false);
            } else {
                responseEditor.setMessage(entry.requestResponse.getResponse(), false);
            }
        }
        UrlRedirectUI.setCurrentlyDisplayedItem(entry.requestResponse);
        super.changeSelection(row, col, toggle, extend);
    }
}
