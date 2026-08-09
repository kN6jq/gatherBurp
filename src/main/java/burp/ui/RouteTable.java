package burp.ui;

import javax.swing.*;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

public class RouteTable extends JTable {
    private static final TableCellRenderer RENDERER = new RouteCustomTableCellRenderer();

    public RouteTable(TableModel tableModel) {
        super(tableModel);
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setMaxWidth(50);
        columnModel.getColumn(1).setMaxWidth(50);
        columnModel.getColumn(2).setMinWidth(100);
        columnModel.getColumn(2).setMaxWidth(150);
    }

    @Override
    public TableCellRenderer getCellRenderer(int row, int column) {
        return RENDERER;
    }
}
