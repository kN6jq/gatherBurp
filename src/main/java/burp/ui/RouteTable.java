package burp.ui;

import javax.swing.*;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

/** 目录探测规则表格（RouteUI 左栏）：规则列表 + 启用状态展示。 */
public class RouteTable extends JTable {
    public RouteTable(TableModel tableModel) {
        super(tableModel);
        TableColumnModel columnModel = getColumnModel();
        columnModel.getColumn(0).setMaxWidth(50);
        columnModel.getColumn(1).setMaxWidth(50);
        columnModel.getColumn(2).setMinWidth(100);
        columnModel.getColumn(2).setMaxWidth(150);
    }
}
