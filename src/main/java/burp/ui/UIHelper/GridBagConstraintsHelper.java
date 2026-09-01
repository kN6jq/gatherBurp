package burp.ui.UIHelper;

import java.awt.*;

/** GridBagConstraints 的流式（链式）包装：setAnchor/setFill/setWeight/setInsets/setIpad
 *  均返回 this，用于简化各面板的网格布局代码。 */
public class GridBagConstraintsHelper extends GridBagConstraints {

    private static final long serialVersionUID = 1L;

    /** 指定组件起始网格的构造函数。 */
    public GridBagConstraintsHelper(int gridx, int gridy) {
        this.gridx = gridx;
        this.gridy = gridy;
    }

    /** 指定组件起始网格与跨度的构造函数。 */
    public GridBagConstraintsHelper(int gridx, int gridy, int gridwidth, int gridheight) {
        this.gridx = gridx;
        this.gridy = gridy;
        this.gridwidth = gridwidth;
        this.gridheight = gridheight;
    }

    /** 设置组件在网格中的摆放方式，返回 this。 */
    public GridBagConstraintsHelper setAnchor(int anchor) {
        this.anchor = anchor;
        return this;
    }

    /** 设置组件在网格中的拉伸方式，返回 this。 */
    public GridBagConstraintsHelper setFill(int fill) {
        this.fill = fill;
        return this;
    }

    /** 设置网格的拉伸程度，返回 this。 */
    public GridBagConstraintsHelper setWeight(double weightx, double weighty) {
        this.weightx = weightx;
        this.weighty = weighty;
        return this;
    }

    /** 统一设置组件与网格四周的间隔，返回 this。 */
    public GridBagConstraintsHelper setInsets(int distance) {
        this.insets = new Insets(distance, distance, distance, distance);
        return this;
    }

    /** 分别设置组件与网格四周的间隔，返回 this。 */
    public GridBagConstraintsHelper setInsets(int top, int left, int bottom, int right) {
        this.insets = new Insets(top, left, bottom, right);
        return this;
    }

    /** 设置组件拉伸长度，返回 this。 */
    public GridBagConstraintsHelper setIpad(int ipadx, int ipady) {
        this.ipadx = ipadx;
        this.ipady = ipady;
        return this;
    }
}
