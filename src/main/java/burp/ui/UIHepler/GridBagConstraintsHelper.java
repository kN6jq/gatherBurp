package burp.ui.UIHepler;

import java.awt.*;

/**
 * @Author Xm17
 * @Date 2024-06-14 10:50
 */
public class GridBagConstraintsHelper extends GridBagConstraints {

    /**

     *

     */

    private static final long serialVersionUID = 1L;

    /**

     * 指定组件起始网格的构造函数

     *

     * @param gridx 水平方向上的起始网格

     * @param gridy 竖直方向上的起始网格

     */

    public GridBagConstraintsHelper(int gridx, int gridy) {

        this.gridx = gridx;

        this.gridy = gridy;

    }

    /**

     * 指定组件起始网格与跨度的构造函数

     *

     * @param gridx 水平方向起始网格

     * @param gridy 竖直方向起始网格

     * @param gridwidth 水平方向占据的网格数目

     * @param gridheight 竖直方向占据的网格数目

     */

    public GridBagConstraintsHelper(int gridx, int gridy, int gridwidth, int gridheight) {

        this.gridx = gridx;

        this.gridy = gridy;

        this.gridwidth = gridwidth;

        this.gridheight = gridheight;

    }

    /**

     * 设置组件在网格中的摆放方式

     *

     * @param anchor 组件的摆放方式

     * @return 当前操作对象

     */

    public GridBagConstraintsHelper setAnchor(int anchor) {

        this.anchor = anchor;

        return this;

    }

    /**

     * 设置组件在网格中的拉伸方式

     *

     * @param fill 组件的拉伸方式

     * @return 当前操作对象

     */

    public GridBagConstraintsHelper setFill(int fill) {

        this.fill = fill;

        return this;

    }

    /**

     * 设置网格的拉伸程度

     *

     * @param weightx 水平方向的拉伸程度

     * @param weighty 竖直方向的拉伸程度

     * @return 当前操作对象

     */

    public GridBagConstraintsHelper setWeight(double weightx, double weighty) {

        this.weightx = weightx;

        this.weighty = weighty;

        return this;

    }

    /**

     * 统一设置组件与网格四周的间隔

     *

     * @param distance 四周的间隔长度

     * @return 当前操作对象

     */

    public GridBagConstraintsHelper setInsets(int distance) {

        this.insets = new Insets(distance, distance, distance, distance);

        return this;

    }

    /**

     * 分别设置组件与网格四周的间隔

     *

     * @param top 组件上方与网格的距离

     * @param left 组件左方与网格的距离

     * @param bottom 组件下方与网格的距离

     * @param right 组件右方与网格的距离

     * @return 当前操作对象

     */

    public GridBagConstraintsHelper setInsets(int top, int left, int bottom, int right) {

        this.insets = new Insets(top, left, bottom, right);

        return this;

    }

    /**

     * 设置组件拉伸长度

     *

     * @param ipadx 水平方向拉伸的长度

     * @param ipady 竖直方向拉伸的长度

     * @return 当前操作对象

     */

    public GridBagConstraintsHelper setIpad(int ipadx, int ipady) {

        this.ipadx = ipadx;

        this.ipady = ipady;

        return this;

    }

}

