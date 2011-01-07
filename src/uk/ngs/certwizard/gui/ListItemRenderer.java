/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import javax.swing.*;
import java.awt.*;

/**
 *
 * @author hyz38924
 */
class ListItemRenderer extends JLabel
        implements ListCellRenderer {

    protected DefaultListCellRenderer defaultRenderer = new DefaultListCellRenderer();

    public Component getListCellRendererComponent(JList list, Object value, int index,
            boolean isSelected, boolean cellHasFocus) {

        Color theForeground = null;
        String theText = null;

        JLabel renderer = (JLabel) defaultRenderer.getListCellRendererComponent(list, value, index,
                isSelected, cellHasFocus);

        if (value instanceof Object[]) {
            Object values[] = (Object[]) value;

            if(isSelected){
                renderer.setOpaque(true);
            }

            theForeground = (Color) values[0];
            theText = (String) values[1];

        } else {

            theForeground = list.getForeground();
            theText = "";
        }
        renderer.setForeground(theForeground);

        renderer.setText(theText);

        return renderer;
    }
}
