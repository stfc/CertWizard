/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.certwizard.gui;

import javax.swing.*;
import java.awt.*;

/**
 * @author David Meredith
 */
public class GeneralMessageDialog {

    public static void showAndWait(Component parent, String text, String title, int JOptionPaneMessageType) {

        JTextArea jt = new JTextArea();
        jt.setText(text);
        jt.setLineWrap(true);
        jt.setEditable(false);
        jt.setWrapStyleWord(true);
        jt.setCaretPosition(0);
        JScrollPane scroller = new JScrollPane(jt);
        scroller.setPreferredSize(new Dimension(600, 100));
        JOptionPane.showMessageDialog(parent, scroller, title, JOptionPaneMessageType);
    }
}
