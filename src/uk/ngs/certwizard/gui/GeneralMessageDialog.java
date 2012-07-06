/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.certwizard.gui;

import java.awt.Component;
import java.awt.Dimension;
import javax.swing.JOptionPane;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;

/**
 *
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
