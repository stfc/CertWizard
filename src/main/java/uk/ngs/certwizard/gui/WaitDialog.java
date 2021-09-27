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

/*
 * @author  : Srikanth Mohan

 * @version : 1.0
 *
 * Development Environment : Oracle9i JDeveloper
 * Name of the File        : WaitDialog.java
 *
 * Creation / Modification History
 *    Srikanth           13-Aug-2002        Created

 *
 */
import java.awt.*;
import java.net.URL;
import javax.swing.JFrame;
import javax.swing.JLabel;

/**
 * This class is used to display the Wait Dialog. This Dialog is displayed when
 * the system is busy processing. All the GUI controls in this dilaog are
 * intialized once and the static methods showDialog/hideDialog, uses this
 * instance to show/hide.
 *
 *
 * @since 1.0
 * @version 1.0
 */
public class WaitDialog extends JFrame {
//  private JLabel jLabel1;

    private static JLabel jLabel2 = new JLabel();
    Rectangle bounds;

    // single instance of this class, used through out the scope of the application
    private static WaitDialog dlg = new WaitDialog();

    /**
     * The constructor intialises all the GUI controls
     */
    private WaitDialog() {
        super();
        try {
            jbInit();
        } catch (Exception e) {
            e.printStackTrace();

        }
    }

    /**
     * This method intializes all the GUI controls and adds it to the Panel
     *
     * @exception Exception if any exception, while creating GUI controls
     */
    private void jbInit() throws Exception {
        this.getContentPane().setLayout(null);
        this.setSize(new Dimension(400, 150));
        this.setResizable(false);

        this.setTitle("Please wait");
        bounds = this.getGraphicsConfiguration().getBounds();

        URL iconURL = getClass().getResource("/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }

        jLabel2.setForeground(SystemColor.textText);
        jLabel2.setBounds(new Rectangle(60, 30, 300, 65));
        jLabel2.setFont(new Font("Dialog", 1, 13));
        this.getContentPane().add(jLabel2, null);

    }

    /**
     *
     * This static method hides the wait dialog.
     */
    public static void hideDialog() {
        dlg.setVisible(false);
    }
}
