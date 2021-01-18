/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
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
     * This static method uses pre-created dialog, positions it in the center
     * and displays it to the user.
     */
    public static void showDialog(String message) {
        if (message == null) {
            jLabel2.setText("Please wait...");
        } else {
            jLabel2.setText(message);
        }

        dlg.setLocation((int) dlg.bounds.getWidth() / 2 - 200, (int) dlg.bounds.getHeight() / 2 - 75);
        dlg.setVisible(true);
        dlg.paint(dlg.getGraphics());
        dlg.toFront();
    }

    /**
     *
     * This static method hides the wait dialog.
     */
    public static void hideDialog() {
        dlg.setVisible(false);
    }
}