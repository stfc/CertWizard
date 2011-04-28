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

import javax.swing.JFrame;
import java.awt.Dimension;
import javax.swing.JLabel;
import java.awt.Rectangle;
import javax.swing.ImageIcon;

import java.awt.Font;
import java.awt.Image;
import java.net.URL;
import java.awt.SystemColor;
import java.awt.Toolkit;

/**
 * This class is used to display the Wait Dialog. This Dialog is displayed
 * when the system is busy processing. All the GUI controls in this dilaog
 * are intialized once and the static methods showDialog/hideDialog, uses
 * this instance to show/hide.

 *
 * @since 1.0
 * @version 1.0
 */
public class WaitDialog extends JFrame  {
//  private JLabel jLabel1;
  private JLabel jLabel2 = new JLabel();
  Rectangle bounds;



  // single instance of this class, used through out the scope of the application
  private static WaitDialog dlg = new  WaitDialog();

  /**
   * The constructor intialises all the GUI controls
   */
  private WaitDialog() {
    try {
      jbInit();
    } catch(Exception e) {
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

    URL iconURL = Apply.class.getResource("/uk/ngs/ca/images/ngs-icon.png");
    if (iconURL != null) {
        this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
    }

//    URL iconURL2 = Apply.class.getResource("/uk/ngs/ca/images/ngs_radars.gif");
//    if (iconURL2 != null) {
//        Image image = Toolkit.getDefaultToolkit().getImage(iconURL);
//        jLabel1 = new JLabel();
//
//    }

    jLabel2.setText("Please wait, while the system is processing...");

    jLabel2.setForeground(SystemColor.textText);
    jLabel2.setBounds(new Rectangle(60, 30, 300, 65));
    jLabel2.setFont(new Font("Dialog", 1, 13));
    this.getContentPane().add(jLabel2, null);

    
  }

  /**
   * This static method uses pre-created dialog, positions it in the center
   * and displays it to the user.
   */
  public static void showDialog() {
    dlg.setLocation( (int)dlg.bounds.getWidth() / 2 - 200, (int)dlg.bounds.getHeight()/2 - 75);
    dlg.show();
    dlg.paint(dlg.getGraphics());
    dlg.toFront();
  }

  /**

   * This static method hides the wait dialog.
   */
  public static void hideDialog()   {
    dlg.hide();
  }
}

