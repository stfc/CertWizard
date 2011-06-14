/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * ContactServerPanel.java
 *
 * Created on 20-Jul-2010, 10:41:31
 */
package uk.ngs.certwizard.gui;

import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.swing.JPanel;

import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.common.SystemStatus;

/**
 *
 * @author xw75
 */
public class ContactServerPanel extends javax.swing.JPanel {

    private Timer timer;
    private JPanel getCertPanel;
    private AtomicBoolean isReachableServer = new AtomicBoolean(false);
    PingService pingService = null;

    //private PasswordPanel passwordPanel;
    private CertWizardMain _certWizardMain = null;

    /** Creates new form ContactServerPanel */
    public ContactServerPanel(CertWizardMain _certWizardMain) {
        initComponents();
        this.add(jPanel1, java.awt.BorderLayout.CENTER);
        this._certWizardMain = _certWizardMain;
        this.getCertPanel = this._certWizardMain.getCertificatePanel();
        pingService = PingService.getPingService();
      
        getCertPanel.add(new PasswordPanel(this._certWizardMain), "PasswordPanel");
        _init();
    }

    /**
     * We need the timer task in order to give the user time to press "Work Offline"
     * in case the user wants to work offline even if there is a connection
     * to the Internet.
     */
    private void _init(){
        //passwordPanel.setVisible(false);

        jLabel2.setText("Attempting to connect to the CA Server...");
        tryAgainButton.setVisible(false);
        //jButton1.setVisible(false);
        timer = new Timer();
        jProgressBar1.setIndeterminate(true);
//        TimerTask task = new updateProgressBar(jProgressBar1);
//        timer.scheduleAtFixedRate(task, 500, 500);
        timer.schedule(new loadMainWindow(this), 2000);


    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel2 = new javax.swing.JLabel();
        jProgressBar1 = new javax.swing.JProgressBar();
        cancelOnlineButton = new javax.swing.JButton();
        tryAgainButton = new javax.swing.JButton();

        setBorder(javax.swing.BorderFactory.createTitledBorder("Contact Server"));
        setLayout(new java.awt.BorderLayout());

        jLabel2.setText("Connecting to the CA Server...");

        jProgressBar1.setMaximum(10);

        cancelOnlineButton.setText("Cancel");
        cancelOnlineButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelOnlineButtonActionPerformed(evt);
            }
        });

        tryAgainButton.setText("Try Again");
        tryAgainButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                tryAgainButtonActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel1Layout = new org.jdesktop.layout.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(jPanel1Layout.createSequentialGroup()
                        .add(jLabel2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 374, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .add(18, 59, Short.MAX_VALUE)
                        .add(tryAgainButton)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(cancelOnlineButton))
                    .add(org.jdesktop.layout.GroupLayout.LEADING, jProgressBar1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 620, Short.MAX_VALUE))
                .add(19, 19, 19))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .add(24, 24, 24)
                .add(jProgressBar1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .add(18, 18, 18)
                .add(jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(cancelOnlineButton)
                    .add(jLabel2)
                    .add(tryAgainButton))
                .addContainerGap(35, Short.MAX_VALUE))
        );

        add(jPanel1, java.awt.BorderLayout.CENTER);
    }// </editor-fold>//GEN-END:initComponents

    private void cancelOnlineButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelOnlineButtonActionPerformed
        // Terminates this timer, discarding any currently scheduled tasks.
        // Does not interfere with a currently executing task (if it exists).
        // Once a timer has been terminated, its execution thread terminates
        // gracefully, and no more tasks may be scheduled on it.
        //timer.cancel();

        //SystemStatus.ISONLINE.set(false);

        // When clicking cancel, show a new PasswordPanel and remove
        // this (ContactServerPanel) from itself.
        //getCertPanel.add(new PasswordPanel(this._certWizardMain), "PasswordPanel");
        //getCertPanel.remove(this);
    }//GEN-LAST:event_cancelOnlineButtonActionPerformed

    private void tryAgainButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_tryAgainButtonActionPerformed
        // TODO add your handling code here:
        //_init();
    }//GEN-LAST:event_tryAgainButtonActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton cancelOnlineButton;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JButton tryAgainButton;
    // End of variables declaration//GEN-END:variables

    class loadMainWindow extends TimerTask {

        ContactServerPanel cPanel;

        public loadMainWindow(ContactServerPanel cPanel) {
            this.cPanel = cPanel;
        }

        public void run() {
            System.out.println("EXECUTING PING CHECK STATEMENT");
            isReachableServer.set( pingService.isPingService() );
            

            if (isReachableServer.get()) {
                System.out.println("PASSED");
                SystemStatus.getInstance().setIsOnline(true);
                // Terminates this timer, discarding any currently scheduled tasks.
                // Does not interfere with a currently executing task (if it exists).
                // Once a timer has been terminated, its execution thread terminates
                // gracefully, and no more tasks may be scheduled on it.
                //timer.cancel();
                //getCertPanel.add(new PasswordPanel(_certWizardMain), "PasswordPanel");
                //getCertPanel.remove(cPanel);
            } else {
                SystemStatus.getInstance().setIsOnline(false); 
                //jLabel2.setText("<html>Failed to connect to the CA server. "
                //        + "You can switch to offline mode by clicking 'Cancel' button, "
                //        + "or retry connecting by clicking 'Try Again'.");
                //new MainWindow().setVisible(true);
                //tryAgainButton.setVisible(true);
                //cancelOnlineButton.setVisible(true);
                //timer.cancel();
                //jProgressBar1.setIndeterminate(false);
            }

        }
    }

//    class updateProgressBar extends TimerTask {
//
//        javax.swing.JProgressBar bar;
//        int value;
//
//        public updateProgressBar(javax.swing.JProgressBar bar) {
//            this.bar = bar;
//            value = bar.getValue();
//        }
//
//        public void run() {
//            bar.setIndeterminate(true);
//            bar.setValue(value + 1);
//
//            if( pingService == null ){
//                pingService = new PingService();
//                System.out.println("EXECUTING PING CHECK STATEMENT");
//                isReachableServer = pingService.isPingService();
//            }
//
//        }
//    }
}
