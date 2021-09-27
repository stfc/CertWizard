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

 /*
 * PasswordPanel.java
 *
 * Created on 20-Jul-2010, 14:48:14
 */
package uk.ngs.certwizard.gui;

//import help_panel_html.LoadHtmlResource;
import java.awt.Dimension;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import net.sf.portecle.gui.error.DThrowable;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.common.LocalBackup;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75 (Xiao Wang)
 */
public class PasswordPanel extends javax.swing.JPanel {

    private JPanel parentPanel;
    private SystemStatus sysStatus = null;
    private boolean isExistKeyStore = false;

    /**
     * Creates new form Password
     */
    public PasswordPanel(JPanel parent) {
        super();
        this.sysStatus = SystemStatus.getInstance();
        this.isExistKeyStore = this.sysStatus.isExistKeyStore();

        this.parentPanel = parent;
        initComponents();

        if (this.isExistKeyStore) {
            jLabel3.setVisible(false);
            txtConfirmPassword.setVisible(false);
        } else {
            jLabel3.setVisible(true);
            txtConfirmPassword.setVisible(true);
        }
        okButton.setEnabled(false);

        String keyStoreFile = SysProperty.getValue("ngsca.key.keystore.file");
        String keyStorePath = SystemStatus.getInstance().getHomeDir().getAbsolutePath();
        keyStorePath = keyStorePath + System.getProperty("file.separator") + ".ca";
        keyStorePath = keyStorePath + System.getProperty("file.separator") + keyStoreFile;
        jLabel2.setText(keyStorePath);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        txtPassword = new javax.swing.JPasswordField();
        okButton = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        txtConfirmPassword = new javax.swing.JPasswordField();
        jScrollPane1 = new javax.swing.JScrollPane();
        jTextPane1 = new javax.swing.JTextPane();
        jLabel2 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();

        jLabel1.setText("Password:");

        txtPassword.addActionListener(this::txtPasswordActionPerformed);
        txtPassword.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtPasswordKeyReleased(evt);
            }
        });

        okButton.setText("OK");
        okButton.addActionListener(this::okButtonActionPerformed);

        jLabel3.setText("Confirm:");

        txtConfirmPassword.addActionListener(this::txtConfirmPasswordActionPerformed);
        txtConfirmPassword.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtConfirmPasswordKeyReleased(evt);
            }
        });

        jScrollPane1.setViewportView(jTextPane1);
        try {
            java.net.URL url;
            if ( this.isExistKeyStore ) {
                url = this.getClass().getResource("/help_panel_html/passwordPanel.html");
            } else {
                url = this.getClass().getResource("/help_panel_html/passwordPanelNew.html");
            }

            jTextPane1.setPage(url);

        } catch (IOException ex) {
            System.err.println("Could not find file: " + "/help_panel_html/welcome.html");
            ex.printStackTrace();
        }

        jLabel2.setText("jLabel2");

        jLabel4.setText("Keystore:");

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(layout.createSequentialGroup()
                        .add(196, 196, 196)
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(jLabel1)
                            .add(jLabel3)
                            .add(jLabel4))
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(layout.createSequentialGroup()
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                                    .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                                        .add(okButton)
                                        .add(org.jdesktop.layout.GroupLayout.LEADING, txtConfirmPassword, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 239, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                    .add(txtPassword, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 239, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                            .add(layout.createSequentialGroup()
                                .add(15, 15, 15)
                                .add(jLabel2))))
                    .add(layout.createSequentialGroup()
                        .addContainerGap()
                        .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 806, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 344, Short.MAX_VALUE)
                .add(18, 18, 18)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(jLabel1)
                    .add(txtPassword, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel3)
                    .add(txtConfirmPassword, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(okButton)
                .add(18, 18, 18)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel4)
                    .add(jLabel2))
                .add(25, 25, 25))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void okButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButtonActionPerformed
//        messageLabel.setText("<html>Please Wait..</html>");
        if (this.isExistKeyStore) {
            loadMainWindowPanel();
        } else {
            String password = new String(txtPassword.getPassword());
            String confirm = new String(txtConfirmPassword.getPassword());
            if (password.equals(confirm)) {
                this.loadMainWindowPanel();
            } else {
                String errorMessage = "The passwords should match.";
                JOptionPane.showMessageDialog(this, errorMessage, "Wrong Password", JOptionPane.ERROR_MESSAGE);
            }
        }
    }//GEN-LAST:event_okButtonActionPerformed

    /**
     * Compare passwords and create/show a new instance of MainWindowPanel if
     * the passwords are correct. Otherwise, show an error on the panel.
     */
    private void loadMainWindowPanel() {

        char[] passphrase = txtPassword.getPassword();
        //boolean isValid = this.sysStatus.isValidPassphrase(passphrase);
        try {
            // Load keyStore and save to disk if it does not already exist
            // (maybe the first time the tool has been run)
            String keyStoreFilePath = ClientKeyStoreCaServiceWrapper.getInstance(passphrase).getClientKeyStore().getKeyStoreFilePath();
            File keyStoreFile = new File(keyStoreFilePath);
            if (!keyStoreFile.exists()) {
                ClientKeyStoreCaServiceWrapper.getInstance(passphrase).getClientKeyStore().reStore();
            }
        } catch (KeyStoreException ex) {
            JOptionPane.showMessageDialog(this, "Wrong Password? " + ex.getCause().getMessage(), "Wrong Password", JOptionPane.ERROR_MESSAGE);
            txtPassword.setText("");
            return;
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Occurred", ex);
            txtPassword.setText("");
            return;
        }

        String _pswdProperty = SysProperty.getValue("uk.ngs.ca.passphrase.property");
        String _pswd = new String(this.txtPassword.getPassword());
        System.setProperty(_pswdProperty, _pswd);

        // create a backup 
        LocalBackup localBackup = new LocalBackup();
        if (!localBackup.isSuccess()) {
            JOptionPane.showMessageDialog(this, localBackup.getMessage(), "Failed to make backup file", JOptionPane.WARNING_MESSAGE);
        }

        //getCertPanel.remove(this);
        this.setVisible(false);

        final MainWindowPanel mainpane = new MainWindowPanel(passphrase);

        parentPanel.addComponentListener(new ComponentListener() {

            public void componentResized(ComponentEvent e) {
                mainpane.setPreferredSize(new Dimension(e.getComponent().getWidth(), e.getComponent().getHeight()));
                revalidate();
            }

            public void componentMoved(ComponentEvent e) {
                //throw new UnsupportedOperationException("Not supported yet.");
            }

            public void componentShown(ComponentEvent e) {
                mainpane.setPreferredSize(new Dimension(e.getComponent().getWidth(), e.getComponent().getHeight()));
                revalidate();
                //throw new UnsupportedOperationException("Not supported yet.");
            }

            public void componentHidden(ComponentEvent e) {
                //throw new UnsupportedOperationException("Not supported yet.");
            }
        });

        parentPanel.add(mainpane, "MainWindowPanel");
        // force an initial resizing 
        mainpane.setPreferredSize(new Dimension(parentPanel.getWidth(), parentPanel.getHeight()));
        mainpane.doPostConstruct();
    }

    private void txtPasswordActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtPasswordActionPerformed
        // TODO add your handling code here:
        if (this.isExistKeyStore) {
            loadMainWindowPanel();
        } else {
            String password = new String(txtPassword.getPassword());
            String confirm = new String(txtConfirmPassword.getPassword());
            if (password.equals(confirm)) {
                loadMainWindowPanel();
            } else {
                String errorMessage = "The passwords should match.";
                JOptionPane.showMessageDialog(this, errorMessage, "Wrong Password", JOptionPane.ERROR_MESSAGE);
            }
        }
    }//GEN-LAST:event_txtPasswordActionPerformed

    private void txtPasswordKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtPasswordKeyReleased
        // TODO add your handling code here:
        if (this.isExistKeyStore) {
            this.okButton.setEnabled(true);
        } else {
            String password = new String(txtPassword.getPassword());
            String confirm = new String(txtConfirmPassword.getPassword());
            this.okButton.setEnabled(password.equals(confirm));
        }
    }//GEN-LAST:event_txtPasswordKeyReleased

    private void txtConfirmPasswordKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtConfirmPasswordKeyReleased
        // TODO add your handling code here:
        String password = new String(txtPassword.getPassword());
        String confirm = new String(txtConfirmPassword.getPassword());

        this.okButton.setEnabled(password.equals(confirm));
    }//GEN-LAST:event_txtConfirmPasswordKeyReleased

    private void txtConfirmPasswordActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtConfirmPasswordActionPerformed
        // TODO add your handling code here:
        String password = new String(txtPassword.getPassword());
        String confirm = new String(txtConfirmPassword.getPassword());
        if (password.equals(confirm)) {
            loadMainWindowPanel();
        } else {
            String errorMessage = "The passwords should match.";
            JOptionPane.showMessageDialog(this, errorMessage, "Wrong Password", JOptionPane.ERROR_MESSAGE);
        }
    }//GEN-LAST:event_txtConfirmPasswordActionPerformed

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextPane jTextPane1;
    private javax.swing.JButton okButton;
    private javax.swing.JPasswordField txtConfirmPassword;
    private javax.swing.JPasswordField txtPassword;
    // End of variables declaration//GEN-END:variables
}
