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

import java.awt.Toolkit;
import java.io.File;
import java.net.URL;
import java.util.Date;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.util.KeyStoreChangePasswordGuiHelper;

/**
 * Dialog for displaying properties about the keyStore and keyStore management
 * such as changing the password.
 *
 * @author David Meredith
 */
public class KeyStorePropertiesJDialog extends javax.swing.JDialog {

    private ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    private MainWindowPanel masterPane;
    private char[] passphrase;

    /**
     * Creates new form KeyStorePropertiesJDialog
     */
    public KeyStorePropertiesJDialog(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();
    }

    public KeyStorePropertiesJDialog(java.awt.Frame parent, boolean modal,
            MainWindowPanel masterPane, ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        super(parent, modal);
        initComponents();
        this.caKeyStoreModel = caKeyStoreModel;
        this.masterPane = masterPane;
        if (this.caKeyStoreModel.getClientKeyStore().getKeyStoreFilePath() != null) {
            this.keyStorePathTextField.setText(this.caKeyStoreModel.getClientKeyStore().getKeyStoreFilePath());
            File keystore = new File(this.caKeyStoreModel.getClientKeyStore().getKeyStoreFilePath());
            if (keystore.exists()) {
                long lastMod = keystore.lastModified();
                Date d = new Date(lastMod);
                this.lastModLabel.setText(d.toString());
            }
        }

        URL iconURL = Apply.class.getResource("/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        this.setTitle("CertWizard keyStore File");

    }

    private void doChangePasswordAction() {
        if (masterPane.confirmBackgroundTaskRunning()) {
            return;
        }
        KeyStoreChangePasswordGuiHelper pwChange = new KeyStoreChangePasswordGuiHelper(this, this.caKeyStoreModel);
        char[] newPassword = pwChange.changeKeyStorePassword();
        if (newPassword != null) {
            passphrase = newPassword;
        }
    }

    public char[] getPassphase() {
        return this.passphrase;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        keyStorePathTextField = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        changePwButton = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        lastModLabel = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

        keyStorePathTextField.setEditable(false);

        jLabel1.setText("Your Keystore Path");

        changePwButton.setText("Change Keystore Password");
        changePwButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                changePwButtonActionPerformed(evt);
            }
        });

        jLabel2.setText("Last Modified");

        lastModLabel.setText("jLabel3");

        jLabel3.setText("KeyStore type");

        jLabel4.setText("Standard PKCS12 keyStore file (.p12)");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel1)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(keyStorePathTextField)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabel4)
                            .addComponent(lastModLabel)
                            .addComponent(changePwButton))
                        .addGap(0, 183, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(keyStorePathTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel1))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(lastModLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jLabel4))
                .addGap(13, 13, 13)
                .addComponent(changePwButton)
                .addContainerGap(42, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void changePwButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_changePwButtonActionPerformed
        // TODO add your handling code here:
        this.doChangePasswordAction();
    }//GEN-LAST:event_changePwButtonActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(KeyStorePropertiesJDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(KeyStorePropertiesJDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(KeyStorePropertiesJDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(KeyStorePropertiesJDialog.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                KeyStorePropertiesJDialog dialog = new KeyStorePropertiesJDialog(new javax.swing.JFrame(), true);
                dialog.addWindowListener(new java.awt.event.WindowAdapter() {
                    @Override
                    public void windowClosing(java.awt.event.WindowEvent e) {
                        System.exit(0);
                    }
                });
                dialog.setVisible(true);
            }
        });
    }
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton changePwButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JTextField keyStorePathTextField;
    private javax.swing.JLabel lastModLabel;
    // End of variables declaration//GEN-END:variables
}
