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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 * Dialog to select or create a writable keyStore directory with the specified
 * name. This usually defaults to '$HOME/dirName' but specific location can vary
 * according to OS.
 *
 * @author David Meredith
 */
public class GetBootstrapDir extends javax.swing.JDialog {

    private String dirName = ".ca";
    private String SELECTED_CA_DIR = "<html>Open this keyStore folder&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OR<br/>"
            + "Browse for another keyStore folder</html>";
    private String SELECTED_PAR_DIR = "<html>Create a new '" + dirName + "' keyStore folder in selected folder&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;OR<br/>"
            + "Browse for your keyStore folder</html>";
    private Path bootDir;

    /**
     * Create a new dialog instance.
     *
     * @param parent
     * @param modal
     * @param dirName Search for a folder with this name in the default OS HOME
     * locations (varies according to OS).
     */
    public GetBootstrapDir(java.awt.Frame parent, boolean modal, String dirName) {
        super(parent, modal);
        initComponents();
        if (dirName == null) {
            throw new RuntimeException("Invalid dirName, must have a value");
        }
        this.dirName = dirName;
        initMyComponents();
    }

    private void initMyComponents() {
        Path dir = this.getDefaultBootDir();
        this.bootDir = dir;
        this.jTextField1.setText(dir.toString());
        this.setLabelText();
        this.setTitle("Select CertWizard keyStore folder");
    }

    private void setLabelText() {
        if (this.bootDir != null) {
            if (this.bootDir.endsWith(this.dirName)) {
                this.jLabel1.setText(SELECTED_CA_DIR);
            } else {
                this.jLabel1.setText(SELECTED_PAR_DIR);
            }
        } else {
            this.jLabel1.setText("Browse for your keyStore folder");
        }
    }

    /**
     * Get the default installation directory. This may be a '.ca' dir or
     * another dir in which the '.ca' dir could be created.
     *
     * @return
     */
    private Path getDefaultBootDir() {
        Path findBootDir = new File(System.getProperty("user.home")).toPath();
        if (Files.isWritable(findBootDir)) {
            // We can access home dir, so lets see if previous installation exists 
            Path caDir = Paths.get(findBootDir.toString(), this.dirName);
            if (Files.isDirectory(caDir) && Files.isWritable(caDir)) {
                findBootDir = caDir;
            }
        } else {
            // Dont have access to 'user.home' - prob due to the known un-fixed java bug:  
            // http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4787931 
            // However, before asking the user to select an alternative folder 
            // first check to see if the JFileChooser will automatically select 
            // another home dir (e.g. on Win its USERPROFILE) and test to see if 
            // USERPROFILE/.ca already exists 
            JFileChooser jf = new JFileChooser(); // does not necessarily use 'user.home'
            jf.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
            findBootDir = jf.getCurrentDirectory().toPath();
            if (Files.isWritable(findBootDir)) {
                // We can access home dir, so lets see if previous installation exists
                Path caDir = Paths.get(findBootDir.toString(), this.dirName);
                if (Files.isDirectory(caDir) && Files.isWritable(caDir)) {
                    findBootDir = caDir;
                }
            }
        }
        return findBootDir;
    }

    /**
     * Get the current writable directory value. This could be a folder with the
     * specified dirName but this is not guaranteed.
     *
     * @return
     */
    public Path getBootDir() {
        return this.bootDir;
    }

    private boolean setCaDir(Path dir) {
        if (!Files.isDirectory(dir)) {
            JOptionPane.showMessageDialog(this, "Selected file is not a folder."
                    + "Please select a writable folder.", "Folder Selection Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        if (!Files.isWritable(dir)) {
            JOptionPane.showMessageDialog(this, "Cannot write to selected folder."
                    + "Please select a writable folder.", "Folder Selection Error", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        // We have a writable directory but not a .ca dir  
        if (!dir.endsWith(this.dirName)) {
            // check to see that a .ca sub-dir does not already exist 
            dir = Paths.get(dir.toString(), this.dirName);
            if (Files.isDirectory(dir) && Files.isWritable(dir)) {
                // Confirm selection dialog and return true if confirmed
                int retval = JOptionPane.showConfirmDialog(this, "Open the following keyStore folder?\n"
                        + dir.toString(), "Confirm", JOptionPane.INFORMATION_MESSAGE);
                if (retval == JOptionPane.OK_OPTION) {
                    this.bootDir = dir;
                    return true;
                }
            } else if (!Files.exists(dir)) {
                // Confirm creation of the .ca dir and return true if confirmed/created    
                int retval = JOptionPane.showConfirmDialog(this, "Create '" + this.dirName + "' keyStore folder in this directory?",
                        "Confirm", JOptionPane.INFORMATION_MESSAGE);
                if (retval == JOptionPane.OK_OPTION) {
                    try {
                        this.bootDir = Files.createDirectory(dir);
                        return true;
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(this, "Could not create '" + this.dirName + "' keyStore folder: " + ex.getMessage(),
                                "Folder Creation Error", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        } // We have a writable .ca dir 
        else {
            return true;
        }
        return false;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jTextField1 = new javax.swing.JTextField();
        browseButton = new javax.swing.JButton();
        okButton = new javax.swing.JButton();
        jLabel1 = new javax.swing.JLabel();
        cancelButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DO_NOTHING_ON_CLOSE);

        jTextField1.setEditable(false);

        browseButton.setText("Browse");
        browseButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                browseButtonActionPerformed(evt);
            }
        });

        okButton.setText("Ok");
        okButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                okButtonActionPerformed(evt);
            }
        });

        jLabel1.setText("jLabel1");

        cancelButton.setText("Cancel");
        cancelButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                cancelButtonActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jTextField1, javax.swing.GroupLayout.DEFAULT_SIZE, 422, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(browseButton))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addGap(0, 0, Short.MAX_VALUE)
                        .addComponent(cancelButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(okButton))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 63, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(browseButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(okButton)
                    .addComponent(cancelButton))
                .addGap(8, 8, 8))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void browseButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_browseButtonActionPerformed
        JFileChooser jf = new JFileChooser(); // does not necessarily use 'user.home'
        jf.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        jf.setFileHidingEnabled(false);
        jf.setDialogTitle("Select folder");
        int returnVal = jf.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            Path dir = jf.getSelectedFile().toPath();
            this.bootDir = dir;
            this.setLabelText();
            this.jTextField1.setText(bootDir.toString());
        }
    }//GEN-LAST:event_browseButtonActionPerformed

    private void okButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_okButtonActionPerformed
        if (this.setCaDir(this.bootDir)) {
            // If setCaDir returns true - a writable '.ca' dir was selected/created 
            // so hide this dialog. 
            this.setVisible(false);
        }
    }//GEN-LAST:event_okButtonActionPerformed

    private void cancelButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_cancelButtonActionPerformed
        int retval = JOptionPane.showConfirmDialog(this, "Are you sure you want to quit CertWizard?",
                "Quit CertWizard", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if (retval == JOptionPane.YES_OPTION) {
            this.bootDir = null;
            this.dispose();
        }
    }//GEN-LAST:event_cancelButtonActionPerformed

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
            java.util.logging.Logger.getLogger(GetBootstrapDir.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(GetBootstrapDir.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(GetBootstrapDir.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(GetBootstrapDir.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the dialog */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                GetBootstrapDir dialog = new GetBootstrapDir(new javax.swing.JFrame(), true, ".ca");
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
    private javax.swing.JButton browseButton;
    private javax.swing.JButton cancelButton;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JTextField jTextField1;
    private javax.swing.JButton okButton;
    // End of variables declaration//GEN-END:variables
}
