/*
 * Confirmation.java
 *
 * Created on 11 March 2010, 16:42
 */
package uk.ngs.certwizard.gui;

import java.awt.Toolkit;
import java.net.URL;
import javax.swing.JOptionPane;

import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.PrivateKey;

import uk.ngs.ca.certificate.management.OnLineCertificateInfo;
import uk.ngs.ca.certificate.OnLineUserCertificateReKey;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.certificate.management.CertificateCSRInfo;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.common.EncryptUtil;

/**
 *
 * @author  hyz38924
 */
public class OnLineConfirmation extends javax.swing.JFrame {

//    private String message;
    private String action;
//    private X509Certificate certificate;
    private int INDEX;
    private OnLineCertificateInfo onLineCertInfo;
    private MainWindowPanel mainWindowPanel;

    private CertificateCSRInfo certCSRInfo = null;

    /** Creates new form Confirmation */
    public OnLineConfirmation(MainWindowPanel mainWindowPanel, String action, String message, int index, OnLineCertificateInfo onLineCertInfo) {

        initComponents();
        URL iconURL = OnLineConfirmation.class.getResource("/uk/ngs/ca/images/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        this.getRootPane().setDefaultButton(btnAccept);
        this.action = action;
        this.setTitle(action + " certificate");
        this.jLabel8.setText(message);

        this.mainWindowPanel = mainWindowPanel;
        this.onLineCertInfo = onLineCertInfo;
        onLineCertInfo.addObserver(mainWindowPanel);

        this.INDEX = index;
        this.certCSRInfo = this.onLineCertInfo.getCertCSRInfos()[this.INDEX];
        String _owner = this.certCSRInfo.getOwner();
        String _email = this.certCSRInfo.getUserEmail();
        String _startdate = this.certCSRInfo.getStartDate();
        String _enddate = this.certCSRInfo.getEndDate();
        String _status = this.certCSRInfo.getStatus();

        this.dn.setText(_owner);
        this.email.setText(_email);
        this.vFrom.setText(_startdate);
        this.vTo.setText(_enddate);
        this.status.setText(_status);
        this.btnAccept.setText(action);
        this.txtRevocationReason.setVisible(false);
        this.lblRevocationReason.setVisible(false);
        this.jScrollPane2.setVisible(false);

        if (this.action.equals("Revoke")) {
            this.lblRevocationReason.setVisible(true);
            this.jScrollPane2.setVisible(true);
            this.txtRevocationReason.setVisible(true);
        }

        if (_status.equals("REVOKED")) {
            this.status.setForeground(new RevokedCertColor());
        } else if (_status.equals("RENEW")) {
            this.status.setForeground(new RenewalDueColor());
        } else if (_status.equals("VALID")) {
            this.status.setForeground(new ValidCertColor());
        } else {
            this.status.setForeground(new PendingColor());
        }

    }

    private boolean isPing(){
        //PingService pingService = new PingService();
        //return pingService.isPingService();
        return PingService.getPingService().isPingService();
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jLabel4 = new javax.swing.JLabel();
        pnlAllDetails = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        vFrom = new javax.swing.JTextField();
        email = new javax.swing.JTextField();
        dn = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        vTo = new javax.swing.JTextField();
        jLabel7 = new javax.swing.JLabel();
        status = new javax.swing.JTextField();
        btnAccept = new javax.swing.JButton();
        btnCancel = new javax.swing.JButton();
        jLabel8 = new javax.swing.JLabel();
        lblRevocationReason = new javax.swing.JLabel();
        jScrollPane2 = new javax.swing.JScrollPane();
        txtRevocationReason = new javax.swing.JTextArea();

        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jTextArea1.setMaximumSize(new java.awt.Dimension(4, 18));
        jScrollPane1.setViewportView(jTextArea1);

        jLabel4.setText("jLabel4");

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Renew certificate");
        setResizable(false);

        pnlAllDetails.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        jLabel1.setText("DN:");

        jLabel2.setText("Email:");

        jLabel3.setText("Valid From:");

        vFrom.setEditable(false);

        email.setEditable(false);

        dn.setEditable(false);
        dn.setHorizontalAlignment(javax.swing.JTextField.LEFT);
        dn.setAutoscrolls(false);
        dn.setMaximumSize(new java.awt.Dimension(6, 20));

        jLabel5.setText("Valid To:");

        vTo.setEditable(false);

        jLabel7.setText("Status:");

        status.setEditable(false);

        org.jdesktop.layout.GroupLayout pnlAllDetailsLayout = new org.jdesktop.layout.GroupLayout(pnlAllDetails);
        pnlAllDetails.setLayout(pnlAllDetailsLayout);
        pnlAllDetailsLayout.setHorizontalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel2)
                    .add(jLabel1)
                    .add(jLabel7)
                    .add(jLabel3, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 67, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(org.jdesktop.layout.GroupLayout.LEADING, pnlAllDetailsLayout.createSequentialGroup()
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                            .add(org.jdesktop.layout.GroupLayout.LEADING, status)
                            .add(org.jdesktop.layout.GroupLayout.LEADING, vFrom, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 100, Short.MAX_VALUE))
                        .add(18, 18, 18)
                        .add(jLabel5)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(vTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 101, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                    .add(org.jdesktop.layout.GroupLayout.LEADING, email, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 317, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(dn, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 484, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlAllDetailsLayout.setVerticalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel1)
                    .add(dn, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel2)
                    .add(email, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel3)
                    .add(vFrom, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel5)
                    .add(vTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel7)
                    .add(status, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(16, Short.MAX_VALUE))
        );

        btnAccept.setText("Renew");
        btnAccept.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnAcceptActionPerformed(evt);
            }
        });

        btnCancel.setText("Cancel");
        btnCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCancelActionPerformed(evt);
            }
        });

        lblRevocationReason.setText("Reason for revocation: ");

        txtRevocationReason.setColumns(20);
        txtRevocationReason.setRows(5);
        jScrollPane2.setViewportView(txtRevocationReason);

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel8, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 579, Short.MAX_VALUE)
                    .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .add(layout.createSequentialGroup()
                        .add(lblRevocationReason)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jScrollPane2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 461, Short.MAX_VALUE))
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                        .add(btnAccept)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnCancel)))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .add(jLabel8, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 48, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .add(18, 18, 18)
                .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(lblRevocationReason)
                    .add(jScrollPane2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 61, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnCancel)
                    .add(btnAccept))
                .addContainerGap())
        );

        pack();
        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        java.awt.Dimension dialogSize = getSize();
        setLocation((screenSize.width-dialogSize.width)/2,(screenSize.height-dialogSize.height)/2);
    }// </editor-fold>//GEN-END:initComponents

    private void btnAcceptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnAcceptActionPerformed
        // TODO add your handling code here:
            //check if connection is fine.

        String reason = this.txtRevocationReason.getText();
        if (reason.contains("'") || reason.contains(";")) {
            JOptionPane.showMessageDialog(this, "Please do not use characters ' and ; when writing the revocation request.", "Input Error", JOptionPane.INFORMATION_MESSAGE);
            WaitDialog.hideDialog();
            return;
        }

        if (this.action.equals("Renew"))
            WaitDialog.showDialog("Renew");

        if (this.action.equals("Revoke"))
            WaitDialog.showDialog("Revoke");

//        if( !isPing() ){
//            JOptionPane.showMessageDialog(this, "There is a problem connecting with the server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
//            WaitDialog.hideDialog();
//            return;
//        }
        

        if (this.action.equals("Renew")) {
            String _id = this.certCSRInfo.getId();
            CertificateDownload certDownload = new CertificateDownload(_id);
            X509Certificate certificate = certDownload.getCertificate();

            OnLineUserCertificateReKey rekey = this.onLineCertInfo.getOnLineUserCertificateReKey();
            rekey.addCertificate(certificate);

            if (rekey.isValidReKey()) {
                if( rekey.doPosts() ){
                    JOptionPane.showMessageDialog(this, "The renewal request has been submitted", "Renewal request successful", JOptionPane.INFORMATION_MESSAGE);
                    String _notifyMessage = "Renew:" + rekey.getAlias();
                    this.onLineCertInfo.notifyObserver( _notifyMessage );
                } else {
                    String messageTitle = rekey.getErrorMessage();
                    String moreMessage = rekey.getDetailErrorMessage();
                    JOptionPane.showMessageDialog(this, moreMessage, messageTitle, JOptionPane.INFORMATION_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(this, "The selected certificate is not valid to renew", "wrong certificate", JOptionPane.INFORMATION_MESSAGE);
            }
            this.dispose();
        }

        if (this.action.equals("Revoke")) {
            String _id = this.certCSRInfo.getId();
            long cert_id = new Long( _id ).longValue();
            String encodedPublicKey = this.certCSRInfo.getPublickey();
            PublicKey _publicKey = EncryptUtil.getPublicKey(encodedPublicKey);

            ClientKeyStore clientKeyStore = this.onLineCertInfo.getClientKeyStore();
            PrivateKey _privateKey = clientKeyStore.getPrivateKey(_publicKey);

            RevokeRequest revokeRequest = new RevokeRequest(_privateKey, cert_id, reason);
            if (revokeRequest.doPosts()) {
                String message = revokeRequest.getMessage();
                JOptionPane.showMessageDialog(this, message, "Certificate revoked", JOptionPane.INFORMATION_MESSAGE);
                String _notifyMessage = "Revoke:" + encodedPublicKey;
                this.onLineCertInfo.notifyObserver( _notifyMessage );
            } else {
                String message = revokeRequest.getMessage();
                JOptionPane.showMessageDialog(this, message, "Certificate revocation failed", JOptionPane.INFORMATION_MESSAGE);
            }
            this.dispose();

        }
        if (this.action.equals("Remove")) {
            if( this.onLineCertInfo.remove(this.INDEX) ){
                JOptionPane.showMessageDialog(this, "The certificate has now been removed from the CertWizard",
                    "Certificate removed", JOptionPane.INFORMATION_MESSAGE);
                String _notifyMessage = "Remove:" + this.INDEX;
                this.onLineCertInfo.notifyObserver( _notifyMessage );
            }else{
                JOptionPane.showMessageDialog(this, "The certificate failed to remove from the CertWizard",
                    "Certificate remove failed", JOptionPane.INFORMATION_MESSAGE);
            }
            this.dispose();
        }
        if( this.action.equals("Install") ){

        }

        WaitDialog.hideDialog();
    }//GEN-LAST:event_btnAcceptActionPerformed

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        // TODO add your handling code here:
        this.dispose();
    }//GEN-LAST:event_btnCancelActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnAccept;
    private javax.swing.JButton btnCancel;
    private javax.swing.JTextField dn;
    private javax.swing.JTextField email;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JLabel lblRevocationReason;
    private javax.swing.JPanel pnlAllDetails;
    private javax.swing.JTextField status;
    private javax.swing.JTextArea txtRevocationReason;
    private javax.swing.JTextField vFrom;
    private javax.swing.JTextField vTo;
    // End of variables declaration//GEN-END:variables
}
