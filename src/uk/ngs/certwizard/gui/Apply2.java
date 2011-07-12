/*
 * Apply.java
 *
 * Created on 05-Mar-2010, 15:11:52
 */
package uk.ngs.certwizard.gui;

import javax.swing.JOptionPane;
import java.awt.Color;
import java.awt.Toolkit;
import java.net.URL;
import java.util.Observer;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

import uk.ngs.ca.info.CAInfo;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.certificate.OffLineUserCertificateRequest;
import uk.ngs.ca.certificate.OnLineUserCertificateRequest;
import uk.ngs.ca.common.MyPattern;
import uk.ngs.ca.certificate.client.PingService;
//import uk.ngs.ca.certificate.client.PingService;

/**
 *
 * @author kjm22495
 */
public class Apply2 extends javax.swing.JDialog {

    private final String mainInfo = "Please enter all the information";
    private final String readyInfo = "Your input is ready, please click Apply button to request certificate or click Cancel button to cancel";
    private OnLineUserCertificateRequest onLineCertRequest = null;
    private String[] RAs;

    private final Pattern emailPattern = Pattern.compile("[-\\.a-zA-Z0-9_]+@[-a-zA-Z0-9\\.]+\\.[a-z]+");
    private boolean onlineCSRCompletedOK = false;
    private Observer observer;

    /** Creates new form Apply */
    public Apply2(Observer observer, char[] passphrase) {
        initComponents();
        this.observer = observer;

        onLineCertRequest = new OnLineUserCertificateRequest(passphrase);
        //onLineCertRequest.addObserver(mainWindowPanel);
        CAInfo caInfo = new CAInfo();
        RAs = caInfo.getRAs();

        javax.swing.DefaultComboBoxModel m = new javax.swing.DefaultComboBoxModel(RAs);
        cmbSelectRA.setModel(m);

        URL iconURL = Apply2.class.getResource("/uk/ngs/ca/images/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        this.getRootPane().setDefaultButton(btnApply);
        setInformation(mainInfo);
        jLabel6.setVisible(false);
    }

    /**
     * @return true if the last online CSR completed ok, otherwise return false.
     */
    public boolean getLastCSRCompletedOK(){
        return this.onlineCSRCompletedOK;
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        cmbSelectRA = new javax.swing.JComboBox();
        jLabel1 = new javax.swing.JLabel();
        txtName = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        txtEmail = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        btnApply = new javax.swing.JButton();
        btnCancel = new javax.swing.JButton();
        txtPin = new javax.swing.JPasswordField();
        txtConfirm = new javax.swing.JPasswordField();
        jLabel6 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        jLabel5 = new javax.swing.JTextArea();
        jLabel7 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Apply for certificate");
        setName("Form"); // NOI18N
        setResizable(false);

        cmbSelectRA.setName("cmbSelectRA"); // NOI18N
        cmbSelectRA.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                cmbSelectRAMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                cmbSelectRAMouseExited(evt);
            }
        });

        jLabel1.setText("Name (firstname lastname)");
        jLabel1.setName("jLabel1"); // NOI18N

        txtName.setName("txtName"); // NOI18N
        txtName.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtNameMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtNameMouseExited(evt);
            }
        });

        jLabel2.setText("Email Address");
        jLabel2.setName("jLabel2"); // NOI18N

        txtEmail.setName("txtEmail"); // NOI18N
        txtEmail.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtEmailMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtEmailMouseExited(evt);
            }
        });

        jLabel3.setText("PIN");
        jLabel3.setName("jLabel3"); // NOI18N

        jLabel4.setText("Confirm PIN");
        jLabel4.setName("jLabel4"); // NOI18N

        btnApply.setText("Apply");
        btnApply.setEnabled(false);
        btnApply.setName("btnApply"); // NOI18N
        btnApply.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnApplyActionPerformed(evt);
            }
        });

        btnCancel.setText("Cancel");
        btnCancel.setName("btnCancel"); // NOI18N
        btnCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCancelActionPerformed(evt);
            }
        });

        txtPin.setName("txtPin"); // NOI18N
        txtPin.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtPinMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtPinMouseExited(evt);
            }
        });
        txtPin.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                txtPinActionPerformed(evt);
            }
        });
        txtPin.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                txtPinFocusGained(evt);
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                txtPinFocusLost(evt);
            }
        });

        txtConfirm.setName("txtConfirm"); // NOI18N
        txtConfirm.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtConfirmMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtConfirmMouseExited(evt);
            }
        });
        txtConfirm.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyReleased(java.awt.event.KeyEvent evt) {
                txtConfirmKeyReleased(evt);
            }
            public void keyTyped(java.awt.event.KeyEvent evt) {
                txtConfirmKeyTyped(evt);
            }
        });

        jLabel6.setText("10 characters min.");
        jLabel6.setName("jLabel6"); // NOI18N

        jScrollPane1.setName("jScrollPane1"); // NOI18N

        jLabel5.setBackground(javax.swing.UIManager.getDefaults().getColor("Label.background"));
        jLabel5.setColumns(20);
        jLabel5.setLineWrap(true);
        jLabel5.setRows(5);
        jLabel5.setText("Please enter all information");
        jLabel5.setWrapStyleWord(true);
        jLabel5.setCaretColor(new java.awt.Color(255, 51, 51));
        jLabel5.setName("jLabel5"); // NOI18N
        jScrollPane1.setViewportView(jLabel5);

        jLabel7.setText("Registration Authority");
        jLabel7.setName("jLabel7"); // NOI18N

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                        .add(jScrollPane1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 350, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .add(34, 34, 34))
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                        .add(btnApply)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnCancel)
                        .addContainerGap())
                    .add(layout.createSequentialGroup()
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(jLabel3)
                            .add(jLabel4)
                            .add(jLabel7)
                            .add(jLabel1)
                            .add(jLabel2))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(layout.createSequentialGroup()
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                                    .add(org.jdesktop.layout.GroupLayout.LEADING, txtConfirm)
                                    .add(org.jdesktop.layout.GroupLayout.LEADING, txtPin, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 104, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                .add(18, 18, 18)
                                .add(jLabel6))
                            .add(txtName, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 267, Short.MAX_VALUE)
                            .add(txtEmail, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 267, Short.MAX_VALUE)
                            .add(cmbSelectRA, 0, 267, Short.MAX_VALUE))
                        .addContainerGap())))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .add(21, 21, 21)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(cmbSelectRA, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel7))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(txtName, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel1))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(txtEmail, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel2))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel3)
                    .add(txtPin, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel6))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel4)
                    .add(txtConfirm, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .add(35, 35, 35)
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnCancel)
                    .add(btnApply))
                .addContainerGap(23, Short.MAX_VALUE))
        );

        pack();
        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        java.awt.Dimension dialogSize = getSize();
        setLocation((screenSize.width-dialogSize.width)/2,(screenSize.height-dialogSize.height)/2);
    }// </editor-fold>//GEN-END:initComponents

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        this.dispose();
    }//GEN-LAST:event_btnCancelActionPerformed

    /*private boolean isPing(){
        //PingService pingService = new PingService();
        //return pingService.isPingService();
        return PingService.getPingService().isPingService();
    }*/

    private void btnApplyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnApplyActionPerformed
        this.onlineCSRCompletedOK = false;
        //WaitDialog.showDialog("Apply");
        boolean complete = true;
        String text = "";
        String myCN = "";

        if (this.txtName.getText().isEmpty()) {
            complete = false;
            text = text + "\nEnter your given name and surname";
        }

        MyPattern pattern = new MyPattern();
        if( pattern.isValidCN( this.txtName.getText() ) ){
            myCN = pattern.getCN();
        }else{
            complete = false;
            text = text + "\n" + pattern.getErrorMessage();
        }


        if (this.txtEmail.getText().isEmpty()) {
            complete = false;
            text = text + "\nEnter your email";
        }

        if (this.txtPin.getPassword().length == 0) {
            complete = false;
            text = text + "\nEnter a PIN";
        }

        if (this.txtConfirm.getPassword().length == 0) {
            complete = false;
            text = text + "\nEnter the PIN again for confirmation";
        }

        if (!complete) {
            jLabel5.setForeground(Color.RED);
            setInformation(text);
        } else {
                //The following checks if the CA Database as well as the CA Server is up or not.
//                if( !isPing() ){
//                    JOptionPane.showMessageDialog(this, "There is a problem connecting with the server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
//                    WaitDialog.hideDialog();
//                    this.dispose();
//                    return;
//                }
                onLineCertRequest.setEmail(this.txtEmail.getText());
                onLineCertRequest.setName(myCN);
                onLineCertRequest.setPIN1(new String(this.txtPin.getPassword()));
                onLineCertRequest.setPIN2(new String(this.txtConfirm.getPassword()));
                onLineCertRequest.setRA((String) this.cmbSelectRA.getSelectedItem());

                String messageTitle;
                if( ! isValidCN( this.txtName.getText() )){
                    messageTitle = "Input problem";
                    JOptionPane.showMessageDialog(this, "Your name input should be \"Firstname Lastname\", please try again.", messageTitle, JOptionPane.INFORMATION_MESSAGE);
                }else if( ! isValidEmail( this.txtEmail.getText() )){
                    messageTitle = "Input problem";
                    JOptionPane.showMessageDialog(this, "Your email input is not valid. "
                            + "\nIt should not contain special characters ' and ;"
                            + "\nPlease also ensure that it is in the form of name.surname@example.com or similar"
                            + "\nPlease try again.", messageTitle, JOptionPane.INFORMATION_MESSAGE);
                }else{
                    System.out.println("doing online CSR now");
                    this.onlineCSRCompletedOK = onLineCertRequest.doOnLineCSR();
                    if (onlineCSRCompletedOK) {
                        messageTitle = "Request Successful";
                        //notify mainwindow only success.
                        //onLineCertRequest.notifyObserver();
                        if(this.observer != null){
                           this.observer.update(null, this);
                        }
                        JOptionPane.showMessageDialog(this, onLineCertRequest.getMessage(), messageTitle, JOptionPane.INFORMATION_MESSAGE);
                        this.dispose();
                    } else {
                        messageTitle = "Request UnSuccessful";
                        this.onlineCSRCompletedOK = false;
                        System.out.println(onLineCertRequest.getMessage());
                        JOptionPane.showMessageDialog(this, onLineCertRequest.getMessage(), messageTitle, JOptionPane.INFORMATION_MESSAGE);
                    }
                }
        }
        //WaitDialog.hideDialog();
    }//GEN-LAST:event_btnApplyActionPerformed

    private boolean isValidEmail(String email) {
        Matcher m = this.emailPattern.matcher(email);
        return m.matches();
    }

    private boolean isValidCN(String cn) {
        cn = cn.trim();
        int index = cn.indexOf(" ");
        if (index == -1) {
            return false;
        } else {
            return true;
        }
    }

    private void txtConfirmKeyTyped(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtConfirmKeyTyped
        // TODO add your handling code here:
    }//GEN-LAST:event_txtConfirmKeyTyped

    private void txtConfirmKeyReleased(java.awt.event.KeyEvent evt) {//GEN-FIRST:event_txtConfirmKeyReleased
        // TODO add your handling code here:
        String pin = new String(txtPin.getPassword());
        String confirm = new String(txtConfirm.getPassword());
        if (pin.equals(confirm)) {
            this.btnApply.setEnabled(true);
            jLabel5.setForeground(Color.BLACK);
            setInformation(mainInfo);
        } else {
            this.btnApply.setEnabled(false);
            jLabel5.setForeground(Color.red);
            setInformation("Your pin and confirmation must match");
        }
    }//GEN-LAST:event_txtConfirmKeyReleased

    private boolean isInputReady(){
        boolean isReady = true;
        String pin = new String(txtPin.getPassword());
        String confirm = new String(txtConfirm.getPassword());
        if( ! pin.equals(confirm)){
            isReady = false;
        }
        if (this.txtName.getText().isEmpty()) {
            isReady = false;
        }
        if (this.txtEmail.getText().isEmpty()) {
            isReady = false;
        }
        if (this.txtPin.getPassword().length == 0) {
            isReady = false;
        }
        if (this.txtConfirm.getPassword().length == 0) {
            isReady = false;
        }
        return isReady;
    }

    private void txtPinFocusGained(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtPinFocusGained
        jLabel6.setVisible(true);
    }//GEN-LAST:event_txtPinFocusGained

    private void cmbSelectRAMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_cmbSelectRAMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please select your local RA");
    }//GEN-LAST:event_cmbSelectRAMouseEntered

    private void cmbSelectRAMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_cmbSelectRAMouseExited
        if( isInputReady() ){
            setInformation( this.readyInfo );
        }else{
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_cmbSelectRAMouseExited

    private void txtNameMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtNameMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please enter your name.");
    }//GEN-LAST:event_txtNameMouseEntered

    private void txtNameMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtNameMouseExited
        if( isInputReady() ){
            setInformation( this.readyInfo );
        }else{
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_txtNameMouseExited

    private void txtEmailMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtEmailMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please enter a valid email address. This will be used to " +
                "send you information regarding your certificate.");
    }//GEN-LAST:event_txtEmailMouseEntered

    private void txtEmailMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtEmailMouseExited
        if( isInputReady() ){
            setInformation( this.readyInfo );
        }else{
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_txtEmailMouseExited

    private void txtPinMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtPinMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please enter a 10 character pin to help identify " +
                "yourself to an RA Operator");
    }//GEN-LAST:event_txtPinMouseEntered

    private void txtPinMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtPinMouseExited
        if( isInputReady() ){
            setInformation( this.readyInfo );
        }else{
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_txtPinMouseExited

    private void txtPinFocusLost(java.awt.event.FocusEvent evt) {//GEN-FIRST:event_txtPinFocusLost
        jLabel6.setVisible(false);
    }//GEN-LAST:event_txtPinFocusLost

    private void txtConfirmMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtConfirmMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please enter your pin again for confirmation");
    }//GEN-LAST:event_txtConfirmMouseEntered

    private void txtConfirmMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtConfirmMouseExited
        if( isInputReady() ){
            setInformation( this.readyInfo );
        }else{
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_txtConfirmMouseExited

    private void txtPinActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtPinActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtPinActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton btnApply;
    private javax.swing.JButton btnCancel;
    private javax.swing.JComboBox cmbSelectRA;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JTextArea jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JPasswordField txtConfirm;
    private javax.swing.JTextField txtEmail;
    private javax.swing.JTextField txtName;
    private javax.swing.JPasswordField txtPin;
    // End of variables declaration//GEN-END:variables
   

    private void setInformation(String text) {
        jLabel5.setText(text);
    }
}
