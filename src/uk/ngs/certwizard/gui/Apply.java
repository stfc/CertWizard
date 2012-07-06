/*
 * Apply.java
 *
 * Created on 05-Mar-2010, 15:11:52
 */
package uk.ngs.certwizard.gui;

import java.awt.Color;
import java.awt.Toolkit;
import java.io.IOException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JOptionPane;
import net.sf.portecle.gui.error.DThrowable;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.EmailValidator;
import uk.ngs.ca.certificate.CertificateRequestCreator;
import uk.ngs.ca.certificate.OnLineUserCertificateRequest;
import uk.ngs.ca.certificate.OnlineHostCertRequest;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.CAKeyPair;
import uk.ngs.ca.common.MyPattern;
import uk.ngs.ca.common.Pair;
import uk.ngs.ca.info.CAInfo;

/**
 * Modal dialog for requesting new host and user certificates.
 *
 * @author kjm22495
 * @author Xiao Wang
 * @author David Meredith (modifications, javadoc)
 */
public class Apply extends javax.swing.JDialog {

    private final String mainInfo = "Please enter all the information";
    private final String readyInfo = "Your input is ready, please click Apply button to request certificate or click Cancel button to cancel";
    private String[] RAs;
    //private final Pattern emailPattern = Pattern.compile("[-\\.a-zA-Z0-9_]+@[-a-zA-Z0-9\\.]+\\.[a-z]+");
    private char[] passphrase;
    private String storedAlias;
    
    private final X509Certificate authCert;
    private final PrivateKey authKey; 
    
    
    /**
     * Options for the type of certificate application.
     */
    public static enum CERT_TYPE {

        HOST_CERT, USER_CERT
    };
    private CERT_TYPE certType = CERT_TYPE.USER_CERT;

    /**
     * Create a new Apply dialog. 
     * 
     * @param passphrase used to unlock/get an instance of {@link ClientKeyStoreCaServiceWrapper}
     * @param certType Apply for either host or user cert 
     * @param keyStoreAliasToAuthHostApply If a host cert is requested, this is the alias of the 
     * keyStore entry that will be used to authenticate the request. Can be null for 
     * user cert requests. When requesting host cert, if this value 
     * does not reference a valid user certificate in the keyStore, then a 
     * {@link IllegalArgumentException} is thrown. 
     * @throws IOException If an error occurs when contact the remote server. 
     */
    public Apply(char[] passphrase, CERT_TYPE certType, String keyStoreAliasToAuthHostApply) throws IOException, KeyStoreException {
        this.passphrase = passphrase;
        this.certType = certType;
        initComponents();
        
        if(CERT_TYPE.HOST_CERT.equals(this.certType)){
            if(keyStoreAliasToAuthHostApply == null || keyStoreAliasToAuthHostApply.trim().equals("")){
                throw new IllegalArgumentException("Invaild keyStore alias"); 
            }
            ClientKeyStoreCaServiceWrapper model = ClientKeyStoreCaServiceWrapper.getInstance(passphrase);
            this.authCert = model.getClientKeyStore().getX509Certificate(keyStoreAliasToAuthHostApply);
            if(this.authCert == null){
                throw new IllegalArgumentException("Invaild keyStore alias - given alias does not refer to X509Certificate");  
            }
            this.authKey = model.getClientKeyStore().getPrivateKey(authCert.getPublicKey()); 
            
        } else {
           this.authCert = null; 
           this.authKey = null; 
        }
       

        CAInfo caInfo = new CAInfo();
        RAs = caInfo.getRAs(); // concat of: "OU+" "+L"
        javax.swing.DefaultComboBoxModel m = new javax.swing.DefaultComboBoxModel(RAs);
        cmbSelectRA.setModel(m);

        URL iconURL = Apply.class.getResource("/uk/ngs/ca/images/ngs-icon.png");
        if (iconURL != null) {
            this.setIconImage(Toolkit.getDefaultToolkit().getImage(iconURL));
        }
        this.getRootPane().setDefaultButton(btnApply);
        setInformation(mainInfo);
        jLabel6.setVisible(false); //hide 10 chars min label 

        if (CERT_TYPE.HOST_CERT.equals(this.certType)) {
            this.labEmail.setText("Host Admin Email");
            this.labCN.setText("Host (DNS) name");
            this.setTitle("Host Certificate Application"); 
            this.txtDN.setText(authCert.getSubjectX500Principal().getName()); 
        } else {
            this.labEmail.setText("User Email");
            this.labCN.setText("Name (firstname lastname)");
            this.setTitle("User Certificate Application"); 
            this.txtDN.setText("N/A"); 
        }
    }

    /**
     * Process the user pressing the Apply button.
     */
    private void doApplyButton() {
        boolean complete = true;
        String text = "";
        ClientKeyStoreCaServiceWrapper model = ClientKeyStoreCaServiceWrapper.getInstance(passphrase);

        if (this.txtName.getText().isEmpty()) {
            complete = false;
            if (CERT_TYPE.USER_CERT.equals(this.certType)) {
                text = text + "\nEnter your given name and surname";
            } else {
                text = text + "\nEnter the host DNS name, e.g. 'myhost.ngs.ac.uk'";
            }
        }

        if (CERT_TYPE.USER_CERT.equals(this.certType)) {
            MyPattern pattern = new MyPattern();
            if (pattern.isValidCN(this.txtName.getText())) {
                // do nothing 
            } else {
                complete = false;
                text = text + "\nYour name input should be \"Firstname Lastname\", please try again.";
            }
        } else {
            if (DomainValidator.getInstance().isValid(this.txtName.getText())) {
                // TODO: may have to cope with 'service/host.domain.ac.uk' 
                // do nothing 
            } else {
                complete = false;
                text = text + "\nInvalid host DNS name.";
            }
        }

        if (this.aliasTextField.getText().isEmpty()) {
            complete = false;
            text = text + "\nEnter an alias (this is just a user friendly name)";
        }

        // test to see if alias is already present
        try {
            if (model.getClientKeyStore().containsAlias(this.aliasTextField.getText())) {
                complete = false;
                text = text + "\nAlias already exits - please enter another alias";
            }
        } catch (KeyStoreException ex) {
            DThrowable.showAndWait(this, "Problem checking if alias already exists", ex);
            return;
        }

        //if (!isValidEmail(this.txtEmail.getText())) {
        if (!EmailValidator.getInstance().isValid(this.txtEmail.getText())) {
            complete = false;
            if (CERT_TYPE.USER_CERT.equals(this.certType)) {
                text = text + "\nInvalid contact email";
            } else {
                text = text + "\nInvalid contact email for the host admin";
            }
        }

        if (this.txtPin.getPassword().length == 0) {
            complete = false;
            text = text + "\nEnter a PIN";
        }
        if (this.txtConfirm.getPassword().length == 0) {
            complete = false;
            text = text + "\nEnter the PIN again for confirmation";
        }
        if(!String.valueOf(this.txtPin.getPassword()).equals(String.valueOf(this.txtConfirm.getPassword())) ){
            complete = false; 
            text = text + "\nPIN numbers do not match"; 
        }

        String testRA = (String) this.cmbSelectRA.getSelectedItem(); 
        if(testRA == null || testRA.trim().length() ==0){
            complete = false; 
            text = text + "\nInvalid RA selection"; 
        } else {
            String[] ou_l = testRA.trim().split("[,\\s]+"); 
            if(ou_l.length != 2){
               complete = false; 
               text = text + "\nInvalid RA selection. Please contact support@grid-support.ac.uk and report this problem";  
            }
        }
        
        if (!complete) {
            jLabel5.setForeground(Color.RED);
            setInformation(text);

        } else {
            if (!(PingService.getPingService().isPingService())) {
                JOptionPane.showMessageDialog(this, "Cannot connect to the CA Server. Please ensure that you are connected to the Internet.\n"
                        + "If you are connected to the Internet but still unable to connect to the CA Server, please check your firewall\n"
                        + "settings and ensure you allow Java to access to the Internet. If problem still persists, please contact\n"
                        + "the helpdesk at support@grid-support.ac.uk.", "Server Connection Fault", JOptionPane.ERROR_MESSAGE);
                return;
            }
            if (CERT_TYPE.USER_CERT.equals(this.certType)) {
                this.processUserCertApplication(model);
            } else {
                try {
                   this.processHostCertApplication(model);  
                } catch(KeyStoreException ex){
                    DThrowable.showAndWait(this, "Problem Host CSR", ex);
                }
            }
        }
    } 
  
    private void processUserCertApplication(ClientKeyStoreCaServiceWrapper model) {
        OnLineUserCertificateRequest onLineCertRequest = new OnLineUserCertificateRequest(passphrase);
        onLineCertRequest.setEmail(this.txtEmail.getText());
        onLineCertRequest.setName(this.txtName.getText());
        onLineCertRequest.setPIN1(new String(this.txtPin.getPassword()));
        onLineCertRequest.setPIN2(new String(this.txtConfirm.getPassword()));
        onLineCertRequest.setRA((String) this.cmbSelectRA.getSelectedItem());
        onLineCertRequest.setAlias(this.aliasTextField.getText());
        WaitDialog.showDialog("Apply");
        boolean problem = true;
        try {
            // creates a new keypair for the CSR (does not reStore the keystore file) 
            this.storedAlias = onLineCertRequest.doOnLineCsrUpdateKeyStore();
            WaitDialog.hideDialog();
            if (this.storedAlias != null) {
                model.getClientKeyStore().reStore();
                JOptionPane.showMessageDialog(this, onLineCertRequest.getMessage(), "Request Successful", JOptionPane.INFORMATION_MESSAGE);
                problem = false;
            }
        } catch (Exception ex) {
            WaitDialog.hideDialog();
            DThrowable.showAndWait(this, "Problem Applying for Certificate", ex);
        }

        if (!problem) {
            WaitDialog.hideDialog();
            this.dispose(); // only dispose if successful 

        } else {
            try {
                //need to clear up the CSR if created in the keyStore
                if (this.storedAlias != null && model.getClientKeyStore().containsAlias(this.storedAlias)) {
                    model.deleteEntry(this.storedAlias);
                    model.getClientKeyStore().reStore();
                }
            } catch (KeyStoreException ex) {
                Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showMessageDialog(this, "Unable to clear up failed KeyStore CSR entry. Please contact helpdesk and quote this message! " + ex.getMessage(), "Unable to clear up CSR request", JOptionPane.ERROR_MESSAGE);
            }
            // reset the alias to null so the calling client can detect success for failure. 
            this.storedAlias = null; 
            JOptionPane.showMessageDialog(this, onLineCertRequest.getMessage(), "Request UnSuccessful", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    
    private void processHostCertApplication(ClientKeyStoreCaServiceWrapper model) throws KeyStoreException  {
        String newHostAlias = this.aliasTextField.getText(); 
        String CN = this.txtName.getText(); 
        String email = this.txtEmail.getText(); 
        char[] pin = this.txtPin.getPassword(); 
        String RA =  ((String)this.cmbSelectRA.getSelectedItem()); 
        String[] ou_l = RA.trim().split("[,\\s]+");   
        String OU = ou_l[0]; 
        String L = ou_l[1];
        
        // Create a new key pair for new host cert 
        KeyPair keyPair = CAKeyPair.getNewKeyPair();
        PublicKey csrPublicKey = keyPair.getPublic();  
        PrivateKey csrPrivateKey = keyPair.getPrivate(); 
        
        // Create a PKCS#10 CSR string from keys and DN info  
        CertificateRequestCreator csrCreator = new CertificateRequestCreator(
                CertificateRequestCreator.TYPE.HOST, CN, OU, L, email);
        String pkcs10 = csrCreator.createCertificateRequest(csrPrivateKey, csrPublicKey);
        
        // Send PKCS#10 CSR to server. Provide authCert/Key for PPPK . 
        OnlineHostCertRequest onlineHostCertReq = new OnlineHostCertRequest(
                authCert, authKey, String.valueOf(pin), email, pkcs10);
        Pair<Boolean, String> result = onlineHostCertReq.doHostCSR();
        
        // If submitted ok, save a new self-signed cert in the keyStore and ReStore. 
        if (result.first) {
            X509Certificate cert = CAKeyPair.createSelfSignedCertificate(keyPair, OU, L, CN);
            X509Certificate[] certs = {cert};

            // First - attempt to reStore the keystore 
            model.getClientKeyStore().setKeyEntry(newHostAlias, csrPrivateKey, passphrase, certs);
            model.getClientKeyStore().reStore();
            // Second - add the new entry to the model map
            KeyStoreEntryWrapper newCsrEntry = model.createKSEntryWrapperInstanceFromEntry(newHostAlias);
            model.getKeyStoreEntryMap().put(newHostAlias, newCsrEntry);
            // Third - update this.storedAlias so that calling code can 
            // determine if request was successful or not. 
            this.storedAlias = newHostAlias;
            GeneralMessageDialog.showAndWait(this, "Host Request Successful", "Request Successful", JOptionPane.INFORMATION_MESSAGE);
            this.dispose(); 
        } else {
            GeneralMessageDialog.showAndWait(this, "Server responded an error: " + result.second, "Host CSR Error", JOptionPane.ERROR_MESSAGE);
        }
    }
    
    
    
    
    /**
     * @return If the application was successful, return the alias of the CSR 
     * that is newly stored in the keyStore, otherwise return null. 
     */
    public String getStoredAlias() {
        return this.storedAlias;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jDesktopPane1 = new javax.swing.JDesktopPane();
        cmbSelectRA = new javax.swing.JComboBox();
        labCN = new javax.swing.JLabel();
        txtName = new javax.swing.JTextField();
        labEmail = new javax.swing.JLabel();
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
        jLabel8 = new javax.swing.JLabel();
        aliasTextField = new javax.swing.JTextField();
        labelRequestorId = new javax.swing.JLabel();
        txtDN = new javax.swing.JTextField();

        jDesktopPane1.setName("jDesktopPane1");

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

        labCN.setText("Common Name");
        labCN.setName("labCN"); // NOI18N

        txtName.setName("txtName"); // NOI18N
        txtName.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                txtNameMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                txtNameMouseExited(evt);
            }
        });

        labEmail.setText("Email Address");
        labEmail.setName("labEmail"); // NOI18N

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

        jLabel8.setText("Alias (user friendly name)");
        jLabel8.setName("jLabel8"); // NOI18N

        aliasTextField.setName("aliasTextField"); // NOI18N
        aliasTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                aliasTextFieldActionPerformed(evt);
            }
        });

        labelRequestorId.setText("Requestor Identitiy");
        labelRequestorId.setName("labelRequestorId");

        txtDN.setEditable(false);
        txtDN.setName("txtDN");

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                        .add(btnApply)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnCancel))
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 617, Short.MAX_VALUE)
                    .add(layout.createSequentialGroup()
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(jLabel3)
                            .add(jLabel4)
                            .add(jLabel7)
                            .add(labCN)
                            .add(labEmail)
                            .add(jLabel8)
                            .add(labelRequestorId))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(layout.createSequentialGroup()
                                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                                    .add(org.jdesktop.layout.GroupLayout.LEADING, txtPin, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 104, Short.MAX_VALUE)
                                    .add(org.jdesktop.layout.GroupLayout.LEADING, txtConfirm)
                                    .add(org.jdesktop.layout.GroupLayout.LEADING, aliasTextField))
                                .add(18, 190, Short.MAX_VALUE)
                                .add(jLabel6))
                            .add(txtName, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 424, Short.MAX_VALUE)
                            .add(txtEmail, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 424, Short.MAX_VALUE)
                            .add(cmbSelectRA, 0, 424, Short.MAX_VALUE)
                            .add(txtDN))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, labelRequestorId)
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, txtDN, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(cmbSelectRA, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel7))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(txtName, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(labCN))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(txtEmail, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(labEmail))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel3)
                    .add(txtPin, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel6))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel4)
                    .add(txtConfirm, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(aliasTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel8))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnCancel)
                    .add(btnApply))
                .addContainerGap())
        );

        pack();
        java.awt.Dimension screenSize = java.awt.Toolkit.getDefaultToolkit().getScreenSize();
        java.awt.Dimension dialogSize = getSize();
        setLocation((screenSize.width-dialogSize.width)/2,(screenSize.height-dialogSize.height)/2);
    }// </editor-fold>//GEN-END:initComponents

    private void btnCancelActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelActionPerformed
        this.dispose();
    }//GEN-LAST:event_btnCancelActionPerformed

    /*
     * private boolean isPing(){ //PingService pingService = new PingService();
     * //return pingService.isPingService(); return
     * PingService.getPingService().isPingService();
    }
     */
    private void btnApplyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnApplyActionPerformed
        // 
        this.doApplyButton();
    }//GEN-LAST:event_btnApplyActionPerformed

    /*
     * private boolean isValidEmail(String email) { if(email == null ||
     * email.trim().equals("")) return false; Matcher m =
     * this.emailPattern.matcher(email); return m.matches();
    }
     */
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

    private boolean isInputReady() {
        boolean isReady = true;
        String pin = new String(txtPin.getPassword());
        String confirm = new String(txtConfirm.getPassword());
        if (!pin.equals(confirm)) {
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
        if (isInputReady()) {
            setInformation(this.readyInfo);
        } else {
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_cmbSelectRAMouseExited

    private void txtNameMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtNameMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please enter your name.");
    }//GEN-LAST:event_txtNameMouseEntered

    private void txtNameMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtNameMouseExited
        if (isInputReady()) {
            setInformation(this.readyInfo);
        } else {
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_txtNameMouseExited

    private void txtEmailMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtEmailMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please enter a valid email address. This will be used to "
                + "send you information regarding your certificate.");
    }//GEN-LAST:event_txtEmailMouseEntered

    private void txtEmailMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtEmailMouseExited
        if (isInputReady()) {
            setInformation(this.readyInfo);
        } else {
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_txtEmailMouseExited

    private void txtPinMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtPinMouseEntered
        jLabel5.setForeground(Color.black);
        setInformation("Please enter a 10 character pin to help identify "
                + "yourself to an RA Operator");
    }//GEN-LAST:event_txtPinMouseEntered

    private void txtPinMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_txtPinMouseExited
        if (isInputReady()) {
            setInformation(this.readyInfo);
        } else {
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
        if (isInputReady()) {
            setInformation(this.readyInfo);
        } else {
            setInformation(mainInfo);
        }
    }//GEN-LAST:event_txtConfirmMouseExited

    private void txtPinActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_txtPinActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_txtPinActionPerformed

    private void aliasTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_aliasTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_aliasTextFieldActionPerformed
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField aliasTextField;
    private javax.swing.JButton btnApply;
    private javax.swing.JButton btnCancel;
    private javax.swing.JComboBox cmbSelectRA;
    private javax.swing.JDesktopPane jDesktopPane1;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JTextArea jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel labCN;
    private javax.swing.JLabel labEmail;
    private javax.swing.JLabel labelRequestorId;
    private javax.swing.JPasswordField txtConfirm;
    private javax.swing.JTextField txtDN;
    private javax.swing.JTextField txtEmail;
    private javax.swing.JTextField txtName;
    private javax.swing.JPasswordField txtPin;
    // End of variables declaration//GEN-END:variables

    private void setInformation(String text) {
        jLabel5.setText(text);
    }
}
