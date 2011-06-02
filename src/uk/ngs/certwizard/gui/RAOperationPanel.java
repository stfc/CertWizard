/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * MainWindowPanel.java
 *
 * Created on 20-Jul-2010, 17:41:14
 */
package uk.ngs.certwizard.gui;

import java.awt.Color;
import java.io.File;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import java.io.FileOutputStream;

import java.util.Observer;
import java.util.Observable;

import org.globus.common.CoGProperties;
import org.globus.util.PEMUtils;
import org.globus.util.Base64;
import org.globus.util.Util;

import org.globus.gsi.bc.BouncyCastleOpenSSLKey;

import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.certificate.management.OffLineCertificateInfo;
import uk.ngs.ca.certificate.management.OnLineCertificateInfo;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.certificate.client.CAMotd;
import uk.ngs.ca.certificate.client.CARARequestsPending;
import uk.ngs.ca.certificate.client.CSRApprove;
import uk.ngs.ca.certificate.client.CSRDelete;
import uk.ngs.ca.certificate.client.CertificateDelete;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.CertificateRA;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.client.RAContact;
import uk.ngs.ca.certificate.management.CertificateCSRInfo;
import uk.ngs.ca.certificate.management.RequestPendingInfo;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class RAOperationPanel extends javax.swing.JPanel implements Observer {

    String MotD = "Message of the Day: \n\n\nThe CA is Awesome";
    ArrayList<Certificate> array;
    private char[] PASSPHRASE;
    private OffLineCertificateInfo offLineCertInfo;
    private OnLineCertificateInfo onLineCertInfo;
    private String[] ONLINEALLDNS = null;

    private int itemSelected = -1;

    private CertificateCSRInfo[] certificateCSRInfos = null;

    private CertWizardMain _certWizardMain = null;

    private CertificateCSRInfo certificateCSRInfo = null;
    private RequestPendingInfo[] requestPendingInfos = null;

    private PrivateKey privateKey = null;
    private PublicKey publicKey = null;

    /** Creates new form MainWindowPanel */

    public RAOperationPanel( CertificateCSRInfo info ){
        this.certificateCSRInfo = info;

        initComponents();

        if (SystemStatus.ISONLINE.get()) {
            String id = info.getId();
            long long_id = new Long( id ).longValue();

            CertificateRA certRA = new CertificateRA( id );
            String ra = certRA.getRA();
            String title = "Certificate Requests for " + ra;
            this.jPanel2.setBorder(new TitledBorder(title));

            String _pswdProperty = SysProperty.getValue("uk.ngs.ca.passphrase.property");
            String _pswd = System.getProperty(_pswdProperty);
            this.PASSPHRASE = _pswd.toCharArray();
            ClientKeyStore clientKeyStore = ClientKeyStore.getClientkeyStore( _pswd.toCharArray() );
            CertificateDownload certDownload = new CertificateDownload( id );
            X509Certificate _cert = certDownload.getCertificate();
            PublicKey _publicKey = _cert.getPublicKey();
            PrivateKey _privKey = clientKeyStore.getPrivateKey(_publicKey);
            this.privateKey = _privKey;
            this.publicKey = _publicKey;
            CARARequestsPending _reqPending = new CARARequestsPending( _privKey, long_id );
            if( _reqPending.doGet() ){
                this.requestPendingInfos = _reqPending.getRequestPendingInfos();
            }

            CAMotd motd = new CAMotd();
            this.MotD = motd.getText();
            setMOD(this.MotD);

            this.btnRefresh.setVisible(true);
        }else{
            this.btnRefresh.setVisible(false);
        }

        fillComboBox();

    }

    private void setupObservable(){
        if (jComboBox1.getItemCount() != 0){
            int index = jComboBox1.getSelectedIndex();
                                
            CertWizardObservable _observable = new CertWizardObservable();        
            _observable.addObserver(this._certWizardMain);        
            _observable.change(this.certificateCSRInfos[ index ]);
        }
        
    }
    
    private void onLineInit() {
        onLineCertInfo = new OnLineCertificateInfo(PASSPHRASE);

        this.certificateCSRInfos = onLineCertInfo.getCertCSRInfos();


        if ((this.certificateCSRInfos == null) || (this.certificateCSRInfos.length == 0)) {
//            if ( (onLineCertInfo.getAllDNs() == null) || ( onLineCertInfo.getAllDNs().length == 0 ) ) {
//            this.btnExport.setEnabled(false);
//            this.btnRevoke.setEnabled(false);
//            this.btnRenew.setEnabled(false);
//            this.btnDelete.setEnabled(false);
//            this.btnInstall.setEnabled(false);
        }
    }

    private void offLineInit() {
        offLineCertInfo = new OffLineCertificateInfo(PASSPHRASE);
        if ((offLineCertInfo.getAllDNs() == null) || (offLineCertInfo.getAllDNs().length == 0)) {
//            this.btnExport.setEnabled(false);
//            this.btnRevoke.setEnabled(false);
//            this.btnRenew.setEnabled(false);
//            this.btnDelete.setEnabled(false);
//            this.btnInstall.setEnabled(false);
        }
    }

    public void refreshOnLine(){
        onLineInit();
        jComboBox1.removeAllItems();
        fillComboBox();
    }

    public void update(Observable observable, Object obj) {
        if (SystemStatus.ISONLINE.get()) {
            if( observable.getClass().getSimpleName().equals("OnLineUserCertificateRequest")
                    || observable.getClass().getSimpleName().equals("ImportCertificate") ){
                String alias = (String)obj;
                ClientKeyStore clientKeyStore = ClientKeyStore.getClientkeyStore( this.PASSPHRASE );
                PublicKey _publicKey = clientKeyStore.getPublicKey(alias);
                CertificateCSRInfo _certCSRInfo = new CertificateCSRInfo( _publicKey );
                this.onLineCertInfo.addCertificateCSRInfo(_certCSRInfo);
                this.certificateCSRInfos = this.onLineCertInfo.getCertCSRInfos();
            }else if( observable.getClass().getSimpleName().equals("OnLineCertificateInfo") ){
                String _message = (String)obj;
                int _index = _message.indexOf("Renew:");
                if( _index != -1 ){
                    String _alias = _message.substring( 6 );
                    ClientKeyStore clientKeyStore = ClientKeyStore.getClientkeyStore( this.PASSPHRASE );
                    PublicKey _publicKey = clientKeyStore.getPublicKey(_alias);
                    CertificateCSRInfo _certCSRInfo = new CertificateCSRInfo( _publicKey );
                    this.onLineCertInfo.addCertificateCSRInfo(_certCSRInfo);
                    this.certificateCSRInfos = this.onLineCertInfo.getCertCSRInfos();
                }
                _index = _message.indexOf("Revoke:");
                if( _index != -1 ){                    
                    String _publickey = _message.substring( 7 );
                    for( int i = 0; i < this.certificateCSRInfos.length; i++ ){
                        String _encodedpublickey = this.certificateCSRInfos[ i ].getPublickey();
                        if( _publickey.equals(_encodedpublickey) ){
                            this.certificateCSRInfos[ i ].update(this.PASSPHRASE);
                        }
                    }
                }
                _index = _message.indexOf("Remove:");
                if( _index != -1 ){
                    String _sizeString = _message.substring( 7 );
                    int _size = new Integer( _sizeString ).intValue();
                    this.onLineCertInfo.deleteCertificateCSRInfo(_size);
                    this.certificateCSRInfos = this.onLineCertInfo.getCertCSRInfos();
                }
            }else{
                onLineInit();
            }
        } else {
            offLineInit();
        }
        jComboBox1.removeAllItems();
        fillComboBox();

    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel2 = new javax.swing.JPanel();
        jComboBox1 = new javax.swing.JComboBox();
        pnlAllDetails = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        serialNumber = new javax.swing.JTextField();
        commonName = new javax.swing.JTextField();
        btnApprove = new javax.swing.JButton();
        btnDelete = new javax.swing.JButton();
        btnContactUser = new javax.swing.JButton();
        btnFullRequest = new javax.swing.JButton();
        email = new javax.swing.JTextField();
        distinguishName = new javax.swing.JTextField();
        role = new javax.swing.JTextField();
        submittedOn = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        jLabel8 = new javax.swing.JLabel();
        btnRefresh = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TextMOD = new javax.swing.JTextArea();
        jLabel7 = new javax.swing.JLabel();

        addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseExited(java.awt.event.MouseEvent evt) {
                formMouseExited(evt);
            }
        });

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificate Requests for "));

        jComboBox1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                jComboBox1MouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jComboBox1MouseExited(evt);
            }
        });
        jComboBox1.addItemListener(new java.awt.event.ItemListener() {
            public void itemStateChanged(java.awt.event.ItemEvent evt) {
                jComboBox1ItemStateChanged(evt);
            }
        });
        jComboBox1.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jComboBox1ActionPerformed(evt);
            }
        });

        pnlAllDetails.setBorder(javax.swing.BorderFactory.createTitledBorder("Request Information"));

        jLabel1.setText("Serial Number");

        jLabel2.setText("Common Name");

        serialNumber.setEditable(false);

        commonName.setEditable(false);

        btnApprove.setText("Approve");
        btnApprove.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnApproveMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnApproveMouseExited(evt);
            }
        });
        btnApprove.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnApproveActionPerformed(evt);
            }
        });

        btnDelete.setText("Delete");
        btnDelete.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnDeleteMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnDeleteMouseExited(evt);
            }
        });
        btnDelete.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnDeleteActionPerformed(evt);
            }
        });

        btnContactUser.setText("Contact User");
        btnContactUser.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnContactUserMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnContactUserMouseExited(evt);
            }
        });
        btnContactUser.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnContactUserActionPerformed(evt);
            }
        });

        btnFullRequest.setText("Full Request");
        btnFullRequest.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnFullRequestMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnFullRequestMouseExited(evt);
            }
        });
        btnFullRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnFullRequestActionPerformed(evt);
            }
        });

        email.setEditable(false);

        distinguishName.setEditable(false);

        role.setEditable(false);

        submittedOn.setEditable(false);

        jLabel3.setText("Email");

        jLabel4.setText("Distinguish Name");

        jLabel5.setText("Role");

        jLabel6.setText("Submitted on");

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Request Status"));

        jLabel8.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/blank.png"))); // NOI18N
        jLabel8.setText("No request exists");

        org.jdesktop.layout.GroupLayout jPanel1Layout = new org.jdesktop.layout.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .add(jLabel8, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 324, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(117, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .add(jLabel8)
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        btnRefresh.setText("Refresh");
        btnRefresh.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnRefreshMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnRefreshMouseExited(evt);
            }
        });
        btnRefresh.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRefreshActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout pnlAllDetailsLayout = new org.jdesktop.layout.GroupLayout(pnlAllDetails);
        pnlAllDetails.setLayout(pnlAllDetailsLayout);
        pnlAllDetailsLayout.setHorizontalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(58, 58, 58)
                        .add(btnRefresh)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnApprove)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnDelete)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnContactUser)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnFullRequest))
                    .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                        .add(org.jdesktop.layout.GroupLayout.LEADING, jPanel1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .add(org.jdesktop.layout.GroupLayout.LEADING, pnlAllDetailsLayout.createSequentialGroup()
                            .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                .add(jLabel1)
                                .add(jLabel2)
                                .add(jLabel3)
                                .add(jLabel4)
                                .add(jLabel5)
                                .add(jLabel6))
                            .add(18, 18, 18)
                            .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                                .add(submittedOn)
                                .add(role)
                                .add(distinguishName)
                                .add(email)
                                .add(commonName)
                                .add(serialNumber, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 368, Short.MAX_VALUE)))))
                .add(20, 20, 20))
        );
        pnlAllDetailsLayout.setVerticalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel1)
                    .add(serialNumber, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(commonName, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel2))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(email, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel3))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(distinguishName, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel4))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(role, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel5))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(submittedOn, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel6))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(jPanel1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnApprove)
                    .add(btnDelete)
                    .add(btnContactUser)
                    .add(btnFullRequest)
                    .add(btnRefresh)))
        );

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 487, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .add(21, 21, 21))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 20, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder("Information"));

        TextMOD.setColumns(20);
        TextMOD.setLineWrap(true);
        TextMOD.setRows(5);
        jScrollPane1.setViewportView(TextMOD);

        org.jdesktop.layout.GroupLayout jPanel3Layout = new org.jdesktop.layout.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 151, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel3Layout.createSequentialGroup()
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 229, Short.MAX_VALUE)
                .addContainerGap())
        );

        jLabel7.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/stfc-transparent.png"))); // NOI18N

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel7, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 187, Short.MAX_VALUE)
                    .add(jPanel3, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .add(27, 27, 27))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(layout.createSequentialGroup()
                        .add(26, 26, 26)
                        .add(jPanel2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                    .add(layout.createSequentialGroup()
                        .add(jLabel7, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 47, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .add(90, 90, 90)
                        .add(jPanel3, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap())
        );

        jPanel2.getAccessibleContext().setAccessibleName("Certificate Requests for");
    }// </editor-fold>//GEN-END:initComponents

    private boolean isPing(){
        //PingService pingService = new PingService();
        //return pingService.isPingService();
        return PingService.getPingService().isPingService();
    }

    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed
        // TODO add your handling code here:

        if (jComboBox1.getItemCount() == 0) {
            this.serialNumber.setText("");
            this.commonName.setText("");
            this.email.setText("");
            this.distinguishName.setText("");
            this.role.setText("");
            this.submittedOn.setText("");
this.jLabel8.setIcon(new ImageIcon(getClass().getResource("/uk/ngs/ca/images/blank.png")));
this.jLabel8.setText("No request exists.");
this.btnApprove.setEnabled(false);
this.btnDelete.setEnabled(false);
this.btnContactUser.setEnabled(false);
this.btnFullRequest.setEnabled(false);
            return;
        }

        if( SystemStatus.ISONLINE.get() ){
            int index = this.jComboBox1.getSelectedIndex();
            this.serialNumber.setText(this.requestPendingInfos[ index ].getSerialNumber());
            this.commonName.setText(this.requestPendingInfos[ index ].getCN());
            this.email.setText(this.requestPendingInfos[ index ].getUserEmail());
            this.distinguishName.setText(this.requestPendingInfos[ index ].getDN());
            this.role.setText(this.requestPendingInfos[ index ].getRole());
            this.submittedOn.setText(this.requestPendingInfos[ index ].getStartDate());
String _title = this.requestPendingInfos[ index ].getDisplayTitle();
if( ( _title.indexOf("NEW") != -1 ) || ( _title.indexOf("REKEY") != -1 ) ){
    this.jLabel8.setIcon(new ImageIcon(getClass().getResource("/uk/ngs/ca/images/cross.png")));
    this.jLabel8.setText("This request has yet to be approved.");
this.btnApprove.setEnabled(true);
this.btnDelete.setEnabled(true);
this.btnContactUser.setEnabled(true);
this.btnFullRequest.setEnabled(true);
}else if( ( _title.indexOf("APPROVED") != -1 ) || ( _title.indexOf("SUSPENDED") != -1 ) ){
    this.jLabel8.setIcon(new ImageIcon(getClass().getResource("/uk/ngs/ca/images/tick.png")));
    this.jLabel8.setText("This request has been approved.");
this.btnApprove.setEnabled(false);
this.btnDelete.setEnabled(true);
this.btnContactUser.setEnabled(true);
this.btnFullRequest.setEnabled(true);
}
        }

    }//GEN-LAST:event_jComboBox1ActionPerformed

    private void btnDeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDeleteActionPerformed
        // TODO add your handling code here:
        int index = jComboBox1.getSelectedIndex();

        if (SystemStatus.ISONLINE.get()) {

            //check if connection is fine.
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem connecting with the server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            
            if( this.jComboBox1.getSelectedIndex() != -1 ){
                if( ( this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("NEW") ) 
                    || ( this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("REKEY") ) 
                    || ( this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("APPROVED") ) ){
                    if (JOptionPane.showConfirmDialog(this, "Are you sure you want to delete request " + this.requestPendingInfos[this.jComboBox1.getSelectedIndex()].getDN() + "?", "Confirm Delete", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                        String _reqID = this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getSerialNumber();
                        long long_reqID = new Long( _reqID ).longValue();
                        String _encodedPubKey = EncryptUtil.getEncodedPublicKey(this.publicKey);
                        CSRDelete csrDelete = new CSRDelete( this.privateKey, _encodedPubKey, long_reqID );
                        if( csrDelete.isSuccessDelete() ){
                            JOptionPane.showMessageDialog(this, "You have deleted the request successfully!", "Success Delete", JOptionPane.INFORMATION_MESSAGE);
                            int size = this.requestPendingInfos.length;
                            RequestPendingInfo[] _reqPendingInfos = new RequestPendingInfo[ size - 1 ];
                            for( int i = 0, j = 0; i < size; i ++ ){
                                if( i != this.jComboBox1.getSelectedIndex() ){
                                    _reqPendingInfos[ j ] = this.requestPendingInfos[ i ];
                                    j++;
                                }
                            }
                            this.requestPendingInfos = _reqPendingInfos;
                            this.jComboBox1.removeAllItems();
                            fillComboBox();
                        }else{
                            JOptionPane.showMessageDialog(this, "You fail to delete the request!", "Unsuccess Delete", JOptionPane.INFORMATION_MESSAGE);
                        }
                    }
                }else if( this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("SUSPENDED") ){
                    if (JOptionPane.showConfirmDialog(this, "Are you sure you want to delete request " + this.requestPendingInfos[this.jComboBox1.getSelectedIndex()].getDN() + "?", "Confirm Delete", JOptionPane.OK_CANCEL_OPTION) == JOptionPane.OK_OPTION) {
                        String _certID = this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getSerialNumber();
                        long long_certID = new Long( _certID ).longValue();
                        String _encodedPubKey = EncryptUtil.getEncodedPublicKey(this.publicKey);
                        CertificateDelete certDelete = new CertificateDelete( this.privateKey, _encodedPubKey, long_certID );
                        if( certDelete.isSuccessDelete() ){
                            JOptionPane.showMessageDialog(this, "You have deleted the request successfully!", "Success Delete", JOptionPane.INFORMATION_MESSAGE);
                            int size = this.requestPendingInfos.length;
                            RequestPendingInfo[] _reqPendingInfos = new RequestPendingInfo[ size - 1 ];
                            for( int i = 0, j = 0; i < size; i ++ ){
                                if( i != this.jComboBox1.getSelectedIndex() ){
                                    _reqPendingInfos[ j ] = this.requestPendingInfos[ i ];
                                    j++;
                                }
                            }
                            this.requestPendingInfos = _reqPendingInfos;
                            this.jComboBox1.removeAllItems();
                            fillComboBox();
                        }else{
                            JOptionPane.showMessageDialog(this, "You fail to delete the request!", "Unsuccess Delete", JOptionPane.INFORMATION_MESSAGE);
                        }
                    }
                }
            }
            
        } 
    }//GEN-LAST:event_btnDeleteActionPerformed

    public void raSendEmail(String _from, String _to, String _subject, String _content){
        String _encodedPubKey = EncryptUtil.getEncodedPublicKey(this.publicKey);
        RAContact raContact = new RAContact( this.privateKey, _encodedPubKey, _from, _to, _subject, _content);
        if( raContact.isSuccessContact() ){
            JOptionPane.showMessageDialog(this, "You have send out email successfully!", "Email Success", JOptionPane.INFORMATION_MESSAGE);
        }else{
            JOptionPane.showMessageDialog(this, "You fail to send out email!", "Unsuccess Email", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    public void approveRequest(){
        String _certID = this.certificateCSRInfo.getId();
        String _reqID = this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getSerialNumber();
        long long_certID = new Long( _certID ).longValue();
        long long_reqID = new Long( _reqID ).longValue();
        CSRApprove csrApprove = new CSRApprove( this.privateKey, long_certID, long_reqID );
        if( csrApprove.isSuccessApprove() ){
            JOptionPane.showMessageDialog(this, "You have approved the request successfully!", "Success Approvement", JOptionPane.INFORMATION_MESSAGE);
            this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].setType("APPROVED");
            String _title = this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getDN();
            _title = "APPROVED:" + _title;
            this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].setDisplayTitle(_title);

            this.jComboBox1.removeAllItems();
            fillComboBox();
        }else{
            JOptionPane.showMessageDialog(this, "You fail to approve the request!", "Unsuccess Approvement", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private void btnApproveActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnApproveActionPerformed
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE.get()) {

            //check if connection is fine.
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem connecting with the server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                return;
            }

            if( ( ! this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("NEW") )
                    && ( ! this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("REKEY") ) ){
                JOptionPane.showMessageDialog(this, "You haven't selected one suitable pending request to approve!", "No suitable request selected", JOptionPane.INFORMATION_MESSAGE);
            }else{
                if( ( this.jComboBox1.getSelectedIndex() != -1 ) && ( this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("NEW") ) ){
                    new ApproveCheckFrame( this, this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ] ).setVisible(true);
                }else if( ( this.jComboBox1.getSelectedIndex() != -1 ) && ( this.requestPendingInfos[ this.jComboBox1.getSelectedIndex() ].getType().equals("REKEY") ) ){
                    new ApproveReKeyCheckFrame( this ).setVisible(true);
                }

            }

        }
    }//GEN-LAST:event_btnApproveActionPerformed

    private void btnContactUserActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnContactUserActionPerformed
        // TODO add your handling code here:

            int index = this.jComboBox1.getSelectedIndex();
            String _emailTo = this.requestPendingInfos[ index ].getUserEmail();
            String _emailFrom = this.certificateCSRInfo.getUserEmail();
            new RAContactEmail( this, _emailFrom, _emailTo).setVisible(true);

    }//GEN-LAST:event_btnContactUserActionPerformed

    private void btnFullRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnFullRequestActionPerformed
        // TODO add your handling code here:
        if( SystemStatus.ISONLINE.get() ){
            int index = this.jComboBox1.getSelectedIndex();
            new FullRequest( this.requestPendingInfos[ index ] ).setVisible( true );
        }
        
    }//GEN-LAST:event_btnFullRequestActionPerformed

    private void formMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_formMouseExited
        // TODO add your handling code here:
    }//GEN-LAST:event_formMouseExited

    private void jComboBox1MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseEntered
        // TODO add your handling code here:
        setMOD("List of certificate requests");
    }//GEN-LAST:event_jComboBox1MouseEntered

    private void btnApproveMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnApproveMouseEntered
        // TODO add your handling code here:
        setMOD("Approve the selected pending request");
    }//GEN-LAST:event_btnApproveMouseEntered

    private void btnDeleteMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseEntered
        // TODO add your handling code here:
        setMOD("Delete the selected pending request");
    }//GEN-LAST:event_btnDeleteMouseEntered

    private void btnContactUserMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnContactUserMouseEntered
        // TODO add your handling code here:
        setMOD("Contact the user by sending email");
    }//GEN-LAST:event_btnContactUserMouseEntered

    private void btnFullRequestMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnFullRequestMouseEntered
        // TODO add your handling code here:
        setMOD("Display full information of the pending request");
    }//GEN-LAST:event_btnFullRequestMouseEntered

    private void jComboBox1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE.get()) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_jComboBox1MouseExited

    private void btnApproveMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnApproveMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE.get()) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnApproveMouseExited

    private void btnDeleteMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE.get()) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnDeleteMouseExited

    private void btnContactUserMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnContactUserMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE.get()) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnContactUserMouseExited

    private void btnFullRequestMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnFullRequestMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE.get()) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnFullRequestMouseExited

    private void jComboBox1ItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_jComboBox1ItemStateChanged
        // TODO add your handling code here:
      
    }//GEN-LAST:event_jComboBox1ItemStateChanged

    private void btnRefreshActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRefreshActionPerformed
        // TODO add your handling code here:
        WaitDialog.showDialog("Refresh");
        String id = this.certificateCSRInfo.getId();
        long long_id = new Long( id ).longValue();
        CARARequestsPending _reqPending = new CARARequestsPending( this.privateKey, long_id );
        if( _reqPending.doGet() ){
            this.requestPendingInfos = _reqPending.getRequestPendingInfos();
        }
        this.jComboBox1.removeAllItems();
        fillComboBox();
//        refreshOnLine();
        WaitDialog.hideDialog();
    }//GEN-LAST:event_btnRefreshActionPerformed

    private void btnRefreshMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRefreshMouseEntered
        // TODO add your handling code here:
        setMOD("Contace with CA server to retrieve the latest requests.");
    }//GEN-LAST:event_btnRefreshMouseEntered

    private void btnRefreshMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRefreshMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE.get()) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnRefreshMouseExited

    private boolean isSuccessPemFiles(X509Certificate certificate, PrivateKey privateKey){
        CoGProperties props = CoGProperties.getDefault();
        String certPemFile = props.getUserCertFile();
        String keyPemFile = props.getUserKeyFile();
        File fCertFile = new File( certPemFile );
        File fKeyFile = new File( keyPemFile );

        String overwriteWarning = "";
        boolean oneExists = false;
        if (fKeyFile.exists()) {
            oneExists = true;
            overwriteWarning += "Local Key file already exists: \n     [" + keyPemFile + "]\n\n";
        }
        if (fCertFile.exists()) {
            oneExists = true;
            overwriteWarning += "Local Certificate file already exists: \n    [" + certPemFile + "]\n";
        }
        if (oneExists) {
            // test here for permissions.
            overwriteWarning += "\nAre you sure you want to overwrite these files ?";
            int ret = JOptionPane.showConfirmDialog( this, overwriteWarning, "Certificate/Key Installation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            // added CLOSED_OPTION so that clicking 'X' does the same as clicking 'No'.
            if (JOptionPane.NO_OPTION == ret || JOptionPane.CLOSED_OPTION == ret) {
                return false;
            }
            if( JOptionPane.YES_OPTION == ret ){
                try{
                    fCertFile.delete();
                    fKeyFile.delete();
                    FileOutputStream certfos = new FileOutputStream(fCertFile);
                    PEMUtils.writeBase64(certfos, "-----BEGIN CERTIFICATE-----", Base64.encode(certificate.getEncoded()), "-----END CERTIFICATE-----");
                    Util.setFilePermissions(certPemFile, 444);
                    certfos.close();

                    // Output key - need to remove dependency on the bouncycastle here !
                    BouncyCastleOpenSSLKey bcosk = new BouncyCastleOpenSSLKey(privateKey);
                    bcosk.encrypt(new String(PASSPHRASE));
                    bcosk.writeTo(keyPemFile);
                    Util.setFilePermissions(keyPemFile, 400);
                    return true;
                }catch( Exception ep ){
                    ep.printStackTrace();
                    return false;
                }

            }

            return true;
        }else{
                 try{
                    FileOutputStream certfos = new FileOutputStream(fCertFile);
                    PEMUtils.writeBase64(certfos, "-----BEGIN CERTIFICATE-----", Base64.encode(certificate.getEncoded()), "-----END CERTIFICATE-----");
                    Util.setFilePermissions(certPemFile, 444);
                    certfos.close();

                    // Output key - need to remove dependency on the bouncycastle here !
                    BouncyCastleOpenSSLKey bcosk = new BouncyCastleOpenSSLKey(privateKey);
                    bcosk.encrypt(new String(PASSPHRASE));
                    bcosk.writeTo(keyPemFile);
                    Util.setFilePermissions(keyPemFile, 400);
                    return true;
                }catch( Exception ep ){
                    ep.printStackTrace();
                    return false;
                }

        }


    }

    private void setRedMOD( String text ){
        TextMOD.setForeground(Color.RED);
        TextMOD.setText(text);
    }
    
    public void setMOD(String text) {
        TextMOD.setForeground(Color.BLACK);
        TextMOD.setText(text);
    }

    private void updateComboBox( int _index ){
        if (SystemStatus.ISONLINE.get()) {
            if( this.certificateCSRInfos[ _index ] != null ){
                ListCellRenderer renderer = new ListItemRenderer();
                String _dn = this.certificateCSRInfos[ _index ].getOwner();
                String _status = this.certificateCSRInfos[ _index ].getStatus();

                Object[] element = new Object[2];
                if (_status.equals("VALID")) {
                    element[ 0 ] = new ValidCertColor();
                    element[ 1 ] = _dn;
                } else if (_status.equals("REVOKED")) {
                    element[ 0 ] = new RevokedCertColor();
                    element[ 1 ] = _dn;
                } else if (_status.equals("SUSPENDED")) {
                    element[ 0 ] = new SuspendCertColor();
                    element[ 1 ] = _dn;
                } else if (_status.equals("NEW")) {
                    element[ 0 ] = new PendingColor();
                    element[ 1 ] = _dn;
                } else if (_status.equals("RENEW")) {
                    element[ 0 ] = new RenewalDueColor();
                    element[ 1 ] = _dn;
                } else if (_status.equals("APPROVED")) {
                    element[ 0 ] = new SuspendCertColor();
                    element[ 1 ] = _dn;
                } else if (_status.equals("ARCHIVED")) {
                    element[ 0 ] = new ValidCertColor();
                    element[ 1 ] = _dn;
                } else if (_status.equals("DELETED")) {
                    element[ 0 ] = new RevokedCertColor();
                    element[ 1 ] = _dn;
                } else {
                    element[ 0 ] = new RevokedCertColor();
                    element[ 1 ] = _dn;
                }


                Object[] _obj = (Object[])jComboBox1.getItemAt(_index);
                jComboBox1.removeItemAt( _index );

                _obj = (Object[])jComboBox1.getItemAt(_index);

                jComboBox1.insertItemAt( element, _index );

                _obj = (Object[])jComboBox1.getItemAt(_index);

            }
        }
    }

    private void fillComboBox() {

        if (SystemStatus.ISONLINE.get()) {
            if( this.requestPendingInfos != null ){
                ListCellRenderer renderer = new ListItemRenderer();
                for( int i = 0; i < this.requestPendingInfos.length; i++ ){
                    String _title = this.requestPendingInfos[ i ].getDisplayTitle();
                    String _type = this.requestPendingInfos[ i ].getType();
                    Object element[] = new Object[3];
                    if( _type.equals("REKEY") ){
                        element[ 0 ] = new RenewalDueColor();
                        element[ 1 ] = _title;
                        element[ 2 ] = _type;
                    }else if( _type.equals( "NEW" ) ){
                        element[ 0 ] = new PendingColor();
                        element[ 1 ] = _title;
                        element[ 2 ] = _type;
                    }else if( _type.equals( "APPROVED" ) ){
                        element[ 0 ] = new SuspendCertColor();
                        element[ 1 ] = _title;
                        element[ 2 ] = _type;
                    }else if( _type.equals( "SUSPENDED" ) ){
                        element[ 0 ] = new SuspendCertColor();
                        element[ 1 ] = _title;
                        element[ 2 ] = _type;
                    }else{
                        element[ 0 ] = new RevokedCertColor();
                        element[ 1 ] = _title;
                        element[ 2 ] = _type;
                    }

                    this.jComboBox1.addItem(element);
                }
                this.jComboBox1.setRenderer(renderer);
            }
        }
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea TextMOD;
    private javax.swing.JButton btnApprove;
    private javax.swing.JButton btnContactUser;
    private javax.swing.JButton btnDelete;
    private javax.swing.JButton btnFullRequest;
    private javax.swing.JButton btnRefresh;
    private javax.swing.JTextField commonName;
    private javax.swing.JTextField distinguishName;
    private javax.swing.JTextField email;
    private javax.swing.JComboBox jComboBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JPanel pnlAllDetails;
    private javax.swing.JTextField role;
    private javax.swing.JTextField serialNumber;
    private javax.swing.JTextField submittedOn;
    // End of variables declaration//GEN-END:variables
}
