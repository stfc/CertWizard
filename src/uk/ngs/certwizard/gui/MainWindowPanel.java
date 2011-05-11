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
import java.util.Timer;

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
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.management.CertificateCSRInfo;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class MainWindowPanel extends javax.swing.JPanel implements Observer {

    String MotD = "Message of the Day: \n\n\nWelcome to the new Certificate Wizard!";
    ArrayList<Certificate> array;
    private char[] PASSPHRASE;
    private OffLineCertificateInfo offLineCertInfo;
    private OnLineCertificateInfo onLineCertInfo;
    private CertificateCSRInfo[] certificateCSRInfos = null;

    private CertWizardMain _certWizardMain = null;


    /** Creates new form MainWindowPanel */
    public MainWindowPanel(char[] passphrase, CertWizardMain _certWizardMain) {
        String _passphrase = new String(passphrase);

        String _property = SysProperty.getValue("uk.ngs.ca.immegration.password.property");
        System.setProperty(_property, _passphrase);
        PASSPHRASE = passphrase;

        this._certWizardMain = _certWizardMain;

        initComponents();

        if (SystemStatus.ISONLINE) {
            //setup timer for 30 minutes
            long timeinmin = 1000*60*30;
            Timer timer = new Timer();
            timer.schedule(new RefreshOnLine( this ), timeinmin, timeinmin);
            onLineInit();
            CAMotd motd = new CAMotd();
            MotD = motd.getText();
            setMOD(MotD);

            //CHECK FOR NEW VERSION HERE! CSRREQUEST HAS THE METHOD

            String certWizardVersion = SysProperty.getValue("ngsca.certwizard.versionNumber");
            Float certWizardVersionFloat = new Float(certWizardVersion);
//            float certWizardVersionInt = Integer.parseInt(certWizardVersion);

            //Now fetch the latest version from the server. Required info is in DBCAInfo, ultimately
            //handled by the CAResource class.
            String latestVersion = motd.getLatestVersion();
            Float latestVersionFloat = new Float(latestVersion);

            if (latestVersionFloat > certWizardVersionFloat) {
                JOptionPane.showMessageDialog(this, "A new version "+latestVersion+" of the Certificate Wizard is available!\n"
                        + "Please go to www.ngs.ac.uk in order to obtain the latest version",
                        "New Version of Certificate Wizard", JOptionPane.INFORMATION_MESSAGE);
            }
//            System.out.println("THE CERTIFICATE VERSION IS: "+ certWizardVersionFloat);
//            System.out.println("THE LATEST VERSION IS: "+ latestVersion);

        } else {
            offLineInit();

            MotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD( MotD );
        }


        fillComboBox();

        this.jPanel5.setVisible(false);

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
            this.btnExport.setEnabled(false);
            this.btnRevoke.setEnabled(false);
            this.btnRenew.setEnabled(false);
            this.btnDelete.setEnabled(false);
            this.btnInstall.setEnabled(false);
        }
    }

    private void offLineInit() {
        offLineCertInfo = new OffLineCertificateInfo(PASSPHRASE);

        this.btnNewCertificateRequest.setEnabled(false); //TEMPORARY ADDITION
        
        if ((offLineCertInfo.getAllDNs() == null) || (offLineCertInfo.getAllDNs().length == 0)) {
            this.btnExport.setEnabled(false);
            this.btnRevoke.setEnabled(false);
            this.btnRenew.setEnabled(false);
            this.btnDelete.setEnabled(false);
            this.btnInstall.setEnabled(false);
            
        }
    }

    public void refreshOnLine(){
        onLineInit();
        jComboBox1.removeAllItems();
        fillComboBox();
    }

    public void update(Observable observable, Object obj) {
        if (SystemStatus.ISONLINE) {
            //keystore and certificateCSRInfo need to be refreshed in OnLineCertificayeInfo.
            this.onLineCertInfo.refresh();

            if( observable.getClass().getSimpleName().equals("OnLineUserCertificateRequest")
                    || observable.getClass().getSimpleName().equals("ImportCertificate") ){
                String alias = (String)obj;
                ClientKeyStore clientKeyStore = new ClientKeyStore( this.PASSPHRASE );
                PublicKey _publicKey = clientKeyStore.getPublicKey(alias);
                CertificateCSRInfo _certCSRInfo = new CertificateCSRInfo( _publicKey );

                this.onLineCertInfo.addCertificateCSRInfo(_certCSRInfo);
                this.certificateCSRInfos = this.onLineCertInfo.getCertCSRInfos();
            }else if( observable.getClass().getSimpleName().equals("OnLineCertificateInfo") ){
                String _message = (String)obj;
                int _index = _message.indexOf("Renew:");
                if( _index != -1 ){
                    String _alias = _message.substring( 6 );
                    ClientKeyStore clientKeyStore = new ClientKeyStore( this.PASSPHRASE );
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
//                onLineInit();
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

        jPanel1 = new javax.swing.JPanel();
        btnNewCertificateRequest = new javax.swing.JButton();
        btnImportCertificate = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        jComboBox1 = new javax.swing.JComboBox();
        pnlAllDetails = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        DN = new javax.swing.JTextField();
        email = new javax.swing.JTextField();
        jPanel4 = new javax.swing.JPanel();
        jPanel5 = new javax.swing.JPanel();
        lblRequestReceived = new javax.swing.JLabel();
        lblRequestApproved = new javax.swing.JLabel();
        lblCertificateGenerated = new javax.swing.JLabel();
        pnlValidDates = new javax.swing.JPanel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        vFrom = new javax.swing.JTextField();
        vTo = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        dRemaining = new javax.swing.JTextField();
        rDue = new javax.swing.JTextField();
        btnDelete = new javax.swing.JButton();
        btnRevoke = new javax.swing.JButton();
        btnExport = new javax.swing.JButton();
        btnRenew = new javax.swing.JButton();
        btnInstall = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TextMOD = new javax.swing.JTextArea();
        jLabel7 = new javax.swing.JLabel();

        addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseExited(java.awt.event.MouseEvent evt) {
                formMouseExited(evt);
            }
        });

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Get A Certificate"));
        jPanel1.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseExited(java.awt.event.MouseEvent evt) {
                jPanel1MouseExited(evt);
            }
        });

        btnNewCertificateRequest.setText("Apply");
        btnNewCertificateRequest.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnNewCertificateRequestMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnNewCertificateRequestMouseExited(evt);
            }
        });
        btnNewCertificateRequest.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnNewCertificateRequestActionPerformed(evt);
            }
        });

        btnImportCertificate.setText("Import");
        btnImportCertificate.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnImportCertificateMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnImportCertificateMouseExited(evt);
            }
        });
        btnImportCertificate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnImportCertificateActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel1Layout = new org.jdesktop.layout.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .add(btnNewCertificateRequest)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(btnImportCertificate)
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnNewCertificateRequest)
                    .add(btnImportCertificate))
                .addContainerGap(14, Short.MAX_VALUE))
        );

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Your certificates and requests"));

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

        pnlAllDetails.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificate Information"));

        jLabel1.setText("DN:");

        jLabel2.setText("Email:");

        DN.setEditable(false);

        email.setEditable(false);

        org.jdesktop.layout.GroupLayout pnlAllDetailsLayout = new org.jdesktop.layout.GroupLayout(pnlAllDetails);
        pnlAllDetails.setLayout(pnlAllDetailsLayout);
        pnlAllDetailsLayout.setHorizontalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel1)
                    .add(jLabel2))
                .add(19, 19, 19)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING, false)
                    .add(email)
                    .add(DN, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 384, Short.MAX_VALUE))
                .addContainerGap(55, Short.MAX_VALUE))
        );
        pnlAllDetailsLayout.setVerticalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(DN, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel1))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(email, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel2))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel4.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificate Status"));

        lblRequestReceived.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/blank.png"))); // NOI18N
        lblRequestReceived.setText("This request is restored in your local system. It will be submitted when online.");

        lblRequestApproved.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/blank.png"))); // NOI18N
        lblRequestApproved.setText("Your request has been approved and is waiting to be signed");

        lblCertificateGenerated.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/blank.png"))); // NOI18N
        lblCertificateGenerated.setText("Your Certificate has been signed and downloaded");

        org.jdesktop.layout.GroupLayout jPanel5Layout = new org.jdesktop.layout.GroupLayout(jPanel5);
        jPanel5.setLayout(jPanel5Layout);
        jPanel5Layout.setHorizontalGroup(
            jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(org.jdesktop.layout.GroupLayout.LEADING, lblCertificateGenerated, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 458, Short.MAX_VALUE)
                    .add(org.jdesktop.layout.GroupLayout.LEADING, lblRequestApproved, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 458, Short.MAX_VALUE)
                    .add(lblRequestReceived, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 458, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel5Layout.setVerticalGroup(
            jPanel5Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel5Layout.createSequentialGroup()
                .addContainerGap()
                .add(lblRequestReceived)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(lblRequestApproved)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(lblCertificateGenerated)
                .addContainerGap())
        );

        jLabel3.setText("Valid From:");

        jLabel4.setText("Valid To:");

        vFrom.setEditable(false);

        vTo.setEditable(false);

        jLabel5.setText("Days Remaining:");

        jLabel6.setText("Renewal Due:");

        dRemaining.setEditable(false);

        rDue.setEditable(false);

        org.jdesktop.layout.GroupLayout pnlValidDatesLayout = new org.jdesktop.layout.GroupLayout(pnlValidDates);
        pnlValidDates.setLayout(pnlValidDatesLayout);
        pnlValidDatesLayout.setHorizontalGroup(
            pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlValidDatesLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel3)
                    .add(jLabel4))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                    .add(vFrom)
                    .add(vTo, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 125, Short.MAX_VALUE))
                .add(28, 28, 28)
                .add(pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(jLabel6)
                    .add(jLabel5))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                    .add(dRemaining)
                    .add(rDue, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 119, Short.MAX_VALUE))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlValidDatesLayout.setVerticalGroup(
            pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlValidDatesLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel3)
                    .add(vFrom, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(dRemaining, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel5))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlValidDatesLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel4)
                    .add(vTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel6)
                    .add(rDue, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        org.jdesktop.layout.GroupLayout jPanel4Layout = new org.jdesktop.layout.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, pnlValidDates, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jPanel5, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel4Layout.createSequentialGroup()
                .add(jPanel5, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlValidDates, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        btnDelete.setText("Remove");
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

        btnRevoke.setText("Revoke");
        btnRevoke.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnRevokeMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnRevokeMouseExited(evt);
            }
        });
        btnRevoke.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRevokeActionPerformed(evt);
            }
        });

        btnExport.setText("Export");
        btnExport.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnExportMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnExportMouseExited(evt);
            }
        });
        btnExport.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnExportActionPerformed(evt);
            }
        });

        btnRenew.setText("Renew");
        btnRenew.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnRenewMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnRenewMouseExited(evt);
            }
        });
        btnRenew.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRenewActionPerformed(evt);
            }
        });

        btnInstall.setText("Install");
        btnInstall.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnInstallMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnInstallMouseExited(evt);
            }
        });
        btnInstall.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnInstallActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, jPanel2Layout.createSequentialGroup()
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 138, Short.MAX_VALUE)
                        .add(btnInstall)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnRenew)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnExport)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnRevoke)
                        .add(4, 4, 4)
                        .add(btnDelete))
                    .add(jComboBox1, 0, 522, Short.MAX_VALUE)
                    .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .add(jPanel4, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .add(12, 12, 12))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 20, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel4, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnRevoke)
                    .add(btnExport)
                    .add(btnRenew)
                    .add(btnInstall)
                    .add(btnDelete))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 141, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel3Layout.createSequentialGroup()
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 242, Short.MAX_VALUE)
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
                    .add(jLabel7, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 181, Short.MAX_VALUE)
                    .add(jPanel1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .add(jPanel3, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, layout.createSequentialGroup()
                .addContainerGap()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(org.jdesktop.layout.GroupLayout.LEADING, jPanel2, 0, 432, Short.MAX_VALUE)
                    .add(layout.createSequentialGroup()
                        .add(jLabel7, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 47, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jPanel1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jPanel3, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addContainerGap())
        );
    }// </editor-fold>//GEN-END:initComponents

    private boolean isPing(){
        PingService pingService = new PingService();
        return pingService.isPingService();
    }

    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed
        // TODO add your handling code here:
//System.out.println("------------------------------------------------------------------------");
        //WaitDialog.showDialog();
        
        if (jComboBox1.getItemCount() == 0) {
            this.DN.setText("");
            this.vFrom.setText("");
            this.vTo.setText("");
            this.rDue.setText("");
            this.dRemaining.setText("");
            this.email.setText("");
            return;
        }
        /*   */ 

        this.DN.requestFocus();
        this.btnDelete.setEnabled(true);
        this.btnExport.setEnabled(true);
        this.btnRenew.setEnabled(true);
        this.btnRevoke.setEnabled(true);
        this.btnInstall.setEnabled(false);
        this.jPanel4.setBorder(new TitledBorder("Certificate Status"));

        this.pnlValidDates.setVisible(true);
        this.jPanel5.setVisible(false);


        int index = jComboBox1.getSelectedIndex();



        if (SystemStatus.ISONLINE) {
           
           if( !isPing() ){
               
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, "
                        + "\nplease report to helpdesk or work under offline by restarting "
                        + "CertWizard and select offline.", "Server Connection Fault",
                        JOptionPane.INFORMATION_MESSAGE);
                //WaitDialog.hideDialog();
                //return;
            } else {
                //update the selected item. This update will only be done if the ping check succeeds
                // i.e. the detabase connection is available

                Object[] _obj = (Object[])jComboBox1.getItemAt(index);
                String my_status = _obj[ 2 ].toString();

                //update the selected item.
                this.certificateCSRInfos[ index ].update( this.PASSPHRASE );


                if( ! my_status.equals(this.certificateCSRInfos[ index ].getStatus())){
                    jComboBox1.removeAllItems();
                    fillComboBox();
                    jComboBox1.setSelectedIndex(index);
                }

            }

            //rest of the code to alter the details when an item in the combo box has been selected,
            //based on the information stored in certificateCSRInfos variable

            //if the request is deleted by server, then the item will be removed from cakeystore.pkcs12 and from this gui.
            if( this.certificateCSRInfos[ index ].getStatus().equals("DELETED") ){
                String _publickeyString = this.certificateCSRInfos[ index ].getPublickey();
                ClientKeyStore _clientKeyStore = new ClientKeyStore( this.PASSPHRASE );
                PublicKey _publickey = EncryptUtil.getPublicKey(_publickeyString);
                PrivateKey _privatekey = _clientKeyStore.getPrivateKey(_publickey);
                _clientKeyStore.removeKey(_privatekey);
                this.onLineCertInfo.deleteCertificateCSRInfo(index);
                this.certificateCSRInfos = this.onLineCertInfo.getCertCSRInfos();
                jComboBox1.removeItemAt( index );
                jComboBox1.removeAllItems();
                fillComboBox();
                index = 0;
            }
            this.DN.setText(this.certificateCSRInfos[ index ].getOwner());
            this.vFrom.setText(this.certificateCSRInfos[ index ].getStartDate());
            this.vTo.setText(this.certificateCSRInfos[ index ].getEndDate());
            this.rDue.setText(this.certificateCSRInfos[ index ].getRenew());
            this.dRemaining.setText(this.certificateCSRInfos[ index ].getLifeDays());
            this.email.setText(this.certificateCSRInfos[ index ].getUserEmail());
            String _status = this.certificateCSRInfos[ index ].getStatus();

            if (_status.equals("REVOKED")) {
                this.jComboBox1.setForeground(new RevokedCertColor());
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
                this.jPanel4.setBorder(new TitledBorder("Certificate Status: " + _status));
            } else if (_status.equals("SUSPENDED")) {
                this.jComboBox1.setForeground(new SuspendCertColor());
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
                this.jPanel4.setBorder(new TitledBorder("Certificate Status: " + _status));
            } else if (_status.equals("NEW")) {
                this.jComboBox1.setForeground(new PendingColor());
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
                lblRequestReceived.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/tick.png")));
                lblRequestReceived.setText("Your certificate request has been submitted and is awaiting approval.");
                lblRequestApproved.setVisible(false);
                lblCertificateGenerated.setVisible(false);
                
                this.pnlValidDates.setVisible(false);
                this.jPanel5.setSize(this.jPanel5.getWidth(), pnlValidDates.getHeight());
                this.jPanel5.setVisible(true);

            } else if (_status.equals("VALID")) {
                    this.btnInstall.setForeground(Color.BLUE);
                    String _lifedays = this.certificateCSRInfos[ index ].getLifeDays();
                    int int_lifedays = new Integer( _lifedays ).intValue();
                    if( int_lifedays < 0 ){
                        this.jPanel4.setBorder(new TitledBorder("Certificate Status: EXPIRED"));
                        if( int_lifedays >= -30 ){
                            this.jComboBox1.setForeground(new ExpiredCertColor());
                        }else{
                            this.jComboBox1.setForeground(new ExpiredForeverCertColor());
                        }
                    }else{
                        this.jPanel4.setBorder(new TitledBorder("Certificate Status: " + _status));
                        this.jComboBox1.setForeground(new ValidCertColor());
                    }

            } else if (_status.equals("RENEW")) {
                this.jComboBox1.setForeground(new RenewalDueColor());
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
                lblRequestReceived.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/tick.png")));
                lblRequestReceived.setText("Your renewal certificate request has been submitted and is waiting for the approval.");
                lblRequestApproved.setVisible(false);
                lblCertificateGenerated.setVisible(false);
                this.pnlValidDates.setVisible(false);
                this.jPanel5.setSize(this.jPanel5.getWidth(), pnlValidDates.getHeight());
                this.jPanel5.setVisible(true);
            } else if (_status.equals("APPROVED")) {
                this.jComboBox1.setForeground(new SuspendCertColor());
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
                lblRequestReceived.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/tick.png")));
                lblRequestReceived.setText("Your certificate has been approved by RA and is waiting for the signing from CA.");
                lblRequestApproved.setVisible(false);
                lblCertificateGenerated.setVisible(false);
                this.pnlValidDates.setVisible(false);
                this.jPanel5.setSize(this.jPanel5.getWidth(), pnlValidDates.getHeight());
                this.jPanel5.setVisible(true);
            } else if (_status.equals("ARCHIVED")) {
                this.jComboBox1.setForeground(new ValidCertColor());
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
            } else if (_status.equals("DELETED")) {
                this.jComboBox1.setForeground(new RevokedCertColor());
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
            } else {
                this.jComboBox1.setForeground(new RevokedCertColor());
                this.btnRenew.setEnabled(false);
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.pnlValidDates.setVisible(false);

                this.jPanel5.setSize(this.jPanel5.getWidth(), pnlValidDates.getHeight());
                this.jPanel5.setVisible(true);
            }
            //setup the Observable
            setupObservable();
        } else {

            //int indexOffline = jComboBox1.getSelectedIndex();
            this.DN.setText(offLineCertInfo.getDN(index));
            this.vFrom.setText(offLineCertInfo.getFormatStartDate(index));
            this.vTo.setText(offLineCertInfo.getFormatEndDate(index));
            this.rDue.setText(offLineCertInfo.getRenewDate(index));
            this.dRemaining.setText(offLineCertInfo.getLifeDays(index));
            this.email.setText(offLineCertInfo.getEmail(index));
            String _status = offLineCertInfo.getStatus(index);
            this.jPanel4.setBorder(new TitledBorder("Certificate Status: " + _status));

            if (_status.equals("Expired")) {
                this.jComboBox1.setForeground(new ExpiredCertColor());
                this.btnExport.setEnabled(true);
                this.btnDelete.setEnabled(true);
                this.btnInstall.setEnabled(true);
                this.btnRevoke.setEnabled(false);
                this.btnRenew.setEnabled(false);
            } else if (_status.equals("Valid")) {
                this.jComboBox1.setForeground(new ValidCertColor());
                this.btnDelete.setEnabled(true);
                this.btnRenew.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.btnInstall.setEnabled(true);
            } else {
                this.jComboBox1.setForeground(new PendingColor());
                this.btnRenew.setEnabled(false);
                this.btnExport.setEnabled(false);
                this.btnRevoke.setEnabled(false);
                this.pnlValidDates.setVisible(false);

                this.jPanel5.setSize(this.jPanel5.getWidth(), pnlValidDates.getHeight());
                this.jPanel5.setVisible(true);

                if (_status.equals("UnSubmitted")) {
                    lblRequestReceived.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/tick.png")));
                    lblRequestApproved.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/blank.png")));
                    lblRequestApproved.setVisible(false);
                    lblCertificateGenerated.setVisible(false);
                }
            }

        }
        //WaitDialog.hideDialog();
    }//GEN-LAST:event_jComboBox1ActionPerformed


    private void btnNewCertificateRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestActionPerformed
        // TODO add your handling code here:
        WaitDialog.showDialog();
        if( SystemStatus.ISONLINE ){
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                WaitDialog.hideDialog();
            }else{
                new Apply(this, PASSPHRASE).setVisible(true);
            }
        }else{ 
            new Apply(this, PASSPHRASE).setVisible(true);
            
        }
        WaitDialog.hideDialog();
    }//GEN-LAST:event_btnNewCertificateRequestActionPerformed

    private void btnImportCertificateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnImportCertificateActionPerformed
        // TODO add your handling code here:
        WaitDialog.showDialog();
        if( SystemStatus.ISONLINE ){
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                WaitDialog.hideDialog();
                return;
            }
        }

        JFileChooser importCert = new JFileChooser();
        importCert.addChoosableFileFilter(new certFilter());
        importCert.setMultiSelectionEnabled(false);
        if (importCert.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            File importFile = importCert.getSelectedFile();
            new ImportFilePassword(this, PASSPHRASE, importFile).setVisible(true);
        }
        WaitDialog.hideDialog();
    }//GEN-LAST:event_btnImportCertificateActionPerformed

    private void btnExportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExportActionPerformed
        // TODO add your handling code here:
        WaitDialog.showDialog();
        int index = jComboBox1.getSelectedIndex();
        X509Certificate cert = null;
        PrivateKey privateKey = null;
        ClientKeyStore keyStore = new ClientKeyStore(PASSPHRASE);
        
        if (SystemStatus.ISONLINE) {
            
            //check if connection is fine.
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                WaitDialog.hideDialog();
                return;
            }

            String _id = this.certificateCSRInfos[ this.jComboBox1.getSelectedIndex() ].getId();
            CertificateDownload certDownload = new CertificateDownload( _id );
            cert = certDownload.getCertificate();
            PublicKey publicKey = cert.getPublicKey();
            privateKey = keyStore.getPrivateKey(publicKey);
        } else {
            cert = offLineCertInfo.getCertificate(index);
            PublicKey publicKey = cert.getPublicKey();
            privateKey = keyStore.getPrivateKey(publicKey);
        }
        new ExportCertificate(cert, privateKey).setVisible(true);
        WaitDialog.hideDialog();
    }//GEN-LAST:event_btnExportActionPerformed

    private void btnRenewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRenewActionPerformed
        // TODO add your handling code here:
        WaitDialog.showDialog();
        if (SystemStatus.ISONLINE) {
            
            //check if connection is fine.
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                WaitDialog.hideDialog();
                return;
            }

            if( ! this.certificateCSRInfos[ this.jComboBox1.getSelectedIndex() ].getStatus().equals("VALID")){
                JOptionPane.showMessageDialog(this, "You haven't selected one valid certificate to renew!", "No suitable certificate selected", JOptionPane.INFORMATION_MESSAGE);
            } else {
                if (this.jComboBox1.getSelectedIndex() != -1) {
                    new OnLineConfirmation(this, "Renew", "Are you sure you want to renew the certificate with the following details?", this.jComboBox1.getSelectedIndex(), onLineCertInfo).setVisible(true);
                } else {
                    JOptionPane.showMessageDialog(this, "You haven't selected any certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
                }
            }

        } else {
            if (this.jComboBox1.getSelectedIndex() != -1) {
                new OffLineConfirmation(this, "Renew", "Are you sure you want to renew the certificate with the following details?", this.jComboBox1.getSelectedIndex(), offLineCertInfo).setVisible(true);
            } else {
                JOptionPane.showMessageDialog(this, "You haven't selected any certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            }
        }
        WaitDialog.hideDialog();
    }//GEN-LAST:event_btnRenewActionPerformed

    private void btnRevokeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRevokeActionPerformed
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            WaitDialog.showDialog();
            //check if connection is fine.
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                WaitDialog.hideDialog();
                return;
            }

            if( ! this.certificateCSRInfos[ this.jComboBox1.getSelectedIndex() ].getStatus().equals( "VALID")){
                JOptionPane.showMessageDialog(this, "You haven't selected one valid certificate to revoke!", "No suitable certificate selected", JOptionPane.INFORMATION_MESSAGE);
            } else {
                if (this.jComboBox1.getSelectedIndex() != -1) {
                    new OnLineConfirmation(this, "Revoke", "Are you sure you want to revoke the certificate with the following details?", this.jComboBox1.getSelectedIndex(), onLineCertInfo).setVisible(true);
                } else {
                    JOptionPane.showMessageDialog(this, "You haven't selected any certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
                }
            }
            WaitDialog.hideDialog();
        } else {
            JOptionPane.showMessageDialog(this, "The certificate can not be revoked by offline. Please do it online.", "No offline certificate revocation", JOptionPane.INFORMATION_MESSAGE);
        }
        
    }//GEN-LAST:event_btnRevokeActionPerformed

    private void btnDeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDeleteActionPerformed
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            WaitDialog.showDialog();
            //check if connection is fine.
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                WaitDialog.hideDialog();
                return;
            }
            
            if (this.jComboBox1.getSelectedIndex() != -1) {
                new OnLineConfirmation(this, "Remove", "Are you sure you want to remove the certificate with the following details?", this.jComboBox1.getSelectedIndex(), onLineCertInfo).setVisible(true);
            } else {
                JOptionPane.showMessageDialog(this, "You haven't selected any certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            }
            WaitDialog.hideDialog();
        } else {
            if (this.jComboBox1.getSelectedIndex() != -1) {
                new OffLineConfirmation(this, "Remove", "Are you sure you want to remove the certificate with the following details?", this.jComboBox1.getSelectedIndex(), offLineCertInfo).setVisible(true);
            } else {
                JOptionPane.showMessageDialog(this, "You haven't selected any certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            }
        }
        
    }//GEN-LAST:event_btnDeleteActionPerformed

    private void btnNewCertificateRequestMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseEntered
        // TODO add your handling code here:
        setMOD("Request a new user certificate");
    }//GEN-LAST:event_btnNewCertificateRequestMouseEntered

    private void formMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_formMouseExited
        // TODO add your handling code here:
    }//GEN-LAST:event_formMouseExited

    private void jPanel1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jPanel1MouseExited
        // TODO add your handling code here:
    }//GEN-LAST:event_jPanel1MouseExited

    private void btnNewCertificateRequestMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnNewCertificateRequestMouseExited

    private void btnImportCertificateMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseEntered
        // TODO add your handling code here:
        setMOD("Import an existing certificate into the certificate wizard");
    }//GEN-LAST:event_btnImportCertificateMouseEntered

    private void jComboBox1MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseEntered
        // TODO add your handling code here:
        setMOD("List of certificates in the Certificate Tool");
    }//GEN-LAST:event_jComboBox1MouseEntered

    private void btnRenewMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseEntered
        // TODO add your handling code here:
        setMOD("Renew a valid certificate from 30 days before it expires");
    }//GEN-LAST:event_btnRenewMouseEntered

    private void btnExportMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseEntered
        // TODO add your handling code here:
        setMOD("Export your certificate to a file, for backing up, or for use in other tools");
    }//GEN-LAST:event_btnExportMouseEntered

    private void btnRevokeMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseEntered
        // TODO add your handling code here:
        setMOD("Revoke your certificate if it is compromised or invalid");
    }//GEN-LAST:event_btnRevokeMouseEntered

    private void btnDeleteMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseEntered
        // TODO add your handling code here:
        setMOD("Remove your certificate from the tool. This will not delete any other copies of the certificate from your computer. \n\nPlease note, you will lose the certificate once you click the Remove button, unless you backup the configuration files and overwrite later.");
    }//GEN-LAST:event_btnDeleteMouseEntered

    private void btnInstallActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnInstallActionPerformed
        // TODO add your handling code here:
        WaitDialog.showDialog();
        CoGProperties props = CoGProperties.getDefault();
        String certPemFile = props.getUserCertFile();
        String keyPemFile = props.getUserKeyFile();

        String message = "<html>Are you sure you want to install pem files in <br>[" + certPemFile + "] and [" + keyPemFile + "]?";

        int index = jComboBox1.getSelectedIndex();
        X509Certificate cert = null;
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        ClientKeyStore keyStore = new ClientKeyStore(PASSPHRASE);

        if (SystemStatus.ISONLINE) {
            //check if connection is fine.
            if( !isPing() ){
                JOptionPane.showMessageDialog(this, "There is a problem to connect with server, \nplease report to helpdesk or work under offline by restarting CertWizard and select offline.", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
                WaitDialog.hideDialog();
                return;
            }

            String _id = this.certificateCSRInfos[ index ].getId();
            CertificateDownload certDownload = new CertificateDownload(_id);
            cert = certDownload.getCertificate();

            publicKey = cert.getPublicKey();
            privateKey = keyStore.getPrivateKey(publicKey);

            if( ! this.certificateCSRInfos[ index ].getStatus().equals("VALID")){
                JOptionPane.showMessageDialog(this, "You haven't selected one valid certificate!", "No suitable certificate selected", JOptionPane.INFORMATION_MESSAGE);
            } else {
                if (this.jComboBox1.getSelectedIndex() != -1) {
                    boolean isSuccess = isSuccessPemFiles( cert, privateKey );
                    if( isSuccess ){
                        String _message = "<html>Your certificate and private key were successfully installed to:<br>Private key: " + keyPemFile + "<br>Certificate: " + certPemFile;
                        JOptionPane.showMessageDialog(this, _message, "Successful Install", JOptionPane.INFORMATION_MESSAGE);
                        String _passphrase = new String(PASSPHRASE);
                        String _property = SysProperty.getValue("uk.ngs.ca.immegration.password.property");
                        System.setProperty(_property, _passphrase);
                    }else{
                        String _message = "<html>Your certificate and private key failed to install on:<br>Private key: " + keyPemFile + "Certificate: " + certPemFile;
                        JOptionPane.showMessageDialog(this, _message, "Failed Install", JOptionPane.INFORMATION_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(this, "You haven't selected any certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
                }
            }

        } else {
            cert = offLineCertInfo.getCertificate(index);
            publicKey = cert.getPublicKey();
            privateKey = keyStore.getPrivateKey(publicKey);

            if (this.jComboBox1.getSelectedIndex() != -1) {
                boolean isSuccess = isSuccessPemFiles( cert, privateKey );
                if( isSuccess ){
                    String _message = "<html>Your certificate and private key were successfully installed to:<br>Private key: " + keyPemFile + "<br>Certificate: " + certPemFile;
                    JOptionPane.showMessageDialog(this, _message, "Successful Install", JOptionPane.INFORMATION_MESSAGE);
                    String _passphrase = new String(PASSPHRASE);
                    String _property = SysProperty.getValue("uk.ngs.ca.immegration.password.property");
                    System.setProperty(_property, _passphrase);

                }else{
                    String _message = "<html>Your certificate and private key failed to install on:<br>Private key: " + keyPemFile + "Certificate: " + certPemFile;
                    JOptionPane.showMessageDialog(this, _message, "Failed Install", JOptionPane.INFORMATION_MESSAGE);
                }
            } else {
                JOptionPane.showMessageDialog(this, "You haven't selected any certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            }
        }

        WaitDialog.hideDialog();

    }//GEN-LAST:event_btnInstallActionPerformed

    private void btnInstallMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseEntered
        // TODO add your handling code here:
        setMOD("Install your certificate to PEM files.");
    }//GEN-LAST:event_btnInstallMouseEntered

    private void btnInstallMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnInstallMouseExited

    private void btnImportCertificateMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnImportCertificateMouseExited

    private void jComboBox1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_jComboBox1MouseExited

    private void btnRenewMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnRenewMouseExited

    private void btnExportMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnExportMouseExited

    private void btnRevokeMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnRevokeMouseExited

    private void btnDeleteMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseExited
        // TODO add your handling code here:
        if (SystemStatus.ISONLINE) {
            setMOD(MotD);
        }else{
            setRedMOD( MotD );
        }
    }//GEN-LAST:event_btnDeleteMouseExited

    private void jComboBox1ItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_jComboBox1ItemStateChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBox1ItemStateChanged

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
        if (SystemStatus.ISONLINE) {
            if( this.certificateCSRInfos[ _index ] != null ){
                ListCellRenderer renderer = new ListItemRenderer();
                String _dn = this.certificateCSRInfos[ _index ].getOwner();
                String _status = this.certificateCSRInfos[ _index ].getStatus();

                Object[] element = new Object[2];
                if (_status.equals("VALID")) {
                    String _lifedays = this.certificateCSRInfos[ _index ].getLifeDays();
                    int int_lifedays = new Integer( _lifedays ).intValue();
                    if( int_lifedays < 0 ){
                        if( int_lifedays >= -30 ){
                            element[ 0 ] =  new ExpiredCertColor();
                        }else{
                            element[ 0 ] = new ExpiredForeverCertColor();
                        }
                    }else{
                        element[ 0 ] = new ValidCertColor();
                    }

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
        if (SystemStatus.ISONLINE) {

            if( this.certificateCSRInfos != null ){
                ListCellRenderer renderer = new ListItemRenderer();
                for( int i = 0; i < this.certificateCSRInfos.length; i++ ){
                    String _dn = this.certificateCSRInfos[ i ].getOwner();
                    String _status = this.certificateCSRInfos[ i ].getStatus();

                    Object element[] = new Object[3];
                    if (_status.equals("VALID")) {
                        String _lifedays = this.certificateCSRInfos[ i ].getLifeDays();
                        int int_lifedays = new Integer( _lifedays ).intValue();
                        if( int_lifedays < 0 ){
                            if( int_lifedays >= -30 ){
                                element[ 0 ] =  new ExpiredCertColor();
                            }else{
                                element[ 0 ] = new ExpiredForeverCertColor();
                            }
                        }else{
                            element[ 0 ] = new ValidCertColor();
                        }

                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else if (_status.equals("REVOKED")) {
                        element[ 0 ] = new RevokedCertColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else if (_status.equals("SUSPENDED")) {
                        element[ 0 ] = new SuspendCertColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else if (_status.equals("NEW")) {
                        element[ 0 ] = new PendingColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else if (_status.equals("RENEW")) {
                        element[ 0 ] = new RenewalDueColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else if (_status.equals("APPROVED")) {
                        element[ 0 ] = new SuspendCertColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else if (_status.equals("ARCHIVED")) {
                        element[ 0 ] = new ValidCertColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else if (_status.equals("DELETED")) {
                        element[ 0 ] = new RevokedCertColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    } else {
                        element[ 0 ] = new RevokedCertColor();
                        element[ 1 ] = _dn;
                        element[ 2 ] = _status;
                    }
                    jComboBox1.addItem(element);
                }
                jComboBox1.setRenderer(renderer);
            }
        } else {
            String[] DNs = offLineCertInfo.getAllDNs();
            if (DNs != null) {
                ListCellRenderer renderer = new ListItemRenderer();

                for (int i = 0; i < DNs.length; i++) {
                    String _dn = offLineCertInfo.getDN(i);
                    String _status = offLineCertInfo.getStatus(i);
                    Object element[] = new Object[2];
                    if (_status.equals("Expired")) {
                        element[ 0] = new ExpiredCertColor();
                        element[ 1] = _dn;
                    } else if (_status.equals("Valid")) {
                        element[ 0] = new ValidCertColor();
                        element[ 1] = _dn;
                    } else {
                        element[ 0] = new PendingColor();
                        element[ 1] = _dn;
                    }

                    jComboBox1.addItem(element);
                }
                jComboBox1.setRenderer(renderer);
            }
        }

    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextField DN;
    private javax.swing.JTextArea TextMOD;
    private javax.swing.JButton btnDelete;
    private javax.swing.JButton btnExport;
    private javax.swing.JButton btnImportCertificate;
    private javax.swing.JButton btnInstall;
    private javax.swing.JButton btnNewCertificateRequest;
    private javax.swing.JButton btnRenew;
    private javax.swing.JButton btnRevoke;
    private javax.swing.JTextField dRemaining;
    private javax.swing.JTextField email;
    private javax.swing.JComboBox jComboBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JPanel jPanel5;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel lblCertificateGenerated;
    private javax.swing.JLabel lblRequestApproved;
    private javax.swing.JLabel lblRequestReceived;
    private javax.swing.JPanel pnlAllDetails;
    private javax.swing.JPanel pnlValidDates;
    private javax.swing.JTextField rDue;
    private javax.swing.JTextField vFrom;
    private javax.swing.JTextField vTo;
    // End of variables declaration//GEN-END:variables


}
