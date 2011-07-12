package uk.ngs.certwizard.gui;

import java.awt.Color;
import java.awt.Component;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;

import java.util.Iterator;
import java.util.Observable;
import java.util.Observer;
import java.util.ResourceBundle;
import net.sf.portecle.DExport;
import net.sf.portecle.DGetAlias;
import net.sf.portecle.DImportKeyPair;
import net.sf.portecle.DViewCertificate;
import net.sf.portecle.FPortecle;
import net.sf.portecle.FileChooserFactory;
import net.sf.portecle.KeyStoreWrapper;
import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.KeyStoreUtil;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.LastDir;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;
import net.sf.portecle.gui.password.DGetNewPassword;
import net.sf.portecle.gui.password.DGetPassword;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.openssl.PasswordFinder;
import org.bouncycastle.util.encoders.Base64;
import org.globus.common.CoGProperties;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.util.PEMUtils;
import org.globus.util.Util;
import uk.ngs.ca.certificate.OnLineUserCertificateReKey;

import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.certificate.client.CAMotd;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * GUI for displaying the keyStore entries in the user's '$HOME/.ca/cakeystore.pkcs12' file.
 * This class also provides functions for importing, exporting, deleting 
 * requesting, requesting, renewing certificates.
 *
 * @author David Meredith
 */
public class MainWindowPanel2 extends javax.swing.JPanel implements Observer {

    private ImageIcon[] images;
    private String stringMotD = "Message of the Day: \n\n\nWelcome to the new Certificate Wizard!";
    private final CAMotd motd = new CAMotd();
    private char[] PASSPHRASE;
    private ClientKeyStoreCaServiceWrapper keyStoreCaWrapper = null;

    /** The last directory accessed by the application */
    private final LastDir m_lastDir = new LastDir();

    /** Portecle Resource bundle base name */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";

    /** Portecle Resource bundle */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);


    /** Creates new form MainWindowPanel */
    public MainWindowPanel2(char[] passphrase, CertWizardMain _certWizardMain) {
        this.PASSPHRASE = passphrase;
        String _passphrase = new String(passphrase);
        WaitDialog.showDialog("Refresh");
        String _property = SysProperty.getValue("uk.ngs.ca.immegration.password.property");
        System.setProperty(_property, _passphrase);
        
        initComponents();
        loadImages();

        try {
            this.keyStoreCaWrapper = ClientKeyStoreCaServiceWrapper.getInstance(passphrase);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MainWindowPanel2.class.getName()).log(Level.SEVERE, null, ex);
            // TODO still need to sort out exceptions and show an error dialog here with the problem
        }


        // do some assertions to check object references are equal. 
        assert (ClientKeyStore.getClientkeyStore(this.PASSPHRASE).getKeyStore()
                == this.keyStoreCaWrapper.getClientKeyStore().getKeyStore());


        this.jComboBox1.setRenderer(new ComboBoxRenderer());
        this.reloadKeystoreUpdateGUI();

        if (SystemStatus.getInstance().getIsOnline()) {
            stringMotD = motd.getText();
            setMOD(stringMotD);
            String certWizardVersion = SysProperty.getValue("ngsca.certwizard.versionNumber");
            //Now fetch the latest version from the server. Required info is in DBCAInfo, ultimately
            //handled by the CAResource class.
            String latestVersion = motd.getLatestVersion();
            if (!(certWizardVersion.equals(latestVersion))) {
                JOptionPane.showMessageDialog(this, "A new version of the Certificate Wizard is available!\n"
                        + "Please go to www.ngs.ac.uk in order to obtain the latest version",
                        "New Version of Certificate Wizard", JOptionPane.INFORMATION_MESSAGE);
            }
        }
        WaitDialog.hideDialog();
    }

    /**
     * The keystore is reloaded and the GUI is updated when invoked by another
     * (e.g. observable) class.
     * @param   o     the observable object.
     * @param   arg   an argument passed to the <code>notifyObservers</code> method.
     */
    public void update(Observable observable, Object obj) {
        this.reloadKeystoreUpdateGUI();
    }

    /** Load the images used in the GUI */
    private void loadImages() {
        //Load the pet images and create an array of indexes.
        images = new ImageIcon[3];
        images[0] = createImageIcon("/uk/ngs/ca/images/certificate_node.gif");
        images[0].setDescription("Trusted certificate");
        images[1] = createImageIcon("/uk/ngs/ca/images/key_node.gif");
        images[1].setDescription("Key");
        images[2] = createImageIcon("/uk/ngs/ca/images/keypair_node.gif");
        images[2].setDescription("Key Pair (public and private keys)");
    }

    /** Returns an ImageIcon, or null if the path was invalid. */
    private ImageIcon createImageIcon(String path) {
        java.net.URL imgURL = MainWindowPanel2.class.getResource(path);
        if (imgURL != null) {
            return new ImageIcon(imgURL);
        } else {
            System.err.println("Couldn't find file: " + path);
            return null;
        }
    }

    /**
     * Reload the keyStore and update the GUI accordingly. Called when:
     * <ol>
     *  <li>refresh button</li>
     *  <li>apply for cert (via Observer update function - TODO refactor to do it explicitly like renew/revoke)</li>
     *  <li>renew cert</li>
     *  <li>revoke cert</li>
     *  <li>importing new cert/key pair from file</li>
     * </ol>
     */
    private void reloadKeystoreUpdateGUI() {
        try {
            this.keyStoreCaWrapper.loadKeyStoreWithOnlineUpdate();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MainWindowPanel2.class.getName()).log(Level.SEVERE, null, ex);
            JOptionPane.showMessageDialog(this, "Unable to load KeyStore: " + ex.getMessage(), "Unable to load KeyStore", JOptionPane.ERROR_MESSAGE);
        }
        this.updateGUI();
    }

    /**
     * Update the entire main panel GUI (including combo and other GUI components)
     * according to the current state of <code>this.keyStoreCaWrapper<code>
     * (note, no reload of keystore !)
     */
    private void updateGUI() {
        this.updateCombo();
        this.updateGUIPanel();
    }

    /**
     * Update combo based on current state of <code>this.keyStoreCaWrapper<code>
     * (note, no reload of keystore !)
     */
    private void updateCombo() {
        jComboBox1.removeAllItems();
        Collection<KeyStoreEntryWrapper> keyStoreEntries = this.keyStoreCaWrapper.getKeyStoreEntryMap().values();
        for (Iterator<KeyStoreEntryWrapper> it = keyStoreEntries.iterator(); it.hasNext();) {
            this.jComboBox1.addItem(it.next());
        }
        if(this.jComboBox1.getItemCount() > 0){
          this.jComboBox1.setSelectedIndex(0);
        } else {
            this.jComboBox1.setSelectedItem(null); 
        }
    }

    /**
     * Update other GUI components based on current state of <code>this.keyStoreCaWrapper<code>
     * (note, no reload of keystore !)
     */
    private void updateGUIPanel() {
        // nullify/clear the gui components first
        this.vFrom.setText("");
        this.vTo.setText("");
        this.subjectDnTextField.setText("");
        this.issuerDnTextField.setText("");
        this.caCertStatusTextField.setText("Unknown (offline or not issued by UK CA)");
        // set to default color first
        this.caCertStatusTextField.setForeground(this.getColorFromState(null));
        this.aliasTextField.setText("");
        this.certificateTypeLabel.setText("");
        this.certificateTypeLabel.setIconTextGap(10);
        this.certificateTypeLabel.setIcon(null);

        // now udpate 
        KeyStoreEntryWrapper selectedKeyStoreEntry = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        // could be null if we have an empty keystore !
        if (this.jComboBox1.getSelectedIndex() != -1 && selectedKeyStoreEntry != null) {
            this.subjectDnTextField.setText(selectedKeyStoreEntry.getX500PrincipalName());
            this.issuerDnTextField.setText(selectedKeyStoreEntry.getIssuerName());
            this.aliasTextField.setText(selectedKeyStoreEntry.getAlias());

            if(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_ENTRY.equals(selectedKeyStoreEntry.getEntryType())){
                this.certificateTypeLabel.setText("Key");
                this.certificateTypeLabel.setIcon(this.images[1]);
            } else if(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKeyStoreEntry.getEntryType())){
                this.certificateTypeLabel.setText("Certificate + Private Key");
                this.certificateTypeLabel.setIcon(this.images[2]);
            } else if(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.TRUST_CERT_ENTRY.equals(selectedKeyStoreEntry.getEntryType())){
                this.certificateTypeLabel.setText("Trusted Third Party Certificate");
                this.certificateTypeLabel.setIcon(this.images[0]);
            }


            if (selectedKeyStoreEntry.getNotBefore() != null) {
                this.vFrom.setText(selectedKeyStoreEntry.getNotBefore().toString());
            } else {
                this.vFrom.setText("N/A");
            }

            if (selectedKeyStoreEntry.getNotAfter() != null) {
                this.vTo.setText(selectedKeyStoreEntry.getNotAfter().toString());
            } else {
                this.vTo.setText("N/A");
            }
            
            // If the CertificateCSRInfo member object of the selected
            // keyStoreEntryWrapper is null, then we did not retrieve
            // the CA server info for this cert (maybe offline or an unrecognized
            // certificate not issued by our CA).
            if (selectedKeyStoreEntry.getServerCertificateCSRInfo() != null) {
                String state = selectedKeyStoreEntry.getServerCertificateCSRInfo().getStatus();
                //labelText += selectedKeyStoreEntry.getServerCertificateCSRInfo().getOwner();
                this.caCertStatusTextField.setText(state + " " + this.getExtraLabelTextFromState(state));
                this.caCertStatusTextField.setForeground(this.getColorFromState(state));
            }
        }
        //((TitledBorder)this.jPanel2.getBorder()).setTitle("Your Certificates and Requests ("+this.jComboBox1.getItemCount()+" entries)");
    }

    /**
     * Renderer class for KeyStoreEntryWrapper objects for the combo box.
     */
    class ComboBoxRenderer extends JLabel implements ListCellRenderer {

        public ComboBoxRenderer() {
            setOpaque(true);
            //setHorizontalAlignment(CENTER);
            //setVerticalAlignment(CENTER);
        }

        public Component getListCellRendererComponent(JList list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
            //Get the selected index. (The index param isn't always valid, so just use the value.)
            //int selectedIndex = ((Integer)value).intValue();

            if (isSelected) {
                setBackground(list.getSelectionBackground());
                setForeground(list.getSelectionForeground());
            } else {
                setBackground(list.getBackground());
                setForeground(list.getForeground());
            }
                        
            // Can assume that we are dealing with KeyStoreEntryWrapper objects.
            KeyStoreEntryWrapper keyStoreEntry = (KeyStoreEntryWrapper) value;
            // can be null if the keyStore is empty ! 
            if (keyStoreEntry != null) {
                String displayText = "[" + keyStoreEntry.getAlias() + "]  [" + keyStoreEntry.getX500PrincipalName() + "]";
                this.setText(displayText);

                // want to display the modified date too
                //keyStoreEntry.getCreationDate();

                // Display an approprate icon dependng on keystore entry type
                if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_ENTRY.equals(keyStoreEntry.getEntryType())) {
                    this.setIcon(images[1]);
                } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.TRUST_CERT_ENTRY.equals(keyStoreEntry.getEntryType())) {
                    this.setIcon(images[0]);
                } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(keyStoreEntry.getEntryType())) {
                    this.setIcon(images[2]);
                } else {
                    // could set an unknown default
                }

                // Set the server status colour (if known). This info will only
                // be fetched if the info could be retrieved from the CA server.
                if (keyStoreEntry.getServerCertificateCSRInfo() != null) {
                    String state = keyStoreEntry.getServerCertificateCSRInfo().getStatus();
                    this.setForeground(getColorFromState(state));
                } else {
                    this.setForeground(Color.DARK_GRAY);
                }
            } else {
                this.setText("No Key Store Entries");
                this.setIcon(null);
            }
            return this;
        }
    }

    /**
     * Return the appropriate display colour according to the given
     * state string. If state is null or not recognised,
     * then return <code>Color.DARK_GRAY</code> as default.
     */
    private Color getColorFromState(String state) {
        if ("VALID".equals(state)) {
            return new ValidCertColor();
            // TODO also need to pass two dates to this method so that the
            // ExpiredCertColor and ExpiredForeverCertColor can be returned.
            // Passing null for these dates will be perfectly valid. 
        } else if ("REVOKED".equals(state)) {
            return new RevokedCertColor();
        } else if ("NEW".equals(state)) {
            // Your certificate request has been submitted and is waiting for approval.
            return new PendingColor();
        } else if ("SUSPENDED".equals(state)) {
            return new SuspendCertColor();
        } else if ("RENEW".equals(state)) {
            // Your renewal certificate request has been submitted and is waiting for approval.
            return new RenewalDueColor();
        } else if ("APPROVED".equals(state)) {
            // Your certificate has been approved by your RA and is waiting for CA signing.
            return new SuspendCertColor();
        } else if ("ARCHIVED".equals(state)) {
            return new ValidCertColor();
        } else if ("DELETED".equals(state)) {
            return new RevokedCertColor();
        } else if ("Expired".equals(state)) {
            return new ExpiredCertColor();
        } else {
            return Color.DARK_GRAY;
        }
    }

    /**
     * Return any extra label text that is appropriate to the given state.
     */
    private String getExtraLabelTextFromState(String state) {
        if ("VALID".equals(state)) {
            return "";
            // TODO also need to pass two dates to this method so that the
            // ExpiredCertColor and ExpiredForeverCertColor can be returned.
            // Passing null for these dates will be perfectly valid.
        } else if ("REVOKED".equals(state)) {
            return "";
        } else if ("NEW".equals(state)) {
            return "Your certificate request has been submitted and is waiting for approval";
        } else if ("SUSPENDED".equals(state)) {
            return "";
        } else if ("RENEW".equals(state)) {
            return "Your renewal certificate request has been submitted and is waiting for approval";
        } else if ("APPROVED".equals(state)) {
            return "Your certificate has been approved by your RA and is waiting for CA signing";
        } else if ("ARCHIVED".equals(state)) {
            return "";
        } else if ("DELETED".equals(state)) {
            return "";
        } else if ("Expired".equals(state)) {
            return "";
        } else {
            return "";
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // The next 3 methods (renew, revoke, new) all require contacting the
    // CA service online
    ///////////////////////////////////////////////////////////////////////////

    /** Called by the Renew button  */
    private void doRenewAction() {
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (!isOnlinePing()) {
            JOptionPane.showMessageDialog(this, "Cannot connect", "Server Connection Fault", JOptionPane.ERROR_MESSAGE);
            stringMotD = "You are working offline.\n\nThe certificate can not be renewed offline.";
            setRedMOD(stringMotD);
            this.btnRefresh.setText("Connect");
            return;
        }
        // Can only renew key_pairs types issued by our CA
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        if (selectedKSEW != null
                && KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                && selectedKSEW.getServerCertificateCSRInfo() != null
                && "VALID".equals(((KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem()).getServerCertificateCSRInfo().getStatus())) {

            int ok = JOptionPane.showConfirmDialog(this, "Are you sure you want to renew the selected certificate?", "Renew Certificate", JOptionPane.OK_CANCEL_OPTION);
            if (JOptionPane.OK_OPTION == ok) {
                WaitDialog.showDialog("Renew");
                String cert_id = selectedKSEW.getServerCertificateCSRInfo().getId();
                CertificateDownload certDownload = new CertificateDownload(cert_id);
                OnLineUserCertificateReKey rekey = new OnLineUserCertificateReKey(PASSPHRASE);
                rekey.addCertificate(certDownload.getCertificate());
                boolean isValidRekey = rekey.isValidReKey();
                boolean submittedOk = rekey.doPosts();
                // TODO: may be better just to reload the selected entry rather than refresh them all ?
                this.reloadKeystoreUpdateGUI();
                WaitDialog.hideDialog();
                if (isValidRekey) {
                    if (submittedOk) {
                        JOptionPane.showMessageDialog(this, "The renewal request has been submitted", "Renewal request successful", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        String messageTitle = rekey.getErrorMessage();
                        String moreMessage = rekey.getDetailErrorMessage();
                        JOptionPane.showMessageDialog(this, moreMessage, messageTitle, JOptionPane.WARNING_MESSAGE);
                    }
                } else {
                    JOptionPane.showMessageDialog(this, "The selected certificate is not valid to renew", "wrong certificate", JOptionPane.WARNING_MESSAGE);
                }
            }
        } else {
            JOptionPane.showMessageDialog(this, "Only VALID certificates issued by the UK CA can be renewed",
                    "No suitable certificate selected", JOptionPane.WARNING_MESSAGE);
        }
    }

    /** Called by the Revoke button  */
    private void doRevokeAction(){
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        if (!isOnlinePing()) {
            JOptionPane.showMessageDialog(this, "Cannot connect", "Server Connection Fault", JOptionPane.ERROR_MESSAGE);
            stringMotD = "You are working offline.\n\nThe certificate can not be revoked offline.";
            setRedMOD(stringMotD);
            this.btnRefresh.setText("Connect");
            return;
        }
        // Can only revoke key_pairs types issued by our CA
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        if (selectedKSEW != null
                && KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                && selectedKSEW.getServerCertificateCSRInfo() != null
                && "VALID".equals(((KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem()).getServerCertificateCSRInfo().getStatus())) {

            int ok = JOptionPane.showConfirmDialog(this, "Are you sure you want to revoke the selected certificate?", "Revoke Certificate", JOptionPane.OK_CANCEL_OPTION);
            if (JOptionPane.OK_OPTION == ok) {
                String reason = "todo"; // TODO: use an inputDialog to get the reason as below
                //JOptionPane.showInputDialog(this, "message", "reason for revokation", JO)
                WaitDialog.showDialog("Revoke");
                long cert_id = new Long(selectedKSEW.getServerCertificateCSRInfo().getId()).longValue();
                RevokeRequest revokeRequest = new RevokeRequest(
                        this.keyStoreCaWrapper.getClientKeyStore().getPrivateKey(selectedKSEW.getAlias()),
                        cert_id, reason);
                boolean revoked = revokeRequest.doPosts();  // do the revokation and block
                // TODO: may be better just to reload the selected entry rather than refresh them all ?
                this.reloadKeystoreUpdateGUI();
                WaitDialog.hideDialog();
                if (revoked) {
                    JOptionPane.showMessageDialog(this, revokeRequest.getMessage(), "Certificate revoked", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(this, revokeRequest.getMessage(), "Problem revoking certificate", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        } else {
            JOptionPane.showMessageDialog(this, "Only VALID certificates issued by the UK CA can be revoked",
                    "No suitable certificate selected", JOptionPane.WARNING_MESSAGE);
        }
    }

    /** Called by the Apply button  */
    private void doNewCertificateAction() {
        if (!this.isOnlinePing()) {
            JOptionPane.showMessageDialog(this, "Cannot connect to the server, \n please check your network connection", "Server Connection Fault", JOptionPane.INFORMATION_MESSAGE);
            stringMotD = "You are working offline.\n\nYou must be online in order to apply for a new certificate.";
            return;
        } else {
            Apply2 apply = new Apply2(this, PASSPHRASE);
            apply.setModal(true);
            apply.setVisible(true);
        }
    }


    ///////////////////////////////////////////////////////////////////////////
    // The next 5 methods (delete, viewDetails, export, install, import)
    // are generic keystore actions that do not require the CA service.
    ///////////////////////////////////////////////////////////////////////////


    /** Called by the Delete button to delete selected keyStore entry (not revocation)  */
    private void doDeleteAction() {
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
        } else {
            int delete = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete this KeyStore entry ?", "Delete KeyStore Entry", JOptionPane.OK_CANCEL_OPTION);
            if (delete == JOptionPane.OK_OPTION) {
                try {
                     this.keyStoreCaWrapper.deleteEntry(((KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem()).getAlias());
                     this.updateGUI();
                } catch (KeyStoreException ex) {
                    Logger.getLogger(MainWindowPanel2.class.getName()).log(Level.SEVERE, null, ex);
                    JOptionPane.showMessageDialog(this, "Unable to delete KeyStore entry: " + ex.getMessage(), "Unable to delete KeyStore entry", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }


    /**
     * Let the user see the certificate details of the selected keystore entry.
     * Based on Portecle. 
     * @see FPortecle#showSelectedEntry()
     */
    private void doViewCertificateDetailsAction() {
        // check that a certificate is selected
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || selectedType.equals(selectedType.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        String sAlias = selectedKSEW.getAlias();
        KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();
        try {
            // Get the entry's certificates
            X509Certificate[] certs;
            if (keyStore.isKeyEntry(sAlias)) {
                // If entry is a key pair
                certs = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sAlias));
            } else {
                // If entry is a trusted certificate
                certs = new X509Certificate[1];
                certs[0] = X509CertUtil.convertCertificate(keyStore.getCertificate(sAlias));
            }

            // Supply the certificates to the view certificate dialog
	    DViewCertificate dViewCertificate =
			    new DViewCertificate(null, MessageFormat.format(
			        RB.getString("FPortecle.CertDetailsEntry.Title"), sAlias), certs);
            dViewCertificate.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dViewCertificate);

        } catch (Exception ex) {
            DThrowable.showAndWait(null, null, ex);
        }
    }

    /**
     * Let the user export the selected entry.
     * Based on Portecle.
     * @see FPortecle#exportSelectedEntry()
     *
     * @return True if the export is successful, false otherwise
     */
    private boolean doExportAction() {
        // check that a certificate is selected
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return false;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || selectedType.equals(selectedType.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return false;
        }
        // Get the entry
        String sAlias = selectedKSEW.getAlias();
        try {
            // Display the Generate Key Pair dialog to get the key
            // pair generation parameters from the user. We create
            // a new KeyStoreWrapper because this is required by
            // the DExport constructor.
            DExport dExport = new DExport(null,
                    new KeyStoreWrapper(this.keyStoreCaWrapper.getClientKeyStore().getKeyStore()), sAlias);
            dExport.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dExport);
            if (!dExport.exportSelected()) {
                return false; // User canceled the dialog
            }

            // Do export
            boolean bSuccess = false;

            // Export head certificate only
            if (dExport.exportHead()) {
                // Export PEM encoded format
                if (dExport.exportPem()) {
                    bSuccess = exportHeadCertOnlyPem(sAlias);
                } // Export DER encoded format
                else if (dExport.exportDer()) {
                    bSuccess = exportHeadCertOnlyDER(sAlias);
                } // Export PkiPath format
                else if (dExport.exportPkiPath()) {
                    bSuccess = exportHeadCertOnlyPkiPath(sAlias);
                } // Export PKCS #7 format
                else // if (dExport.exportPkcs7())
                {
                    bSuccess = exportHeadCertOnlyPkcs7(sAlias);
                }
            } // Complete certification path (PKCS #7 or PkiPath)
            else if (dExport.exportChain()) {
                if (dExport.exportPkiPath()) {
                    //bSuccess = exportAllCertsPkiPath(sAlias);
                } else // if (dExport.exportPkcs7())
                {
                    bSuccess = exportAllCertsPkcs7(sAlias);
                }
            } // Complete certification path and private key (PKCS #12)
            else {
                if (dExport.exportPem()) {
                    bSuccess = exportPrivKeyCertChainPEM(sAlias);
                } else // if (dExport.exportPkcs12())
                {
                    bSuccess = exportPrivKeyCertChainPKCS12(sAlias);
                }
            }

            if (bSuccess) {
                // Display success message
		JOptionPane.showMessageDialog(this, RB.getString("FPortecle.ExportSuccessful.message"),
	            RB.getString("FPortecle.Export.Title"), JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        }
        return true;
    }

    /** Install the selected cert as '$HOME/.globus/usercert.pem'
     * and '$HOME/.globus/userkey.pem' for subsequent globus usage */
    private void doInstallSelectedCertificateAction() {
        // check that a certificate is selected
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || !selectedType.equals(selectedType.KEY_PAIR_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate and key pair!", "No certificate key pair selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        // ok, export the selected cert 
        // TODO: remove the dependency on GoGProperties (we can do this ourselves - better to not depend on this) 
        CoGProperties props = CoGProperties.getDefault();
        String certPemFile = props.getUserCertFile();
        String keyPemFile = props.getUserKeyFile();
        File fCertFile = new File(certPemFile);
        File fKeyFile = new File(keyPemFile);
        // check usercert.pem and userkey.pem do not already exist.
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
            overwriteWarning += "\nAre you sure you want to overwrite these files ?";
            int ret = JOptionPane.showConfirmDialog(this, overwriteWarning, "Certificate/Key Installation", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (JOptionPane.YES_OPTION != ret) {
                return;
            }
        }
        // ok, here we can export the cert and key as pem files.    
        FileOutputStream certfos = null; 
        try {
            // first, delete files (if they already exist) 
            fCertFile.delete();
            fKeyFile.delete();
            // get X509Cert and Private key of selected alias 
            String alias = selectedKSEW.getAlias() ; 
            X509Certificate certificate = (X509Certificate)this.keyStoreCaWrapper.getClientKeyStore().getKeyStore().getCertificate( alias ); 
            PrivateKey privateKey = (PrivateKey)this.keyStoreCaWrapper.getClientKeyStore().getKeyStore().getKey(alias, PASSPHRASE); 
            // Write the certificate 
            // TODO - remove dependency on org.globus.util.PEMUtils (we can do this ourselves - better to not depend on this)
            // TODO - remove dependency on org.globus.util.Util (we can do this ourselves - better to not depend on this)
            certfos = new FileOutputStream(fCertFile);
            PEMUtils.writeBase64(certfos, "-----BEGIN CERTIFICATE-----", Base64.encode(certificate.getEncoded()), "-----END CERTIFICATE-----");
            Util.setFilePermissions(certPemFile, 444);
            
            // Write the key - need to remove dependency on the bouncycastle here !
            BouncyCastleOpenSSLKey bcosk = new BouncyCastleOpenSSLKey(privateKey);
            bcosk.encrypt(new String(PASSPHRASE));
            bcosk.writeTo(keyPemFile);
            Util.setFilePermissions(keyPemFile, 400);
            
            JOptionPane.showMessageDialog(this, "usercert.pem and userkey.pem exported OK to '$USER_HOME/.globus/'",
	            "Export usercert.pem userkey.pem", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            ex.printStackTrace();
            DThrowable.showAndWait(null, null, ex);
        } finally {
            try{ certfos.close(); }catch(Exception ex){/* do nothing */}
        }
    }

    /**
     * Let the user import a key pair a PKCS #12 keystore or a PEM bundle.
     * Based on Portecle.
     * @see FPortecle#importKeyPair()
     */
    private void doImportCertificateAction() {
        // Let the user choose a file to import from
        File fKeyPairFile = chooseImportFileHelper();
        if (fKeyPairFile == null){
           return; // user cancelled
        }

        // Not a file?
        if (!fKeyPairFile.isFile()) {
            JOptionPane.showMessageDialog(this,
                    MessageFormat.format(RB.getString("FPortecle.NotFile.message"), fKeyPairFile),
                    RB.getString("FPortecle.ImportKeyPair.Title"), JOptionPane.WARNING_MESSAGE);
            return;
        }

        // log all the exceptions that may occur
        ArrayList<Exception> exceptions = new ArrayList<Exception>();
        KeyStore tempStore = null;
        PEMReader reader = null;
        try {
            PasswordFinder passwordFinder = new PasswordFinder() {
                private int passwordNumber = 1;
                @Override
                public char[] getPassword() {
                    // Get the user to enter the private key password
                    DGetPassword dGetPassword =
                            new DGetPassword(null, MessageFormat.format(
                            RB.getString("FPortecle.PrivateKeyPassword.Title"),
                            new Object[]{String.valueOf(passwordNumber)}));
                    dGetPassword.setLocationRelativeTo(getParent());
                    SwingHelper.showAndWait(dGetPassword);
                    char[] cPassword = dGetPassword.getPassword();
                    passwordNumber++;
                    return cPassword;
                }
            };

            reader = new PEMReader(new FileReader(fKeyPairFile.getPath()), passwordFinder);
            tempStore = KeyStoreUtil.loadEntries(reader);
            if (tempStore.size() == 0) {
                tempStore = null;
            }
        } catch (Exception e) {
            exceptions.add(e);
        } finally {
            if (reader != null) { try { reader.close(); } catch (IOException e) { /* do nothing */}
            }
        }

        // Treat as PKCS #12 keystore
        if (tempStore == null) {

            // Get the user to enter the PKCS #12 keystore's password
            DGetPassword dGetPassword =
                    new DGetPassword(null, RB.getString("FPortecle.Pkcs12Password.Title"));
            dGetPassword.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dGetPassword);
            char[] cPkcs12Password = dGetPassword.getPassword();
            if (cPkcs12Password == null) {
                return;
            }

            // Load the PKCS #12 keystore
            // DM: important note, the KeyStoreUtil.java class has been modified
            // so that it uses the unlimited strength pkcs12 provider so that
            // unlimited length passwords can be used (circumvents manually
            // installing the unlimited strength Jurisdiction policy files from
            // oracle). 
            try {
                tempStore = KeyStoreUtil.loadKeyStore(fKeyPairFile, cPkcs12Password, KeyStoreType.PKCS12);
            } catch (Exception e) {
                exceptions.add(e);
            }
        }

        if (tempStore == null && !exceptions.isEmpty()) {
            int iSelected =
                    SwingHelper.showConfirmDialog(this,
                    MessageFormat.format(RB.getString("FPortecle.NoOpenKeyPairFile.message"), fKeyPairFile),
                    RB.getString("FPortecle.ImportKeyPairFile.Title"));
            if (iSelected == JOptionPane.YES_OPTION) {
                for (Exception e : exceptions) {
                    DThrowable.showAndWait(null, null, e);
                }
            }
            return;
        }

        try {
            // Display the import key pair dialog supplying the PKCS #12 keystore to it
            DImportKeyPair dImportKeyPair = new DImportKeyPair(null, tempStore);
            dImportKeyPair.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dImportKeyPair);

            // Get the private key and certificate chain of the key pair
            Key privateKey = dImportKeyPair.getPrivateKey();
            Certificate[] certs = dImportKeyPair.getCertificateChain();

            if (privateKey == null || certs == null) {
                // User did not select a key pair for import
                return;
            }

            // Get an alias for the new keystore entry
            String sAlias = dImportKeyPair.getAlias();
            if (sAlias == null) {
                sAlias = X509CertUtil.getCertificateAlias(X509CertUtil.convertCertificate(certs[0]));
            }
            KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();

            sAlias = getNewEntryAliasHelper(keyStore, sAlias, "FPortecle.KeyPairEntryAlias.Title", false);
            if (sAlias == null) {
                return;
            }

            // TODO Get a password for the new keystore entry if applicable
	    /*char[] cPassword = KeyStoreUtil.DUMMY_PASSWORD;
            if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported()){
                DGetNewPassword dGetNewPassword =
                new DGetNewPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
                dGetNewPassword.setLocationRelativeTo(this);
                SwingHelper.showAndWait(dGetNewPassword);
                cPassword = dGetNewPassword.getPassword();
                if (cPassword == null){
                  return false;
                }
            }*/

            WaitDialog.showDialog("General");
            // Delete old entry first
            if (keyStore.containsAlias(sAlias)) {
                keyStore.deleteEntry(sAlias);
            }

            // make sure...
            assert keyStore == ClientKeyStore.getClientkeyStore(this.PASSPHRASE).getKeyStore();
            // Place the private key and certificate chain into the keystore and update
            keyStore.setKeyEntry(sAlias, privateKey, this.PASSPHRASE, certs);
     
            // Update the frame's components and title
            this.reloadKeystoreUpdateGUI();
            WaitDialog.hideDialog();
            // Display success message
           JOptionPane.showMessageDialog(this, RB.getString("FPortecle.KeyPairImportSuccessful.message"),
			    RB.getString("FPortecle.ImportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
           return;
        } catch (Exception ex) {
            DThrowable.showAndWait(null, null, ex);
        }
    }

    /**
     * Let the user choose a file to import from. Based on Portecle.
     * @see FPortecle#chooseImportFile()
     * @return The chosen file or null if none was chosen
     */
    private File chooseImportFileHelper() {
        JFileChooser chooser = FileChooserFactory.getKeyPairFileChooser(null);
        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }
        chooser.setDialogTitle(RB.getString("FPortecle.ImportKeyPairFile.Title"));
        chooser.setMultiSelectionEnabled(false);
        int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.ImportKeyPairFile.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }


    /**
     * Gets a new entry alias from user, handling overwrite issues.
     * Based on Portecle.
     * @see FPortecle#getNewEntryAlias(java.security.KeyStore, java.lang.String, java.lang.String, boolean)
     *
     * @param keyStore target keystore
     * @param sAlias suggested alias
     * @param dialogTitleKey message key for dialog titles
     * @param selectAlias whether to pre-select alias text in text field
     * @return alias for new entry, null if user cancels the operation
     */
    private String getNewEntryAliasHelper(KeyStore keyStore, String sAlias, String dialogTitleKey,
            boolean selectAlias)
            throws KeyStoreException {
        while (true) {
            // Get the alias for the new entry
            DGetAlias dGetAlias =
                    new DGetAlias(null, RB.getString(dialogTitleKey), sAlias.toLowerCase(), selectAlias);
            dGetAlias.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dGetAlias);

            sAlias = dGetAlias.getAlias();
            if (sAlias == null) {
                return null;
            }

            // Check an entry with the selected does not already exist in the keystore
            if (!keyStore.containsAlias(sAlias)) {
                return sAlias;
            }
            String sMessage = MessageFormat.format(RB.getString("FPortecle.OverWriteEntry.message"), sAlias);

            int iSelected =
                    JOptionPane.showConfirmDialog(this, sMessage, "Confirm Alias",
                    JOptionPane.YES_NO_CANCEL_OPTION);
            switch (iSelected) {
                case JOptionPane.YES_OPTION:
                    return sAlias;
                case JOptionPane.NO_OPTION:
                    // keep looping
                    break;
                default:
                    return null;
            }
        }
    }





    /**
     * Invoke PingService to test for connection and update this.refresh button
     */
    private boolean isOnlinePing() {
        boolean online = PingService.getPingService().isPingService();
        if (online) {
            this.btnRefresh.setText("Refresh");
        } else {
            this.btnRefresh.setText("Connect");
        }
        return online;
    }



    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jRadioButton1 = new javax.swing.JRadioButton();
        jPanel1 = new javax.swing.JPanel();
        btnNewCertificateRequest = new javax.swing.JButton();
        btnImportCertificate = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        jComboBox1 = new javax.swing.JComboBox();
        pnlAllDetails = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        subjectDnTextField = new javax.swing.JTextField();
        jLabel8 = new javax.swing.JLabel();
        issuerDnTextField = new javax.swing.JTextField();
        jLabel9 = new javax.swing.JLabel();
        aliasTextField = new javax.swing.JTextField();
        jLabel10 = new javax.swing.JLabel();
        certificateTypeLabel = new javax.swing.JLabel();
        caCertStatusTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        jPanel4 = new javax.swing.JPanel();
        vFrom = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        vTo = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        dRemaining = new javax.swing.JTextField();
        rDue = new javax.swing.JTextField();
        viewCertDetailsButton = new javax.swing.JButton();
        btnRefresh = new javax.swing.JButton();
        btnInstall = new javax.swing.JButton();
        btnRenew = new javax.swing.JButton();
        btnExport = new javax.swing.JButton();
        btnRevoke = new javax.swing.JButton();
        btnDelete = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TextMOD = new javax.swing.JTextArea();
        jLabel7 = new javax.swing.JLabel();

        jRadioButton1.setText("jRadioButton1");

        setPreferredSize(new java.awt.Dimension(840, 458));
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
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btnImportCertificate)
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
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

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Your Certificates and Requests  "));

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

        jLabel1.setText("Subject DN:");

        subjectDnTextField.setEditable(false);
        subjectDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel8.setText("Issuer DN:");

        issuerDnTextField.setEditable(false);
        issuerDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel9.setText("Alias:");

        aliasTextField.setEditable(false);
        aliasTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel10.setText("Type:");

        certificateTypeLabel.setText("CertificateType");

        caCertStatusTextField.setEditable(false);
        caCertStatusTextField.setFont(new java.awt.Font("Tahoma", 1, 11));
        caCertStatusTextField.setText("Unknown (offilne or certificate not recognized by UK CA)");
        caCertStatusTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel2.setText("Status with CA:");

        vFrom.setEditable(false);
        vFrom.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel3.setText("Valid From:");

        jLabel4.setText("Valid To:");

        vTo.setEditable(false);
        vTo.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel5.setText("Days Remaining:");

        jLabel6.setText("Renewal Due:");

        dRemaining.setEditable(false);
        dRemaining.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        rDue.setEditable(false);
        rDue.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        org.jdesktop.layout.GroupLayout jPanel4Layout = new org.jdesktop.layout.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                    .add(jPanel4Layout.createSequentialGroup()
                        .add(jLabel3)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                        .add(vFrom, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 119, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                    .add(jPanel4Layout.createSequentialGroup()
                        .add(jLabel4)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .add(vTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                .add(18, 18, 18)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel5)
                    .add(jLabel6))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(rDue, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 119, Short.MAX_VALUE)
                    .add(dRemaining, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 118, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
        );

        jPanel4Layout.linkSize(new java.awt.Component[] {dRemaining, rDue, vFrom, vTo}, org.jdesktop.layout.GroupLayout.HORIZONTAL);

        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel3)
                    .add(vFrom, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 23, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel5)
                    .add(dRemaining, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel4)
                    .add(vTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel6)
                    .add(rDue, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel4Layout.linkSize(new java.awt.Component[] {dRemaining, rDue, vFrom, vTo}, org.jdesktop.layout.GroupLayout.VERTICAL);

        viewCertDetailsButton.setText("< View Details");
        viewCertDetailsButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                viewCertDetailsButtonActionPerformed(evt);
            }
        });

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

        org.jdesktop.layout.GroupLayout pnlAllDetailsLayout = new org.jdesktop.layout.GroupLayout(pnlAllDetails);
        pnlAllDetails.setLayout(pnlAllDetailsLayout);
        pnlAllDetailsLayout.setHorizontalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(jPanel4, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .addContainerGap())
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(jLabel1)
                            .add(jLabel8)
                            .add(jLabel10)
                            .add(jLabel2)
                            .add(jLabel9))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                            .add(pnlAllDetailsLayout.createSequentialGroup()
                                .add(certificateTypeLabel)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 329, Short.MAX_VALUE)
                                .add(viewCertDetailsButton))
                            .add(org.jdesktop.layout.GroupLayout.LEADING, caCertStatusTextField, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 504, Short.MAX_VALUE)
                            .add(issuerDnTextField, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 504, Short.MAX_VALUE)
                            .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 504, Short.MAX_VALUE)
                            .add(aliasTextField, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 504, Short.MAX_VALUE))
                        .addContainerGap())))
            .add(org.jdesktop.layout.GroupLayout.TRAILING, pnlAllDetailsLayout.createSequentialGroup()
                .add(btnRefresh)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 179, Short.MAX_VALUE)
                .add(btnInstall)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btnRenew)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btnExport)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btnRevoke)
                .add(4, 4, 4)
                .add(btnDelete)
                .addContainerGap())
        );
        pnlAllDetailsLayout.setVerticalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel1)
                    .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(issuerDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel8))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(caCertStatusTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel2))
                .add(7, 7, 7)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(aliasTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel9))
                .add(19, 19, 19)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                        .add(jLabel10)
                        .add(certificateTypeLabel))
                    .add(viewCertDetailsButton))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel4, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 70, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 36, Short.MAX_VALUE)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnRefresh)
                    .add(btnInstall)
                    .add(btnRenew)
                    .add(btnExport)
                    .add(btnRevoke)
                    .add(btnDelete))
                .addContainerGap())
        );

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {aliasTextField, caCertStatusTextField, issuerDnTextField, subjectDnTextField}, org.jdesktop.layout.GroupLayout.VERTICAL);

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .add(1, 1, 1)
                .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 598, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .add(43, 43, 43))
            .add(jPanel2Layout.createSequentialGroup()
                .add(11, 11, 11)
                .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 28, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addContainerGap())
        );

        jPanel3.setBorder(javax.swing.BorderFactory.createTitledBorder("Information"));

        TextMOD.setColumns(20);
        TextMOD.setWrapStyleWord(true);
        TextMOD.setLineWrap(true);
        TextMOD.setRows(5);
        jScrollPane1.setViewportView(TextMOD);

        org.jdesktop.layout.GroupLayout jPanel3Layout = new org.jdesktop.layout.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jScrollPane1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 150, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel3Layout.createSequentialGroup()
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 233, Short.MAX_VALUE)
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
                    .add(jPanel3, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                        .add(jPanel1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .add(jLabel7, 0, 0, Short.MAX_VALUE)))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                    .add(jPanel2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(layout.createSequentialGroup()
                        .add(jLabel7, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 47, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jPanel1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jPanel3, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );
    }// </editor-fold>//GEN-END:initComponents


    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed
        // 
        this.updateGUIPanel();
    }//GEN-LAST:event_jComboBox1ActionPerformed

    private void btnNewCertificateRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestActionPerformed
        // 
        this.doNewCertificateAction();
    }//GEN-LAST:event_btnNewCertificateRequestActionPerformed

    private void btnImportCertificateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnImportCertificateActionPerformed
        // 
        this.doImportCertificateAction();
    }//GEN-LAST:event_btnImportCertificateActionPerformed

    private void btnExportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExportActionPerformed
        // 
        this.doExportAction();
    }//GEN-LAST:event_btnExportActionPerformed

    private void btnRenewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRenewActionPerformed
        // 
        this.doRenewAction();
    }//GEN-LAST:event_btnRenewActionPerformed

    private void btnRevokeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRevokeActionPerformed
        // 
        this.doRevokeAction();
    }//GEN-LAST:event_btnRevokeActionPerformed

    private void btnDeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDeleteActionPerformed
        //
        this.doDeleteAction();
    }//GEN-LAST:event_btnDeleteActionPerformed

    private void btnNewCertificateRequestMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseEntered
        // 
        setMOD("Request a new user certificate");
    }//GEN-LAST:event_btnNewCertificateRequestMouseEntered

    private void formMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_formMouseExited
        // TODO add your handling code here:
    }//GEN-LAST:event_formMouseExited

    private void jPanel1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jPanel1MouseExited
        // TODO add your handling code here:
    }//GEN-LAST:event_jPanel1MouseExited

    private void btnNewCertificateRequestMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseExited
        // 
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_btnNewCertificateRequestMouseExited

    private void btnImportCertificateMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseEntered
        // TODO add your handling code here:
        setMOD("Import an existing certificate file into the certificate wizard.");
    }//GEN-LAST:event_btnImportCertificateMouseEntered

    private void jComboBox1MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseEntered
        // TODO add your handling code here:
        setMOD("Your current certificates and certificate requests.");
    }//GEN-LAST:event_jComboBox1MouseEntered

    private void btnRenewMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseEntered
        // TODO add your handling code here:
        setMOD("Renew the selected certificate 30 days before it expires (the certificate must be valid).");
    }//GEN-LAST:event_btnRenewMouseEntered

    private void btnExportMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseEntered
        // TODO add your handling code here:
        setMOD("Export the selected certificate to a file for back up, or for use in other tools (exports a .p12 file).");
    }//GEN-LAST:event_btnExportMouseEntered

    private void btnRevokeMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseEntered
        // TODO add your handling code here:
        setMOD("Revoke your certificate if it is compromised or invalid.");
    }//GEN-LAST:event_btnRevokeMouseEntered

    private void btnDeleteMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseEntered
        // TODO add your handling code here:
        setMOD("Remove your certificate from the tool. "
                + "This will not delete any other copies of the certificate from your computer.");
    }//GEN-LAST:event_btnDeleteMouseEntered

    private void btnInstallActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnInstallActionPerformed
        // TODO add your handling code here:
        this.doInstallSelectedCertificateAction();
    }//GEN-LAST:event_btnInstallActionPerformed

    private void btnInstallMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseEntered
        // TODO add your handling code here:
        setMOD("Install the selected certificate to local PEM files: \n\n"
                + "'$HOME/.globus/usercert.pem' \n"
                + "'$HOME/.globus/usercert.pem' ");
    }//GEN-LAST:event_btnInstallMouseEntered

    private void btnInstallMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_btnInstallMouseExited

    private void btnImportCertificateMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_btnImportCertificateMouseExited

    private void jComboBox1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_jComboBox1MouseExited

    private void btnRenewMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_btnRenewMouseExited

    private void btnExportMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_btnExportMouseExited

    private void btnRevokeMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_btnRevokeMouseExited

    private void btnDeleteMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);
        }
    }//GEN-LAST:event_btnDeleteMouseExited

    private void jComboBox1ItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_jComboBox1ItemStateChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBox1ItemStateChanged

    private void btnRefreshActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRefreshActionPerformed
        // TODO add your handling code here:
        WaitDialog.showDialog("Updating");
        assert this.keyStoreCaWrapper.getClientKeyStore().getKeyStore() ==
                ClientKeyStore.getClientkeyStore(PASSPHRASE).getKeyStore();
        this.reloadKeystoreUpdateGUI();
        WaitDialog.hideDialog();
    }//GEN-LAST:event_btnRefreshActionPerformed

    private void btnRefreshMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRefreshMouseEntered
        // TODO add your handling code here:
        setMOD("Retrieve certificate information from the CA Server and update the status of the certificates stored in the Certificate Wizard");
    }//GEN-LAST:event_btnRefreshMouseEntered

    private void btnRefreshMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRefreshMouseExited
        // TODO add your handling code here:
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotD);

        }
    }//GEN-LAST:event_btnRefreshMouseExited

    private void viewCertDetailsButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonActionPerformed
        // TODO add your handling code here:
        this.doViewCertificateDetailsAction();
    }//GEN-LAST:event_viewCertDetailsButtonActionPerformed

  
    private void setRedMOD(String text) {
        TextMOD.setForeground(Color.RED);
        TextMOD.setText(text);
    }

    private void setMOD(String text) {
        TextMOD.setForeground(Color.BLACK);
        TextMOD.setText(text);
    }


    ////////////////////////////////////////////////////////////////////////////
    // The next set of methods starting with export and choose are soley used
    // for exporting keystore entries to different file formats. They are
    // largely copied verbatum from Portecle. TODO: They could be refactored into
    // a helper class to make this class smaller.
    ////////////////////////////////////////////////////////////////////////////


    /**
     * Export the private key and certificates of the keystore entry to a PKCS #12 keystore file.
     * Based on Portecle.
     * @see FPortecle#exportPrivKeyCertChainPKCS12(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportPrivKeyCertChainPKCS12(String sEntryAlias) {
        /*KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Get the entry's password (we may already know it from the wrapper)
        char[] cPassword = m_keyStoreWrap.getEntryPassword(sEntryAlias);

        if (cPassword == null)
        {
        cPassword = KeyStoreUtil.DUMMY_PASSWORD;

        if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
        {
        DGetPassword dGetPassword =
        new DGetPassword(this, RB.getString("FPortecle.KeyEntryPassword.Title"));
        dGetPassword.setLocationRelativeTo(this);
        SwingHelper.showAndWait(dGetPassword);
        cPassword = dGetPassword.getPassword();

        if (cPassword == null)
        {
        return false;
        }
        }
        }*/
        KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();
        char[] cPassword = this.PASSPHRASE;

        File fExportFile = null;

        try {
            // Get the private key and certificate chain from the entry
            Key privKey = keyStore.getKey(sEntryAlias, cPassword);
            Certificate[] certs = keyStore.getCertificateChain(sEntryAlias);

            // Update the keystore wrapper
            // DM: commented this out - not sure if its necessary ?
            //m_keyStoreWrap.setEntryPassword(sEntryAlias, cPassword);

            // Create a new PKCS #12 keystore
            KeyStore pkcs12 = KeyStoreUtil.createKeyStore(KeyStoreType.PKCS12);

            // Place the private key and certificate chain into the PKCS #12 keystore under the same alias as
            // it has in the loaded keystore
            pkcs12.setKeyEntry(sEntryAlias, privKey, new char[0], certs);

            // Get a new password for the PKCS #12 keystore
            DGetNewPassword dGetNewPassword =
                    new DGetNewPassword(null, RB.getString("FPortecle.Pkcs12Password.Title"));
            dGetNewPassword.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dGetNewPassword);

            char[] cPKCS12Password = dGetNewPassword.getPassword();

            if (cPKCS12Password == null) {
                return false;
            }

            String basename = null;
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                basename = X509CertUtil.getCertificateAlias((X509Certificate) certs[0]);
            }
            if (basename == null || basename.isEmpty()) {
                basename = sEntryAlias;
            }

            // Let the user choose the export PKCS #12 file
            fExportFile = chooseExportPKCS12File(basename);
            if (fExportFile == null) {
                return false;
            }

            if (!confirmOverwrite(fExportFile, "Overwrite")) {
                return false;
            }

            // Store the keystore to disk
            KeyStoreUtil.saveKeyStore(pkcs12, fExportFile, cPKCS12Password);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        } catch (FileNotFoundException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(this, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (GeneralSecurityException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        }
    }

    /**
     * Export the private key and certificates of the keystore entry to a PEM encoded "OpenSSL" format bundle.
     * Based on Portecle.
     * @see FPortecle#exportPrivKeyCertChainPEM(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportPrivKeyCertChainPEM(String sEntryAlias) {
        /*KeyStore keyStore = m_keyStoreWrap.getKeyStore();

        // Get the entry's password (we may already know it from the wrapper)
        char[] cPassword = m_keyStoreWrap.getEntryPassword(sEntryAlias);

        if (cPassword == null)
        {
        cPassword = KeyStoreUtil.DUMMY_PASSWORD;

        if (m_keyStoreWrap.getKeyStoreType().isEntryPasswordSupported())
        {
        DGetPassword dGetPassword =
        new DGetPassword(null, RB.getString("FPortecle.KeyEntryPassword.Title"));
        dGetPassword.setLocationRelativeTo(this);
        SwingHelper.showAndWait(dGetPassword);
        cPassword = dGetPassword.getPassword();

        if (cPassword == null)
        {
        return false;
        }
        }
        }*/
        KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();
        char[] cPassword = this.PASSPHRASE;

        File fExportFile = null;
        PEMWriter pw = null;

        try {
            // Get the private key and certificate chain from the entry
            Key privKey = keyStore.getKey(sEntryAlias, cPassword);
            Certificate[] certs = keyStore.getCertificateChain(sEntryAlias);

            // Get a new password to encrypt the private key with
            DGetNewPassword dGetNewPassword =
                    new DGetNewPassword(null, RB.getString("FPortecle.PrivateKeyExportPassword.Title"));
            dGetNewPassword.setLocationRelativeTo(this);
            SwingHelper.showAndWait(dGetNewPassword);

            char[] password = dGetNewPassword.getPassword();
            if (password == null) {
                return false;
            }

            String basename = null;
            if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                basename = X509CertUtil.getCertificateAlias((X509Certificate) certs[0]);
            }
            if (basename == null || basename.isEmpty()) {
                basename = sEntryAlias;
            }

            // Let the user choose the PEM export file
            fExportFile = chooseExportPEMFile(basename);
            if (fExportFile == null) {
                return false;
            }

            if (!confirmOverwrite(fExportFile, "Overwrite")) {
                return false;
            }

            // Do the export
            pw = new PEMWriter(new FileWriter(fExportFile));

            if (password.length == 0) {
                pw.writeObject(privKey);
            } else {
                // TODO: make algorithm configurable/ask user?
                String algorithm = "DES-EDE3-CBC";
                SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
                pw.writeObject(privKey, algorithm, password, rand);
            }

            for (Certificate cert : certs) {
                pw.writeObject(cert);
            }
            pw.flush();

            m_lastDir.updateLastDir(fExportFile);

            return true;
        } catch (FileNotFoundException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(this, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (GeneralSecurityException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } finally {
            if (pw != null) {
                try {
                    pw.close();
                } catch (IOException ex) {
                    DThrowable.showAndWait(null, null, ex);
                }
            }
        }
    }

    /**
     * Export all of the certificates of the keystore entry to a PKCS #7 file.
     * Based on Portecle.
     * @see FPortecle#exportAllCertsPkcs7(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportAllCertsPkcs7(String sEntryAlias) {
        // Get the certificates
        //KeyStore keyStore = m_keyStoreWrap.getKeyStore();
        KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();
        X509Certificate[] certChain = null;
        try {
            certChain = X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias));
        } catch (KeyStoreException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        }

        String basename = null;
        if (certChain.length > 0) {
            basename = X509CertUtil.getCertificateAlias(certChain[0]);
        }
        if (basename == null || basename.isEmpty()) {
            basename = sEntryAlias;
        }

        // Let the user choose the export PKCS #7 file
        File fExportFile = chooseExportPKCS7File(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, "Overwrite")) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertsEncodedPkcs7(certChain);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);
            m_lastDir.updateLastDir(fExportFile);
            return true;
        } catch (FileNotFoundException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(null, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    DThrowable.showAndWait(null, null, e);
                }
            }
        }
    }

    /**
     * Export the head certificate of the keystore entry to a PKCS #7 file.
     * Based on Portecle
     * @see FPortecle#exportHeadCertOnlyPkcs7(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPkcs7(String sEntryAlias) {
        X509Certificate cert = null;
        try {
            // Get the head certificate
            cert = getHeadCert(sEntryAlias);
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.isEmpty()) {
            basename = sEntryAlias;
        }

        // Let the user choose the export PKCS #7 file
        File fExportFile = chooseExportPKCS7File(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, "Overwrite")) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedPkcs7(cert);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        } catch (FileNotFoundException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(null, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    DThrowable.showAndWait(null, null, e);
                }
            }
        }
    }

    /**
     * Export the head certificate of the keystore entry in a PEM encoding.
     * Based on Portecle.
     * @see FPortecle#exportHeadCertOnlyPem(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPem(String sEntryAlias) {
        X509Certificate cert = null;
        try {
            cert = getHeadCert(sEntryAlias);
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.isEmpty()) {
            basename = sEntryAlias;
        }

        // Let the user choose the export certificate file
        File fExportFile = chooseExportCertFile(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, "Overwrite")) {
            return false;
        }

        PEMWriter pw = null;
        try {
            pw = new PEMWriter(new FileWriter(fExportFile));
            pw.writeObject(cert);
            m_lastDir.updateLastDir(fExportFile);
            return true;
        } catch (FileNotFoundException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(this, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } finally {
            if (pw != null) {
                try {
                    pw.close();
                } catch (IOException ex) {
                    DThrowable.showAndWait(null, null, ex);
                }
            }
        }
    }

    /**
     * Export the head certificate of the keystore entry in a DER encoding.
     * Based on Portecle.
     * @see FPortecle#exportHeadCertOnlyDER(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyDER(String sEntryAlias) {
        X509Certificate cert = null;
        try {
            // Get the head certificate
            cert = getHeadCert(sEntryAlias);
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.isEmpty()) {
            basename = sEntryAlias;
        }

        // Let the user choose the export certificate file
        File fExportFile = chooseExportCertFile(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, "Overwrite")) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedDer(cert);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        } catch (FileNotFoundException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(this, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException ex) {
                    DThrowable.showAndWait(null, null, ex);
                }
            }
        }
    }

    /**
     * Export the head certificate of the keystore entry to a PkiPath file.
     * Based on Portecle.
     * @see FPortecle#exportHeadCertOnlyPkiPath(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPkiPath(String sEntryAlias) {
        X509Certificate cert = null;
        try {
            // Get the head certificate
            cert = getHeadCert(sEntryAlias);
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        }

        String basename = X509CertUtil.getCertificateAlias(cert);
        if (basename.isEmpty()) {
            basename = sEntryAlias;
        }

        // Let the user choose the export PkiPath file
        File fExportFile = chooseExportPkiPathFile(basename);
        if (fExportFile == null) {
            return false;
        }

        if (!confirmOverwrite(fExportFile, "Overwrite")) {
            return false;
        }

        FileOutputStream fos = null;
        try {
            // Do the export
            byte[] bEncoded = X509CertUtil.getCertEncodedPkiPath(cert);
            fos = new FileOutputStream(fExportFile);
            fos.write(bEncoded);

            m_lastDir.updateLastDir(fExportFile);

            return true;
        } catch (FileNotFoundException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(this, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } catch (CryptoException ex) {
            DThrowable.showAndWait(null, null, ex);
            return false;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    DThrowable.showAndWait(null, null, e);
                }
            }
        }
    }

    /**
     * Let the user choose a PKCS #12 file to export to.
     * Based on Portecle.
     * @see FPortecle#chooseExportPKCS12File(java.lang.String)
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPKCS12File(String basename) {
        JFileChooser chooser = FileChooserFactory.getPkcs12FileChooser(basename);
        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }
        chooser.setDialogTitle(RB.getString("FPortecle.ExportKeyCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);
        int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a PKCS #7 file to export to.
     * Based on Portecle.
     * @see FPortecle#chooseExportPKCS7File(java.lang.String)
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPKCS7File(String basename) {
        JFileChooser chooser = FileChooserFactory.getPkcs7FileChooser(basename);
        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }
        chooser.setDialogTitle(RB.getString("FPortecle.ExportCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);
        int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a PEM file to export to.
     * Based on Portecle.
     * @see FPortecle#chooseExportPEMFile(java.lang.String)
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPEMFile(String basename) {
        JFileChooser chooser = FileChooserFactory.getPEMFileChooser(basename);
        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }
        chooser.setDialogTitle(RB.getString("FPortecle.ExportKeyCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);
        int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a PkiPath file to export to.
     * Based on Portecle.
     * @see FPortecle#chooseExportPkiPathFile(java.lang.String)
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportPkiPathFile(String basename) {
        JFileChooser chooser = FileChooserFactory.getPkiPathFileChooser(basename);
        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }
        chooser.setDialogTitle(RB.getString("FPortecle.ExportCertificates.Title"));
        chooser.setMultiSelectionEnabled(false);
        int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a certificate file to export to.
     * Based on Portecle.
     * @see FPortecle#chooseExportCertFile(java.lang.String)
     *
     * @param basename default filename (without extension)
     * @return The chosen file or null if none was chosen
     */
    private File chooseExportCertFile(String basename) {
        JFileChooser chooser = FileChooserFactory.getX509FileChooser(basename);
        File fLastDir = m_lastDir.getLastDir();
        if (fLastDir != null) {
            chooser.setCurrentDirectory(fLastDir);
        }
        chooser.setDialogTitle(RB.getString("FPortecle.ExportCertificate.Title"));
        chooser.setMultiSelectionEnabled(false);
        int iRtnValue = chooser.showDialog(this, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * File overwrite confirmation dialog.
     * Based on Portecle.
     * @see FPortecle#confirmOverwrite(java.io.File, java.lang.String)
     *
     * @param file the file possibly being overwritten
     * @param title window title
     * @return true if the write operation should continue
     */
    private boolean confirmOverwrite(File file, String title) {
        if (file.isFile()) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.OverWriteFile.message"), file.getName());
            int iSelected = JOptionPane.showConfirmDialog(this, sMessage, title, JOptionPane.YES_NO_OPTION);
            return iSelected == JOptionPane.YES_OPTION;
        }
        return true;
    }

    /**
     * Get the keystore entry's head certificate.
     * Based on Portecle.
     * @see FPortecle#getHeadCert(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return The keystore entry's head certificate
     * @throws CryptoException Problem getting head certificate
     */
    private X509Certificate getHeadCert(String sEntryAlias)
            throws CryptoException {
        try {
            // Get keystore
            KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();
            // Get the entry's head certificate
            X509Certificate cert;
            if (keyStore.isKeyEntry(sEntryAlias)) {
                cert =
                        X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(keyStore.getCertificateChain(sEntryAlias)))[0];
            } else {
                cert = X509CertUtil.convertCertificate(keyStore.getCertificate(sEntryAlias));
            }
            return cert;
        } catch (KeyStoreException ex) {
            String sMessage =
                    MessageFormat.format(RB.getString("FPortecle.NoAccessEntry.message"), sEntryAlias);
            throw new CryptoException(sMessage, ex);
        }
    }






    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea TextMOD;
    private javax.swing.JTextField aliasTextField;
    private javax.swing.JButton btnDelete;
    private javax.swing.JButton btnExport;
    private javax.swing.JButton btnImportCertificate;
    private javax.swing.JButton btnInstall;
    private javax.swing.JButton btnNewCertificateRequest;
    private javax.swing.JButton btnRefresh;
    private javax.swing.JButton btnRenew;
    private javax.swing.JButton btnRevoke;
    private javax.swing.JTextField caCertStatusTextField;
    private javax.swing.JLabel certificateTypeLabel;
    private javax.swing.JTextField dRemaining;
    private javax.swing.JTextField issuerDnTextField;
    private javax.swing.JComboBox jComboBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JPanel jPanel4;
    private javax.swing.JRadioButton jRadioButton1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JPanel pnlAllDetails;
    private javax.swing.JTextField rDue;
    private javax.swing.JTextField subjectDnTextField;
    private javax.swing.JTextField vFrom;
    private javax.swing.JTextField vTo;
    private javax.swing.JButton viewCertDetailsButton;
    // End of variables declaration//GEN-END:variables
}

 /** Called by the Import button (our old defunked way ) */
    /*private void doImportCertificateAction() {
        JFileChooser importCert = new JFileChooser();
        importCert.addChoosableFileFilter(new certFilter());
        importCert.setMultiSelectionEnabled(false);

        if (importCert.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            // request the password for the pkcs12 file
            JPasswordField pwd = new JPasswordField(20);
            int action = JOptionPane.showConfirmDialog(this, pwd, "Enter Password", JOptionPane.OK_CANCEL_OPTION);
            if (JOptionPane.OK_OPTION == action) {
                // check the password is valid
                char[] password = pwd.getPassword();
                if (password == null || password.length == 0) {
                    JOptionPane.showMessageDialog(this, "Invalid password", "Invalid password", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                try {
                    // store a map of <DN, alias> keystore entries.
                    Map<String, String> p12certDnValues = new HashMap<String, String>(0);
                    KeyStore importKeyStore = PKCS12KeyStoreUnlimited.getInstance();
                    importKeyStore.load(new FileInputStream(importCert.getSelectedFile()), password);
                    Enumeration<String> aliases = importKeyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        if (importKeyStore.isKeyEntry(alias)) {
                            if (importKeyStore.getCertificate(alias) instanceof X509Certificate) {
                                String dn = ((X509Certificate) importKeyStore.getCertificate(alias)).getSubjectX500Principal().toString();
                                p12certDnValues.put(dn, alias);
                            }
                        }
                    }
                    if (p12certDnValues.isEmpty()) {
                        JOptionPane.showMessageDialog(this, "Could not find a [cert/key] combination with the given password", "PFX/P12 File Extraction", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    String selected = (String) JOptionPane.showInputDialog(
                            this, "Select your [cert/key] entry", "Keystore Selection Dialog",
                            JOptionPane.PLAIN_MESSAGE, null,
                            p12certDnValues.keySet().toArray(),
                            p12certDnValues.keySet().toArray()[0]);
                    if (selected == null) {
                        JOptionPane.showMessageDialog(this, "You didn't select a imported entry.", "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                    String selectedAlias = p12certDnValues.get(selected);

                    // add the selected entry to our ca keystore (try to reuse same alias)
                    String addAlias = this.getUnusedAlias(selectedAlias);
                    if(addAlias == null) return; // they decided to cancel.

                    // TODO: Need to confirm they want to add this cert under the addAlias

                    // TODO: check
                    // TODO: this also adds the eScience root and eScience CA trusted certs to the keystore
                    //Certificate[] chain = importKeyStore.getCertificateChain(selectedAlias);
                    // TODO: this adds just the cert
                    // or Ask if you want to import those trust certs also ?
                    Certificate[] chain = {importKeyStore.getCertificate(selectedAlias) };

                    this.keyStoreCaWrapper.getClientKeyStore().getKeyStore().setKeyEntry(
                            addAlias,
                            importKeyStore.getKey(selectedAlias, password),
                            this.PASSPHRASE,
                            chain);

                    // persist the newly added cert
                    this.keyStoreCaWrapper.getClientKeyStore().reStore();

                    // finally update the GUI
                    this.reloadKeystoreUpdateGUI();

                } catch (Exception ex) {
                    Logger.getLogger(MainWindowPanel2.class.getName()).log(Level.SEVERE, null, ex);
                    JOptionPane.showMessageDialog(this, "Error occured: " + ex.getMessage(),
                            "Error on certificate import", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
    }*/

    /** Recursive helper function to get an alias that is not used in the ca keystore */
    /*private String getUnusedAlias(String testAlias) throws KeyStoreException {
        boolean testAliasAlreadyPresent = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore().containsAlias(testAlias);
        if (testAliasAlreadyPresent) {
            String newAlias = JOptionPane.showInputDialog(this, "Alias: ["+testAlias+"] already exists. Enter a new alias");
            if(newAlias != null && newAlias.trim().length() > 0){
                return this.getUnusedAlias(newAlias);
            } else {
                return null;
            }
        } else {
            return testAlias;
        }
    }*/



  /* private boolean importToKeyStore( ) {
        boolean isSuccess = false;
        Key _key = null;
        Certificate _cert = null;

        if (isExistFile(this.certFile)) {
            Map<String, String>  storeKeyCertAliases_CertDN = new HashMap<String, String>(0);

            try {
                this.importKeyStore = PKCS12KeyStoreUnlimited.getInstance();
                this.importKeyStore.load(new FileInputStream(this.certFile), this.fileProtectionPassphrase);
                Enumeration aliases = this.importKeyStore.aliases();
                int i = 0;
                while (aliases.hasMoreElements()) {
                    ++i;
                    String alias = (String) aliases.nextElement();
                    if( this.importKeyStore.isKeyEntry(alias) ){
                        Certificate keysCert = this.importKeyStore.getCertificate(alias);
                        if (keysCert instanceof X509Certificate ) {
                            X500Principal pp = ((X509Certificate)keysCert).getSubjectX500Principal();
                            if(pp != null){
                                String dn = pp.getName();
                                if(dn == null || "".equals(dn)){
                                    dn = "unknownDN_"+i;
                                }
                                storeKeyCertAliases_CertDN.put(dn, alias);
                            }
                        }
                    }
                }
                if(storeKeyCertAliases_CertDN.size() == 0){
                        JOptionPane.showMessageDialog(frame, "Could not find a [cert/key] combination with the given password", "PFX/P12 File Extraction", JOptionPane.ERROR_MESSAGE);
                        this.Message = null;
                        return false;
                }
                String selected = (String) JOptionPane.showInputDialog(
                            frame,
                            "Select your [cert/key] entry",
                            "Keystore Selection Dialog",
                            JOptionPane.PLAIN_MESSAGE,
                            null,
                            storeKeyCertAliases_CertDN.keySet().toArray(),
                            storeKeyCertAliases_CertDN.keySet().toArray()[0]);
                if (selected == null) {
                    this.Message = "You didn't select a imported entry.";
                    JOptionPane.showMessageDialog(frame, "You didn't select a imported entry.", "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                    return false;
                }


                String selectedAlias = storeKeyCertAliases_CertDN.get(selected);
                _cert = this.importKeyStore.getCertificate(selectedAlias); // shouldn't we be getting the whole cert chain here ?
                _key = this.importKeyStore.getKey(selectedAlias, this.fileProtectionPassphrase);
                if (!(_cert instanceof X509Certificate)) {
                    JOptionPane.showMessageDialog(frame, "Could not find your certificate when trying to import.", "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                    return false;
                }
                if (!(_key instanceof PrivateKey)) {
                    JOptionPane.showMessageDialog(frame, "Could not find your private key when trying to import.", "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                    return false;
                }

                X509Certificate x509_cert = (X509Certificate)_cert;
                PrivateKey priv_key = (PrivateKey)_key;

                //ClientKeyStore clientKeyStore = new ClientKeyStore(this.keyStorePassphrase);
                ClientKeyStore clientKeyStore = ClientKeyStore.getClientkeyStore(this.keyStorePassphrase);
                String _dn = x509_cert.getSubjectDN().getName();
                String _value = SysProperty.getValue("ngsca.cert.o"); // the organization

                int _index = _dn.indexOf(_value);

                //find out if the e-mail extension exists, and hence prevent host cert from getting imported
                String dn = x509_cert.getSubjectDN().getName();


                    ///ADDED: CHECK FOR HOST CERTIFICATES AS WELL AS NON E-SCIENCE CERTIFICATES

                if ((_index == -1) || dn.contains(".")) {
                            //this message will display the certificate issued by UK e-Science CA cannot be supported.
                    String _message = SysProperty.getValue("ngsca.cert.limit");
                    _message = _message + "\nYou may have tried to import a certificate which is not issued by e-Science CA, or \n"
                            + "you may have tried to import a host certificate, which is not yet supported by this \n"
                            + "version of Certificate Management Wizard ." + "\nYour certificate DN is " + _dn + "\nPlease select a UK e-Science "
                            + "personal certificate to import.";
                    this.Message = _message;
                    JOptionPane.showMessageDialog(frame, _message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                    isSuccess = false;
                } else {

                      //AO - Removed as there is no need to do a check on the public key when importing a certificate into the keystore.
                      //The certificate already been issued by CA already has the public key in the database!

//                    PublicKey publicKey = x509_cert.getPublicKey();
//                    ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey( publicKey );
//                    if( ! resourcesPublicKey.isExist() ){
//                        this.Message = "Your imported certificate looks valid, but there is no any record in the service database. Please contact with Helpdesk";
//                        JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
//                        isSuccess = false;
//                    }

                    if (clientKeyStore.addNewKey(priv_key, x509_cert)) {
                        this.Alias = clientKeyStore.getAlias(x509_cert);

                        ClientCertKeyStore clientCertKeyStore = ClientCertKeyStore.getClientCertKeyStore(keyStorePassphrase);
                        if (clientCertKeyStore.addNewKey(priv_key, x509_cert)) {
                            this.Message = "The keys have been added up in local keyStore and cert KeyStore files.";
                            isSuccess = true;
                        } else {
                            this.Message = "The keys have been added up in local KeyStore, but failed in local cert KeyStore.";
                            JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                            isSuccess = false;
                        }
                    } else {
                        this.Message = "The Keys are failed to add up in local keyStore file.";
                        JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                        isSuccess = false;
                    }
                }
            }catch( UnrecoverableKeyException badpasswordEx ){
                JOptionPane.showMessageDialog(frame, "Could not load your [key/cert] with the given password", "PFX File Extraction", JOptionPane.ERROR_MESSAGE);
                this.Message = null;
                return false;
            }catch( KeyStoreException kep ){
                this.Message = "The imported certificate file format should be pkcs12. Please check the format of your imported file.";
                JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                isSuccess = false;
            }catch( NoSuchProviderException nepep ){
                this.Message = "Please make sure you are using BouncyCastle provider.";
                JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                isSuccess = false;
            }catch( FileNotFoundException fnfep ){
                this.Message = "The imported File can not be found. Please make sure you import a real file.";
                JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                isSuccess = false;
            }catch( IOException ioep ){
                this.Message = ioep.getMessage();
                JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                isSuccess = false;
            }catch( NoSuchAlgorithmException nsaep ){
                this.Message = nsaep.getMessage();
                JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                isSuccess = false;
            }catch( CertificateException cep ){
                this.Message = cep.getMessage();
                JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                isSuccess = false;
            }

        } else {
            this.Message = "You didn't select a valid file. Please try again.";
            JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
            isSuccess = false;
        }

        return isSuccess;
    }*/
