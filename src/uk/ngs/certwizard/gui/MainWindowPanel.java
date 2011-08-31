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
import java.text.Format;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
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
public class MainWindowPanel extends javax.swing.JPanel implements Observer {

    private ImageIcon[] images;
    private String stringMotD = "Hit the Refresh button to fetch the latest message of the Day";
    private final CAMotd motd = new CAMotd();
    private char[] PASSPHRASE;
    private ClientKeyStoreCaServiceWrapper keyStoreCaWrapper = null;
    private String stringMotDOffline = "You are working offline.\n\nPlease note that you will not be able to Apply, Renew, Revoke "
            + "your certificate or retrieve certificate status information from the Server until the connection has been established "
            + "to the CA Server. \n\nHit the Refresh button again to give another attempt to connect to the CA Server";


    /** The last directory accessed by the application */
    private final LastDir m_lastDir = new LastDir();

    /** Portecle Resource bundle base name */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";

    /** Portecle Resource bundle */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);


    /** Creates new form MainWindowPanel */
    public MainWindowPanel(char[] passphrase, CertWizardMain _certWizardMain) {
        this.PASSPHRASE = passphrase;
        String _passphrase = new String(passphrase);
            
        String _property = SysProperty.getValue("uk.ngs.ca.immegration.password.property");
        System.setProperty(_property, _passphrase);
        
        initComponents();
        loadImages();

        WaitDialog.showDialog("General");
        
        try {
            this.keyStoreCaWrapper = ClientKeyStoreCaServiceWrapper.getInstance(passphrase);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
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
        } else {
            setRedMOD(stringMotDOffline);
        }
        WaitDialog.hideDialog();

        // if we have not certs, present a useful message
        if(this.keyStoreCaWrapper.getKeyStoreEntryMap().isEmpty()){
            JOptionPane.showMessageDialog(this, "You appear to have no certificates. Please either\n"
                    + "a) Apply for a certificate with the 'Apply' button or\n"
                    + "b) Import a certificate/key pair from file (this file can be exported from your web browser)");
        } else {
            // set to the first visible cert/key entry (rather than showing e.g. trust root certs). 
            for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
                KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
                if(KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEWComboBox.getEntryType())){
                    this.jComboBox1.setSelectedIndex(index);
                    break; 
                }
            }
       
        }
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
        java.net.URL imgURL = MainWindowPanel.class.getResource(path);
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
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
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

        Date vToDate  = null;

        this.vFrom.setText("");
        this.vTo.setText("");
        this.subjectDnTextField.setText("");
        this.issuerDnTextField.setText("");
        this.rDue.setText("");
        this.dRemaining.setText("");
        this.caCertStatusTextField.setText("Unknown (offline or certificate not recognized by UK CA)");
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

            Format formatter;

            formatter = new SimpleDateFormat("EEE MMM dd HH:mm yyyy");
            String vFromFormatted = "";
            String vToFormatted = "";

            if (selectedKeyStoreEntry.getNotBefore() != null) {
                vFromFormatted = formatter.format(selectedKeyStoreEntry.getNotBefore());
                this.vFrom.setText(vFromFormatted);
            } else {
                this.vFrom.setText("N/A");
            }

            if (selectedKeyStoreEntry.getNotAfter() != null) {
                vToFormatted = formatter.format(selectedKeyStoreEntry.getNotAfter());
                this.vTo.setText(vToFormatted);
            } else {
                this.vTo.setText("N/A");
            }

//            if (selectedKeyStoreEntry.getNotBefore() != null) {
//                this.vFrom.setText(selectedKeyStoreEntry.getNotBefore().toString());
//            } else {
//                this.vFrom.setText("N/A");
//            }
//
//            if (selectedKeyStoreEntry.getNotAfter() != null) {
//                this.vTo.setText(selectedKeyStoreEntry.getNotAfter().toString());
//            } else {
//                this.vTo.setText("N/A");
//            }



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

            //Remaining time

            vToDate= selectedKeyStoreEntry.getNotAfter();
            int timeLeft = Integer.parseInt(getLifeDays(vToDate));
            if (timeLeft < 0)
                this.dRemaining.setText("0");
            else
                this.dRemaining.setText(Integer.toString(timeLeft));

            //Renewal Due

            Calendar renewalDue = Calendar.getInstance();
            renewalDue.setTime(vToDate);
            renewalDue.add(Calendar.MONTH, -1);

            this.rDue.setText(formatter.format(renewalDue.getTime()));

            Calendar todaysDate = Calendar.getInstance();
            
            if (todaysDate.after(renewalDue))
                this.rDue.setForeground(new RenewalDueColor());
            else
                this.rDue.setForeground(Color.black);

        }
        //((TitledBorder)this.jPanel2.getBorder()).setTitle("Your Certificates and Requests ("+this.jComboBox1.getItemCount()+" entries)");
    }

    /**
     * Method used by updateGUIPanel() method to calculate the number of days
     * remaining until the selected certificate expires.
     *
     * @param date of "Valid To"
     * @return number of days remaining until certificate expires
     */
    private String getLifeDays(Date date) {

        long currentMillis = new Date().getTime();
        long endMillis = date.getTime();
        if (endMillis < currentMillis) { //This means it's expired
            return "Expired";
        }
        long diffDays = (endMillis - currentMillis) / (24 * 60 * 60 * 1000);
        //the live days would include the extra rekey days.
        return new Long(diffDays).toString();

    }

    /**
     * Method to allow the user to change the keystore password.
     *
     */
    private void doChangePasswdAction() {

        //ask for the current password first.
        DGetPassword dGetPassword =
            new DGetPassword(null, "Enter the current Keystore Password");
        dGetPassword.setLocationRelativeTo(this);
        SwingHelper.showAndWait(dGetPassword);

        char[] cPkcs12Password = dGetPassword.getPassword();

        if (cPkcs12Password == null) {
            return; //user hit cancel button
        }

        String sPkcs12Password = new String(cPkcs12Password);
        String sCurrentPassword = new String(this.PASSPHRASE);
        
        if (!(sPkcs12Password.equals(sCurrentPassword)))
        {
            JOptionPane.showMessageDialog(this, "The current keystore password you've entered is incorrect",
                    "Wrong Password", JOptionPane.ERROR_MESSAGE);
            return;
        }


        // Get a new password for the new keystore password
        DGetNewPassword dGetNewPassword =
                new DGetNewPassword(null, RB.getString("FPortecle.SetKeyStorePassword.Title"));
        dGetNewPassword.setLocationRelativeTo(this);
        SwingHelper.showAndWait(dGetNewPassword);

        char[] cPKCS12Password = dGetNewPassword.getPassword();

        if (cPKCS12Password == null) {
            return; //user hit cancel button
        }

        if (new String(cPKCS12Password).trim().equals("")) {
            JOptionPane.showMessageDialog(this, "Please enter a password for certificate keystore.",
                "No Password Entered", JOptionPane.ERROR_MESSAGE);
            return;
        }

        //set the new keystore password: set in passphrase.property as well as
        //the variable PASSPHRASE. Finally call the reStorePassword method in
        //ClientKeyStore to restore the keystore with the new password.

        String _pswdProperty = SysProperty.getValue("uk.ngs.ca.passphrase.property");
        String _pswd = new String(cPKCS12Password);
        System.setProperty(_pswdProperty, _pswd);
        this.PASSPHRASE = cPKCS12Password;

        this.keyStoreCaWrapper.getClientKeyStore().reStorePassword(PASSPHRASE);

        JOptionPane.showMessageDialog(this, "Key Store password has successfully been changed",
        "Password Change Successful", JOptionPane.INFORMATION_MESSAGE);


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
            return "(Your certificate request is waiting for approval)";
        } else if ("SUSPENDED".equals(state)) {
            return "(Your certificate revocation request is waiting to be processed)";
        } else if ("RENEW".equals(state)) {
            return "(Your renewal certificate is waiting for approval)";
        } else if ("APPROVED".equals(state)) {
            return "(Your certificate is now waiting for CA signing)";
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
            return;
        }
        // Can only renew key_pairs types issued by our CA
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        if (selectedKSEW != null
                && KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                && selectedKSEW.getServerCertificateCSRInfo() != null
                && "VALID".equals(((KeyStoreEntryWrapper) selectedKSEW).getServerCertificateCSRInfo().getStatus())) {

            int ok = JOptionPane.showConfirmDialog(this, "Are you sure you want to renew the selected certificate?", "Renew Certificate", JOptionPane.OK_CANCEL_OPTION);
            if (JOptionPane.OK_OPTION == ok) {

                //let the user alter the alias
                KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();
                String sAlias = selectedKSEW.getAlias();

                try {
                    sAlias = getNewEntryAliasHelper(keyStore, sAlias, "FPortecle.KeyPairEntryAlias.Title", false);

                    if (sAlias == null) {
                        WaitDialog.hideDialog(); //user hit cancel
                        return;
                    }

                    // Check alias entry does not already exist in the keystore
                    if (keyStore.containsAlias(sAlias)) {

                        JOptionPane.showMessageDialog(
                            this,
                            MessageFormat.format("The keystore already contains an entry with the alias " + sAlias+ "\n"
                            + "Please enter a unique alias", sAlias),
                            RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
                        WaitDialog.hideDialog();
                        return;

                    }

                } catch (KeyStoreException ex) {
                    DThrowable.showAndWait(null, null, ex);
                }

                //submit the renewal request saving the alias in the combo box
                WaitDialog.showDialog("Renew");
                String cert_id = selectedKSEW.getServerCertificateCSRInfo().getId();
                CertificateDownload certDownload = new CertificateDownload(cert_id);
                OnLineUserCertificateReKey rekey = new OnLineUserCertificateReKey(PASSPHRASE,sAlias);
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
        if (!isOnlinePing()) {
            return;
        
        } else {
            Apply apply = new Apply(this, PASSPHRASE);
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
                    Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
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
		JOptionPane.showMessageDialog(this, "Your certificate has been exported successfully.\n"
                                                    + "Please ensure that you make a backup of this\n"
                                                    + "certificate somewhere away from your computer.\n"
                                                    + "E.g. USB dongle, CD/DVD\n",
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
        FileOutputStream certfos = null;
        
        try {
            // prevent install of self signed certs (CSRs)
            X509Certificate testValidCertificateToExport = (X509Certificate) this.keyStoreCaWrapper.getClientKeyStore().getKeyStore().getCertificate(selectedKSEW.getAlias());
            if (testValidCertificateToExport.getIssuerDN().toString().equals(testValidCertificateToExport.getSubjectDN().toString())) {
                JOptionPane.showMessageDialog(this, "You cannot install a certificate request.\n"
                        + "If you have requested a new or a renewal request, please wait until the\n"
                        + "certificate has been approved and signed by e-Science CA before\n"
                        + "installing it.", "Cannot install certificate", JOptionPane.ERROR_MESSAGE);
                return;
            }

            // check online status before installing 
            if (selectedKSEW.getServerCertificateCSRInfo() == null) {
                int ret = JOptionPane.showConfirmDialog(this, "You are either offline or this certificate cannot be validated by our CA\n"
                        + "Are you sure you want to export this certificate ?");
                if (ret != JOptionPane.YES_OPTION) {
                    return;
                }
            } else {
                if (!"VALID".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus())) {
                    int ret = JOptionPane.showConfirmDialog(this, "According to our CA this certificate is not VALID\n"
                            + "Are you sure you want to export this certificate ?");
                    if (ret != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
            }

            // ok, export the selected cert
            // TODO: remove the dependency on org.globus.common.GoGProperties (we can do this ourselves - better to not depend on this)
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


            // first, delete files (if they already exist) 
            fCertFile.delete();
            fKeyFile.delete();
            // get X509Cert and Private key of selected alias 
            String alias = selectedKSEW.getAlias();
            X509Certificate certificate = (X509Certificate) this.keyStoreCaWrapper.getClientKeyStore().getKeyStore().getCertificate(alias);
            PrivateKey privateKey = (PrivateKey) this.keyStoreCaWrapper.getClientKeyStore().getKeyStore().getKey(alias, PASSPHRASE);
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

            JOptionPane.showMessageDialog(this, "[usercert.pem] and [userkey.pem] installed OK to '$USER_HOME/.globus/'",
                    "Install usercert.pem userkey.pem", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception ex) {
            ex.printStackTrace();
            DThrowable.showAndWait(null, null, ex);
        } finally {
            try {
                if (certfos != null) {
                    certfos.close();
                }
            } catch (Exception ex) {/* do nothing */

            }
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



            // Check entry does not already exist in the keystore
            if (keyStore.containsAlias(sAlias)) {

                JOptionPane.showMessageDialog(
                    this,
                    MessageFormat.format("The keystore already contains an entry with the alias " + sAlias+ "\n"
                    + "Please enter a unique alias", sAlias),
                    RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);

                return;

            }

            WaitDialog.showDialog("General");
            // make sure...
            assert keyStore == ClientKeyStore.getClientkeyStore(this.PASSPHRASE).getKeyStore();
            // Place the private key and certificate chain into the keystore and update
            keyStore.setKeyEntry(sAlias, privateKey, this.PASSPHRASE, certs);
     
            // Update the frame's components and title
            this.reloadKeystoreUpdateGUI();
            WaitDialog.hideDialog();
            
            // Set to the combo to the newly imported entry. 
            for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
                KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
                if(sAlias.equals(selectedKSEWComboBox.getAlias())){
                    this.jComboBox1.setSelectedIndex(index);
                    break; 
                }
            }
            
            // Display success message
           JOptionPane.showMessageDialog(this, RB.getString("FPortecle.KeyPairImportSuccessful.message"),
			    RB.getString("FPortecle.ImportKeyPair.Title"), JOptionPane.INFORMATION_MESSAGE);
           return;
        } catch (Exception ex) {
            DThrowable.showAndWait(null, null, ex);
        }
    }

    /**
     * Let the user change the alias for the selected keypair or trusted certificate entry.
     * Based on Portecle.
     * @see FPortecle#renameSelectedEntry()
     */
    private void doChangeAliasAction() {

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

        // Get the entry
        String sAliasOld = selectedKSEW.getAlias();
        KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStore();


        try {

            //retrieve the new alias from the user
            String sAliasNew = getNewEntryAliasHelper(keyStore, sAliasOld, "FPortecle.KeyPairEntryAlias.Title", false);

            

            if (sAliasNew == null) {
                return;
            }

            if (sAliasNew.trim().equals(sAliasOld)) {
                return;
            }
            
            if (sAliasNew.trim().equals("")) {
                JOptionPane.showMessageDialog(this, "You cannot have empty alias name. Please enter a unique friendly name",
                    "No Alias Entered", JOptionPane.ERROR_MESSAGE);
                return;
            }


            // Check entry does not already exist in the keystore
            if (keyStore.containsAlias(sAliasNew)) {

                JOptionPane.showMessageDialog(
                    this,
                    MessageFormat.format("The keystore already contains an entry with the alias " + sAliasNew+ "\n"
                    + "Please enter a unique alias", sAliasNew),
                    RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
                
                return;

            }
            WaitDialog.showDialog("General");
            
            // Create the new entry with the new name and copy the old entry across

            // If the entry is a key pair...
            if (keyStore.isKeyEntry(sAliasOld))
            {

                // Do the copy
                Key key = keyStore.getKey(sAliasOld, this.PASSPHRASE);
                Certificate[] certs = keyStore.getCertificateChain(sAliasOld);
                keyStore.setKeyEntry(sAliasNew, key, this.PASSPHRASE, certs);

            } else {
                // ...if the entry is a trusted certificate
                // Do the copy
                Certificate cert = keyStore.getCertificate(sAliasOld);
                keyStore.setCertificateEntry(sAliasNew, cert);
            }

            // Delete the old entry
            keyStore.deleteEntry(sAliasOld);

            // Update the frame's components and title
            //this.reloadKeystoreUpdateGUI();
            //this.updateCombo();
            KeyStoreEntryWrapper changedKSEW = this.keyStoreCaWrapper.getKeyStoreEntryMap().get(sAliasOld);
            changedKSEW.setAlias(sAliasNew);
            this.keyStoreCaWrapper.getKeyStoreEntryMap().remove(sAliasOld);
            this.keyStoreCaWrapper.getKeyStoreEntryMap().put(sAliasNew, changedKSEW);          
            this.updateGUI();


            WaitDialog.hideDialog();

            return;

        } catch (Exception ex) {
            DThrowable.showAndWait(null, null, ex);
        } finally {
            WaitDialog.hideDialog();
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

            return sAlias;

        }
    }





    /**
     * Invoke PingService to test for connection
     */
    private boolean isOnlinePing() {
        boolean online = PingService.getPingService().isPingService();
        if (!online) {
            JOptionPane.showMessageDialog(this, "Cannot connect to the CA Server. Please ensure that you are connected to the Internet.\n"
                    + "If you are connected to the Internet but still unable to connect to the CA Server, please check your firewall\n"
                    + "settings and ensure you allow Java to access to the Internet. If problem still persists, please contact\n"
                    + "the helpdesk at support@grid-support.ac.uk.", "Server Connection Fault", JOptionPane.ERROR_MESSAGE);
    //            stringMotD = "You are working offline.\n\nThe certificate can not be renewed offline.";
            setRedMOD(stringMotDOffline);
    //            this.btnRefresh.setText("Connect");
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
        caCertStatusTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        certificateTypeLabel = new javax.swing.JLabel();
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
        btnChangeAlias = new javax.swing.JButton();
        jPanel3 = new javax.swing.JPanel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TextMOD = new javax.swing.JTextArea();
        jLabel7 = new javax.swing.JLabel();
        btnChangePasswd = new javax.swing.JButton();

        jRadioButton1.setText("jRadioButton1");

        setPreferredSize(new java.awt.Dimension(840, 458));
        addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseExited(java.awt.event.MouseEvent evt) {
                formMouseExited(evt);
            }
        });
        setLayout(new org.netbeans.lib.awtextra.AbsoluteLayout());

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
                .add(7, 7, 7)
                .add(btnNewCertificateRequest, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 73, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btnImportCertificate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 82, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(13, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .add(jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(btnNewCertificateRequest)
                    .add(btnImportCertificate))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        add(jPanel1, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 132, -1, 60));

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificates and Requests  "));

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
        subjectDnTextField.setAutoscrolls(true);
        subjectDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));
        subjectDnTextField.setMaximumSize(new java.awt.Dimension(2, 18));
        subjectDnTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                subjectDnTextFieldActionPerformed(evt);
            }
        });

        jLabel8.setText("Issuer DN:");

        issuerDnTextField.setEditable(false);
        issuerDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel9.setText("Alias:");

        aliasTextField.setEditable(false);
        aliasTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel10.setText("Type:");

        caCertStatusTextField.setEditable(false);
        caCertStatusTextField.setFont(new java.awt.Font("Tahoma", 1, 11));
        caCertStatusTextField.setText("Unknown");
        caCertStatusTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));
        caCertStatusTextField.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                caCertStatusTextFieldActionPerformed(evt);
            }
        });

        jLabel2.setText("Status:");

        certificateTypeLabel.setText("CertificateType");

        vFrom.setEditable(false);
        vFrom.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));
        vFrom.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                vFromActionPerformed(evt);
            }
        });

        jLabel3.setText("Valid From:");

        jLabel4.setText("Valid To:");

        vTo.setEditable(false);
        vTo.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel5.setText("Days Remaining:");

        jLabel6.setText("Renewal Due:");

        dRemaining.setEditable(false);
        dRemaining.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));
        dRemaining.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                dRemainingActionPerformed(evt);
            }
        });

        rDue.setEditable(false);
        rDue.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));
        rDue.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                rDueActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel4Layout = new org.jdesktop.layout.GroupLayout(jPanel4);
        jPanel4.setLayout(jPanel4Layout);
        jPanel4Layout.setHorizontalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel4Layout.createSequentialGroup()
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel3)
                    .add(jLabel4))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                    .add(vTo)
                    .add(vFrom, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 132, Short.MAX_VALUE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jLabel5)
                    .add(jLabel6))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(dRemaining, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE)
                    .add(rDue, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 146, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel4Layout.setVerticalGroup(
            jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel4Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jPanel4Layout.createSequentialGroup()
                        .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                            .add(jLabel5)
                            .add(dRemaining, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(jLabel6)
                            .add(rDue, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                    .add(jPanel4Layout.createSequentialGroup()
                        .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(jLabel3)
                            .add(vFrom, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 23, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jPanel4Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(vTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(jLabel4))))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel4Layout.linkSize(new java.awt.Component[] {dRemaining, rDue, vFrom, vTo}, org.jdesktop.layout.GroupLayout.VERTICAL);

        viewCertDetailsButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/view_icon.gif"))); // NOI18N
        viewCertDetailsButton.setText("View Details");
        viewCertDetailsButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                viewCertDetailsButtonMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                viewCertDetailsButtonMouseExited(evt);
            }
        });
        viewCertDetailsButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                viewCertDetailsButtonActionPerformed(evt);
            }
        });

        btnRefresh.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/ajax-refresh-icon.gif"))); // NOI18N
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

        btnInstall.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/install.PNG"))); // NOI18N
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

        btnRenew.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/icon_renew.GIF"))); // NOI18N
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

        btnExport.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/icon_exportBib.gif"))); // NOI18N
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

        btnRevoke.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/revoke.png"))); // NOI18N
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

        btnDelete.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/delete_icon.png"))); // NOI18N
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

        btnChangeAlias.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/edit_icon.gif"))); // NOI18N
        btnChangeAlias.setText("Change Alias");
        btnChangeAlias.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnChangeAliasMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnChangeAliasMouseExited(evt);
            }
        });
        btnChangeAlias.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnChangeAliasActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout pnlAllDetailsLayout = new org.jdesktop.layout.GroupLayout(pnlAllDetails);
        pnlAllDetails.setLayout(pnlAllDetailsLayout);
        pnlAllDetailsLayout.setHorizontalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(62, 62, 62)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                            .add(btnInstall, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .add(btnRefresh, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 105, Short.MAX_VALUE))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                            .add(btnExport, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .add(btnRenew, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 106, Short.MAX_VALUE))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                            .add(btnDelete, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .add(btnRevoke, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 104, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .addContainerGap()
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                            .add(jPanel4, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .add(pnlAllDetailsLayout.createSequentialGroup()
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                    .add(jLabel1)
                                    .add(jLabel8)
                                    .add(jLabel2)
                                    .add(jLabel9)
                                    .add(jLabel10))
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                                    .add(issuerDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 390, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                    .add(pnlAllDetailsLayout.createSequentialGroup()
                                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                                            .add(certificateTypeLabel)
                                            .add(aliasTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 240, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                                        .add(16, 16, 16)
                                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                                            .add(viewCertDetailsButton, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 121, Short.MAX_VALUE)
                                            .add(btnChangeAlias, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                                    .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 390, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                    .add(caCertStatusTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 390, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))))))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        pnlAllDetailsLayout.setVerticalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel1)
                    .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(issuerDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel8))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(caCertStatusTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(jLabel2))
                        .add(13, 13, 13)
                        .add(jLabel9)
                        .add(18, 18, 18)
                        .add(jLabel10))
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(32, 32, 32)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(aliasTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(btnChangeAlias))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(certificateTypeLabel)
                            .add(viewCertDetailsButton))))
                .add(1, 1, 1)
                .add(jPanel4, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 70, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(btnRefresh, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .add(btnRenew, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 26, Short.MAX_VALUE))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(btnInstall, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(btnExport, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(btnRevoke, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 27, Short.MAX_VALUE)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(btnDelete, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {aliasTextField, caCertStatusTextField, issuerDnTextField, subjectDnTextField}, org.jdesktop.layout.GroupLayout.VERTICAL);

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 480, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addContainerGap())
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .add(6, 6, 6)
                .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 28, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        add(jPanel2, new org.netbeans.lib.awtextra.AbsoluteConstraints(211, 24, -1, -1));

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
            .add(jPanel3Layout.createSequentialGroup()
                .addContainerGap()
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 158, Short.MAX_VALUE)
                .addContainerGap())
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel3Layout.createSequentialGroup()
                .add(jScrollPane1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, 205, Short.MAX_VALUE)
                .addContainerGap())
        );

        add(jPanel3, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 199, -1, -1));

        jLabel7.setIcon(new javax.swing.ImageIcon(getClass().getResource("/uk/ngs/ca/images/stfc-transparent.png"))); // NOI18N
        add(jLabel7, new org.netbeans.lib.awtextra.AbsoluteConstraints(12, 40, 194, 47));

        btnChangePasswd.setText("Change Password");
        btnChangePasswd.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                btnChangePasswdMouseEntered(evt);
            }
            public void mouseExited(java.awt.event.MouseEvent evt) {
                btnChangePasswdMouseExited(evt);
            }
        });
        btnChangePasswd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnChangePasswdActionPerformed(evt);
            }
        });
        add(btnChangePasswd, new org.netbeans.lib.awtextra.AbsoluteConstraints(34, 100, -1, -1));
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
        this.mouseExitedActionPerformed(evt);
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
        setMOD("Export the selected certificate to a file for back up, or for use in other tools."
                + "You will be prompted to create a password to protect your exported certificate");
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
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnInstallMouseExited

    private void btnImportCertificateMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnImportCertificateMouseExited

    private void mouseExitedActionPerformed(java.awt.event.MouseEvent evt) {
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
//            stringMotD = "You are working offline.\n\nPlease note that working offline only display valid certificates. Please select working online, if you want to access all certificates.";
            setRedMOD(stringMotDOffline);
        }
    }

    private void jComboBox1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_jComboBox1MouseExited

    private void btnRenewMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnRenewMouseExited

    private void btnExportMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnExportMouseExited

    private void btnRevokeMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnRevokeMouseExited

    private void btnDeleteMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnDeleteMouseExited

    private void jComboBox1ItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_jComboBox1ItemStateChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBox1ItemStateChanged

    private void btnRefreshActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRefreshActionPerformed

        if (!isOnlinePing()) {
            return;
        }
        stringMotD = motd.getText();
        //Fetch the alias of the selected certificate in order to select that entry again in the combo box
        //after refresh completes
        String alias = null;
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "There are no certificate in the keystore", "No certificate in the keystore!", JOptionPane.WARNING_MESSAGE);
            return;
        } else {
            KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
            // Get the entry
            alias = selectedKSEW.getAlias();
        }

        WaitDialog.showDialog("General");
        assert this.keyStoreCaWrapper.getClientKeyStore().getKeyStore() ==
                ClientKeyStore.getClientkeyStore(PASSPHRASE).getKeyStore();
        this.reloadKeystoreUpdateGUI();


        //select the same entry as what the user has previously selected.
        String retrievedAlias = "";
        KeyStoreEntryWrapper selectedKSEWComboBox = null;

        for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
            selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
            // Get the entry
            retrievedAlias = selectedKSEWComboBox.getAlias();

            //if the retrieved Alias is the same one as user selected, select it.
            if (retrievedAlias.equals(alias)) {
                this.jComboBox1.setSelectedIndex(index);
                WaitDialog.hideDialog();
                return;
            }
        }

        
    }//GEN-LAST:event_btnRefreshActionPerformed

    private void btnRefreshMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRefreshMouseEntered
        // TODO add your handling code here:
        setMOD("Retrieve certificate information from the CA Server and update the status of the certificates stored in the Certificate Wizard");
    }//GEN-LAST:event_btnRefreshMouseEntered

    private void btnRefreshMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRefreshMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnRefreshMouseExited

    private void viewCertDetailsButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonActionPerformed
        // TODO add your handling code here:
        this.doViewCertificateDetailsAction();
    }//GEN-LAST:event_viewCertDetailsButtonActionPerformed

    private void dRemainingActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_dRemainingActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_dRemainingActionPerformed

    private void btnChangeAliasActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnChangeAliasActionPerformed
        // TODO add your handling code here:
        this.doChangeAliasAction();
    }//GEN-LAST:event_btnChangeAliasActionPerformed

    private void caCertStatusTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_caCertStatusTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_caCertStatusTextFieldActionPerformed

    private void rDueActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_rDueActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_rDueActionPerformed

    private void subjectDnTextFieldActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_subjectDnTextFieldActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_subjectDnTextFieldActionPerformed

    private void btnChangePasswdActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnChangePasswdActionPerformed
        // TODO add your handling code here:
        this.doChangePasswdAction();
    }//GEN-LAST:event_btnChangePasswdActionPerformed

    private void btnChangePasswdMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangePasswdMouseEntered
        // TODO add your handling code here:
        setMOD("Change the Certificate Wizard global password used to protect all your certificates in Certificate Wizard");

    }//GEN-LAST:event_btnChangePasswdMouseEntered

    private void btnChangePasswdMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangePasswdMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnChangePasswdMouseExited

    private void btnChangeAliasMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangeAliasMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnChangeAliasMouseExited

    private void viewCertDetailsButtonMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonMouseExited
        // TODO add your handling code here:
        this.mouseExitedActionPerformed(evt);

    }//GEN-LAST:event_viewCertDetailsButtonMouseExited

    private void btnChangeAliasMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangeAliasMouseEntered
        // TODO add your handling code here:
        setMOD("Change the user friendly name of the selected certificate");
    }//GEN-LAST:event_btnChangeAliasMouseEntered

    private void viewCertDetailsButtonMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonMouseEntered
        // TODO add your handling code here:
        setMOD("View further details of the selected certificate. If you have imported and selected a certificate chain, "
                + "you will be able to view details of the individual certificates contained in the certificate chain.");
    }//GEN-LAST:event_viewCertDetailsButtonMouseEntered

    private void vFromActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_vFromActionPerformed
        // TODO add your handling code here:
    }//GEN-LAST:event_vFromActionPerformed

  
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
    private javax.swing.JButton btnChangeAlias;
    private javax.swing.JButton btnChangePasswd;
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
