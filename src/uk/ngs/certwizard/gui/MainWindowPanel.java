package uk.ngs.certwizard.gui;

import java.awt.Color;
import java.awt.Component;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.Format;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.*;
import net.sf.portecle.DGetAlias;
import net.sf.portecle.DViewCertificate;
import net.sf.portecle.FPortecle;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.LastDir;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;
import net.sf.portecle.gui.password.DGetNewPassword;
import net.sf.portecle.gui.password.DGetPassword;
import org.bouncycastle.util.encoders.Base64;
import org.globus.common.CoGProperties;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.util.PEMUtils;
import org.globus.util.Util;
import uk.ngs.ca.certificate.OnLineUserCertificateReKey;
import uk.ngs.ca.certificate.client.CAMotd;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.PingService;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE;
import uk.ngs.ca.common.GuiExecutor;
import uk.ngs.ca.common.SystemStatus;
import uk.ngs.ca.task.OnlineUpdateKeyStoreEntriesSwingWorker;
import uk.ngs.ca.tools.property.SysProperty;
import uk.ngs.ca.util.CertificateExportUtil;
import uk.ngs.ca.util.CertificateImportUtil;

/**
 * GUI for displaying the keyStore entries in the user's
 * '$HOME/.ca/cakeystore.pkcs12' file. This class also manages importing,
 * exporting, deleting requesting, renewing certificates. <p> Lots of
 * refactoring is required and extracting logic out of this class into service
 * classes and helper function objects. The <tt>caKeyStoreModel</tt> needs to be
 * extracted into an external class that is accessible from other GUI
 * components. Lots of original xw75 code remains.
 *
 * @author Xiao Wang
 * @author David Meredith (partial refactoring)
 */
public class MainWindowPanel extends javax.swing.JPanel implements Observer {

    private ImageIcon[] images; 
    private String stringMotD = "Hit the Refresh button to fetch the latest message of the Day";
    private final CAMotd motd = new CAMotd();
    private char[] PASSPHRASE;
    private ClientKeyStoreCaServiceWrapper caKeyStoreModel = null;
    private String stringMotDOffline = "You are working offline.\n\nYou will not be able to apply-for, renew or revoke "
            + "your certificates until a connection has been established. "
            + "Hit the Refresh button to try and reconnect.\n\nTo configure CertWizard's connection see:\nhttp://ngs.ac.uk/tools/certwizard";
    /**
     * The last directory accessed by the application
     */
    private final LastDir m_lastDir = new LastDir();
    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    /**
     * Portecle Resource bundle
     */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);
    //private final AtomicBoolean onlineUpdateTaskRunning = new AtomicBoolean(false); 
    //private final ExecutorService invokeOnceBackgroundExec = Executors.newSingleThreadExecutor();
    //private final ScheduledExecutorService schedBackgroundExec = Executors.newSingleThreadScheduledExecutor();
    //private BackgroundTask<Void> runningOnlineUpdateTask;  // confined to AWT event thread. 
    private OnlineUpdateKeyStoreEntriesSwingWorker onlineUpdateTask = new OnlineUpdateKeyStoreEntriesSwingWorker(null, null, null);
    //private ScheduledExecutorService messageOfDayExecutor = Executors.newSingleThreadScheduledExecutor();

   
    
    /**
     * Creates new form MainWindowPanel
     */
    public MainWindowPanel(char[] passphrase) {
        super();
        this.PASSPHRASE = passphrase;
         
        System.setProperty(SysProperty.getValue("uk.ngs.ca.immegration.password.property"),
                this.PASSPHRASE.toString());
        initComponents();
        loadImages();

        try {
            this.caKeyStoreModel = ClientKeyStoreCaServiceWrapper.getInstance(this.PASSPHRASE);
        } catch (KeyStoreException ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
            // TODO still need to sort out exceptions and show an error dialog here with the problem
        }

        this.jComboBox1.setRenderer(new ComboBoxRenderer());

        // populate the keystore by reading local file  
        try {
            this.caKeyStoreModel.loadFromFile();
        } catch (KeyStoreException ex) {
            Logger.getLogger(MainWindowPanel.class.getName()).log(Level.SEVERE, null, ex);
            JOptionPane.showMessageDialog(null, "Unable to load KeyStore: " + ex.getMessage(), "Unable to load KeyStore", JOptionPane.ERROR_MESSAGE);
        }
        this.updateKeyStoreGuiFromModel();
        this.setComboFirstCertEntry();
    }

    /**
     * Do some post object construction checks. Shows modal message dialogs if
     * a) no certificates exist in the managed CA keystore b) a newer version of
     * the certificate wizard is available.
     */
    public void doPostConstruct() {
        
        if (this.caKeyStoreModel.getKeyStoreEntryMap().isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "You have no certificates. Please either:\n"
                    + "a) Apply for a certificate with the [Apply For New Cert] button or\n"
                    + "b) Import an existing certificate from a backup file with the [Import Cert From File] button\n\n"
                    + "(Note, you can export your certificate as a backup file from your web browser)",
                    "No Certificates Found",
                    JOptionPane.INFORMATION_MESSAGE);

        }
        //Now fetch the latest version from the server. Required info is in DBCAInfo, ultimately
        //handled by the CAResource class.
        String latestVersion = motd.getLatestVersion();
        String certWizardVersion = SysProperty.getValue("ngsca.certwizard.versionNumber");
        if (!(certWizardVersion.equals(latestVersion))) {
            JOptionPane.showMessageDialog(this, "A new version of the Certificate Wizard is available!\n"
                    + "Please go to www.ngs.ac.uk in order to obtain the latest version",
                    "New Version of Certificate Wizard", JOptionPane.INFORMATION_MESSAGE);
        }
        //messageOfDayExecutor.scheduleWithFixedDelay(new MessageOfDayTask(), 0, 30, TimeUnit.MINUTES);

        // Start thread executors to update cert/csr combo list and MOD 
        //this.schedBackgroundExec.scheduleWithFixedDelay(runningOnlineUpdateTask, 0, 1, TimeUnit.MINUTES); 

        onlineUpdateTask = new OnlineUpdateKeyStoreEntriesSwingWorker(
                caKeyStoreModel.getKeyStoreEntryMap(), caKeyStoreModel, this);
        onlineUpdateTask.addPropertyChangeListener(onlineUpdateTaskPropertyListener); 
        onlineUpdateTask.execute();
    }

    /**
     * Handle onlineUpdateTask property changes (runs in AWT Event thread) 
     */    
    private PropertyChangeListener onlineUpdateTaskPropertyListener = new PropertyChangeListener() {

        public void propertyChange(PropertyChangeEvent e) {
            String propertyName = e.getPropertyName();
            if ("progress".equals(propertyName)) {
                // not handled currently 
            } else if ("state".equals(propertyName)) {
                //System.out.println("state change is: "+onlineUpdateTask.getState());
                if (SwingWorker.StateValue.DONE.equals(onlineUpdateTask.getState())) {
                    updateOnlineUpdateComponents(false);
                } else if (SwingWorker.StateValue.PENDING.equals(onlineUpdateTask.getState())) {
                    updateOnlineUpdateComponents(true);
                } else if (SwingWorker.StateValue.STARTED.equals(onlineUpdateTask.getState())) {
                    updateOnlineUpdateComponents(true);
                } else {
                    updateOnlineUpdateComponents(false);
                }
            }
        }
    };
    
    
    private void updateOnlineUpdateComponents(boolean running) {
        if (running) {
            btnCancelOnlineUpdate.setEnabled(true);
            jProgressBar1.setEnabled(true);
            jProgressBar1.setIndeterminate(true); 
            labelOnlineUpdate.setText("Updating...");
            btnRefreshAll.setEnabled(false); 
        } else {
            btnCancelOnlineUpdate.setEnabled(false);
            jProgressBar1.setEnabled(false);
            jProgressBar1.setIndeterminate(false); 
            jProgressBar1.setValue(100); 
            labelOnlineUpdate.setText("");
            btnRefreshAll.setEnabled(true);
        }
    }
    
    /**
     * The keyStore GUI components are updated when invoked by an observable.
     *
     * @param observable the observable object.
     * @param obj an argument passed to the <code>notifyObservers</code> method.
     */
    public void update(Observable observable, Object obj) {
        /*if (observable != null && observable instanceof OnlineUpdateKeyStoreEntries) {}*/
        this.updateKeyStoreGuiFromModel();
    }

    /**
     * Load the images used in the GUI
     */
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

    /**
     * Returns an ImageIcon, or null if the path was invalid.
     */
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
     * Update the GUI according to the current state of <code>this.caKeyStoreModel</code>.
     * Important, there is no reStore/reload of keyStore. The update of the GUI
     * components is guaranteed to be executed in the AWT event thread. 
     */
    public final void updateKeyStoreGuiFromModel() {
        GuiExecutor.instance().execute(new Runnable() {
            public void run() {
                reloadComboFromModel();
                updateGUIPanel();
            }
        });
    }

    /**
     * Reload combo from <code>this.caKeyStoreModel.getKeyStoreEntryMap()<code>
     * (note, no reload of keystore !). Combo elements are rendered with CombBoxRenderer inner class.
     */
    private void reloadComboFromModel() {
        int preSelectedIndex = this.jComboBox1.getSelectedIndex();
        this.jComboBox1.removeAllItems();
        Collection<KeyStoreEntryWrapper> keyStoreEntries = this.caKeyStoreModel.getKeyStoreEntryMap().values();
        for (Iterator<KeyStoreEntryWrapper> it = keyStoreEntries.iterator(); it.hasNext();) {
            this.jComboBox1.addItem(it.next());
        }
        if (this.jComboBox1.getItemCount() > 0) {
            // show the previously selected index. 
            if (preSelectedIndex < this.jComboBox1.getItemCount()) {
                this.jComboBox1.setSelectedIndex(preSelectedIndex);
            } else {
                this.jComboBox1.setSelectedIndex(0);
            }
        } else {
            this.jComboBox1.setSelectedItem(null);
        }
    }

    /**
     * Set the selected combo item according to the given alias. 
     */
    private void setComboSelectedItemByAlias(String alias) {
        for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
            KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
            if (alias.equals(selectedKSEWComboBox.getAlias())) {
                this.jComboBox1.setSelectedIndex(index); 
                break;
            }
        }
    }
    
    /**
     * Get the number of certificate/keY entries (e.g. exclude trust root certs). 
     */
    private int getComboCertEntryCount() {
        int count = 0 ; 
        if (!this.caKeyStoreModel.getKeyStoreEntryMap().isEmpty()) {
            for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
                KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
                if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEWComboBox.getEntryType())) {
                    ++ count; 
                }
            }
        }
        return count; 
    }
    
    /**
     * Set to the first visible cert/key entry (rather than showing e.g. trust root cert). 
     */
    private void setComboFirstCertEntry() {
        if (!this.caKeyStoreModel.getKeyStoreEntryMap().isEmpty()) {
            for (int index = 0; index < this.jComboBox1.getItemCount(); index++) {
                KeyStoreEntryWrapper selectedKSEWComboBox = (KeyStoreEntryWrapper) this.jComboBox1.getItemAt(index);
                if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEWComboBox.getEntryType())) {
                    this.jComboBox1.setSelectedIndex(index);
                    break;
                }
            }
        }
    }
    
    /**
     * Update other GUI components based on selected combo item (note, no reload of keystore !)
     */
    private void updateGUIPanel() {
        // nullify/clear the gui components first
        this.vFrom.setText("");
        this.vTo.setText("");
        this.subjectDnTextField.setText("");
        this.issuerDnTextField.setText("");
        this.rDue.setText("");
        this.dRemaining.setText("");
        this.caCertStatusTextField.setText("Unknown (offline or certificate not recognized by UK CA)");
        // set to default color first
        this.caCertStatusTextField.setForeground(this.getColorFromState(null, null));
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

            if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_ENTRY.equals(selectedKeyStoreEntry.getEntryType())) {
                this.certificateTypeLabel.setText("Key");
                this.certificateTypeLabel.setIcon(this.images[1]);
            } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKeyStoreEntry.getEntryType())) {
                this.certificateTypeLabel.setText("Certificate + Private Key");
                this.certificateTypeLabel.setIcon(this.images[2]);
            } else if (KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.TRUST_CERT_ENTRY.equals(selectedKeyStoreEntry.getEntryType())) {
                this.certificateTypeLabel.setText("Trusted Third Party Certificate");
                this.certificateTypeLabel.setIcon(this.images[0]);
            }

            Format formatter;
            formatter = new SimpleDateFormat("EEE MMM dd HH:mm yyyy");
            if (selectedKeyStoreEntry.getNotBefore() != null) {
                this.vFrom.setText(formatter.format(selectedKeyStoreEntry.getNotBefore()));
            } else {
                this.vFrom.setText("N/A");
            }

            if (selectedKeyStoreEntry.getNotAfter() != null) {
                this.vTo.setText(formatter.format(selectedKeyStoreEntry.getNotAfter()));
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


            // First, get the date info from the keystore entry 
            Date endDate = selectedKeyStoreEntry.getNotAfter();
            Calendar todaysDate = Calendar.getInstance();


            // If the CertificateCSRInfo member object of the selected
            // keyStoreEntryWrapper is null, then we did not retrieve
            // the CA server info for this cert (maybe offline or an unrecognized
            // certificate not issued by our CA).
            if (selectedKeyStoreEntry.getServerCertificateCSRInfo() != null) {
                String state = selectedKeyStoreEntry.getServerCertificateCSRInfo().getStatus();
                this.caCertStatusTextField.setText(state + " " + this.getExtraLabelTextFromState(state));
                this.caCertStatusTextField.setForeground(this.getColorFromState(state, endDate));
            }

            //Remaining time
            if (endDate.after(todaysDate.getTime())) {
                // endDate is after today (hence we have time left) 
                long diffDays = (endDate.getTime() - todaysDate.getTimeInMillis()) / (24 * 60 * 60 * 1000);
                this.dRemaining.setText(String.valueOf(diffDays));
            } else {
                // we are expired  
                this.dRemaining.setText("0");
                // this is required because the CA server returned state will be 
                // valid even if the state is Expired (i.e. it is up to the 
                // client to check the time remaining and set set state accordingly). 
                this.caCertStatusTextField.setText("Expired" + " " + this.getExtraLabelTextFromState("Expired"));
            }


            //Renewal Due
            Calendar renewalDue = Calendar.getInstance();
            renewalDue.setTime(endDate);
            renewalDue.add(Calendar.MONTH, -1);
            this.rDue.setText(formatter.format(renewalDue.getTime()));
            if (todaysDate.after(renewalDue)) {
                this.rDue.setForeground(new RenewalDueColor());
            } else {
                this.rDue.setForeground(Color.black);
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
                    this.setForeground(getColorFromState(state, keyStoreEntry.getNotAfter()));
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
     * Return the appropriate display colour according to the given state
     * string. If state is null or not recognised, then return
     * <code>Color.DARK_GRAY</code> as default. If State is equal to 'VALID' and
     * the endDate is not null, then test to see if the end date is before
     * today, if true, we are actually expired. This is required because the CA
     * server returns the 'VALID' state even if the certificate's end date is in
     * the past (i.e. it is valid in that it is recognised by our CA server, but
     * it has actually expired).
     *
     * @param state Optional end date / not after date of keystore entry
     * (nullable).
     * @param endDate
     * @return The colour that is appropriate to given state
     */
    private Color getColorFromState(String state, Date endDate) {
        if ("VALID".equals(state)) {
            if (endDate != null) {
                Calendar todaysDate = Calendar.getInstance();
                if (endDate.before(todaysDate.getTime())) {
                    // End date is BEFORE today, hence we are Expired. 
                    // TODO: If end date is more than 30 days before today, set to 
                    // ExpiredForeverCertColor, otherwise there may be a chance to 
                    // renew within next 30 day threshold. 
                    return new ExpiredCertColor();
                }
            }
            return new ValidCertColor();

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
    // The next 4 methods (renew, revoke, import, applyForNew) all require  
    // contacting the CA service online
    ///////////////////////////////////////////////////////////////////////////
    /**
     * Called by the Renew button. 
     */
    private void doRenewAction()  {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }

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

                JOptionPane.showMessageDialog(this, "You will now be prompted to enter a new unique alias\n"
                        + "for your certificate to be renewed.", "Certificate Renewal", JOptionPane.INFORMATION_MESSAGE);
                //let the user alter the alias
                //KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStoreCopy();
                String newCsrRenewalAlias = selectedKSEW.getAlias();

                try {
                    newCsrRenewalAlias = getNewEntryAliasHelper(newCsrRenewalAlias, "FPortecle.KeyPairEntryAlias.Title", false);

                    if (newCsrRenewalAlias == null) {
                        WaitDialog.hideDialog(); //user hit cancel
                        return;
                    }

                    // Check alias entry does not already exist in the keystore
                    //if (keyStore.containsAlias(sAlias)) {
                    if (this.caKeyStoreModel.getClientKeyStore().containsAlias(newCsrRenewalAlias)) {
                        JOptionPane.showMessageDialog(
                                this,
                                MessageFormat.format("The keystore already contains an entry with the alias " + newCsrRenewalAlias + "\n"
                                + "Please enter a unique alias", newCsrRenewalAlias),
                                RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
                        WaitDialog.hideDialog();
                        return;

                    }

                } catch (KeyStoreException ex) {
                    DThrowable.showAndWait(null, null, ex);
                }

                // Submit the renewal request saving the new csr renewal under the 
                // new alias in the keystore. The existing cert that is selected 
                // for renewal is left untouched.  
                WaitDialog.showDialog("Please wait for renewal to complete");
                String cert_id = selectedKSEW.getServerCertificateCSRInfo().getId();
                CertificateDownload certDownload = new CertificateDownload(cert_id);
                OnLineUserCertificateReKey rekey = new OnLineUserCertificateReKey(PASSPHRASE, newCsrRenewalAlias, certDownload.getCertificate());
                boolean isReadyForReKey = rekey.isValidReKey();

                if (isReadyForReKey) {
                    // Submit renewal here (does not reStore keyStore but does add a new entry for CSR) 
                    boolean submittedOk = rekey.doPosts(); 
                    WaitDialog.hideDialog();
                    if (submittedOk) {
                        JOptionPane.showMessageDialog(this, "The renewal request has been submitted", "Renewal request successful", JOptionPane.INFORMATION_MESSAGE);

                        try {
                            // Persist the keystore to file 
                            this.caKeyStoreModel.getClientKeyStore().reStore();                       
                            
                            // Add a new keystore entry to the model (don't
                            // reload all the entries from model as exsisting online
                            // state of the different entries will be lost) 
                            KeyStoreEntryWrapper newCsrEntry = this.caKeyStoreModel.createKSEntryWrapperInstanceFromEntry(newCsrRenewalAlias);
                            this.caKeyStoreModel.getKeyStoreEntryMap().put(newCsrRenewalAlias, newCsrEntry);                          
                            this.reloadComboFromModel();
                            this.setComboSelectedItemByAlias(newCsrRenewalAlias);                         
                                           
                            if (caKeyStoreModel.onlineUpdateKeyStoreEntry(newCsrEntry)) {
                                // Don't need to reStore (no online state is saved to file)
                                //caKeyStoreModel.getClientKeyStore().reStore(); 
                            }        
                        } catch(KeyStoreException ex){
                            DThrowable.showAndWait(null, "Problem Saving Renewal Certificate", ex);
                        }

                    } else {
                        String messageTitle = rekey.getErrorMessage();
                        String moreMessage = rekey.getDetailErrorMessage();
                        JOptionPane.showMessageDialog(this, moreMessage, messageTitle, JOptionPane.ERROR_MESSAGE);
                    }
                    this.updateKeyStoreGuiFromModel();
                    
                } else {
                    WaitDialog.hideDialog();
                    JOptionPane.showMessageDialog(this, "The selected certificate is not valid to renew", "wrong certificate", JOptionPane.WARNING_MESSAGE);
                }
            }
        } else {
            JOptionPane.showMessageDialog(this, "Only VALID certificates issued by the UK CA can be renewed",
                    "No suitable certificate selected", JOptionPane.WARNING_MESSAGE);
        }

    }

    /**
     * Called by the Revoke button. 
     */
    private void doRevokeAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
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
                        this.caKeyStoreModel.getClientKeyStore().getPrivateKey(selectedKSEW.getAlias()),
                        cert_id, reason);
                // do the revokation with the CA and block (note, this has 
                // no interaction with the keystore) 
                boolean revoked = revokeRequest.doPosts();

                // Just reload the selected entry rather than refreshing all 
                try {
                    if (caKeyStoreModel.onlineUpdateKeyStoreEntry(selectedKSEW)) {
                        // Don't need to reStore (no online state is saved to file)
                        //caKeyStoreModel.getClientKeyStore().reStore(); 
                    }
                } catch (KeyStoreException ex) {
                    DThrowable.showAndWait(null, "Problem Revoking Certificate", ex);
                }
                this.updateKeyStoreGuiFromModel();

                WaitDialog.hideDialog();

                if (revoked) {
                    JOptionPane.showMessageDialog(this, revokeRequest.getMessage(), "Certificate revoked", JOptionPane.INFORMATION_MESSAGE);
                } 
            }
        } else {
            JOptionPane.showMessageDialog(this, "Only VALID certificates issued by the UK CA can be revoked",
                    "No suitable certificate selected", JOptionPane.WARNING_MESSAGE);
        }
    }
    
    /**
     * Let the user import a key pair a PKCS #12 keystore or a PEM bundle. 
     * Based on Portecle.
     *
     * @see FPortecle#importKeyPair() 
     */
    private void doImportCertificateAction() {
        // prevent import when background thread is refreshing. 
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
        try {
            CertificateImportUtil util = new CertificateImportUtil(this, PASSPHRASE);
            String newHeadCertImportAlias = util.doImportCertificateAction();
            if(newHeadCertImportAlias != null){
                // Update the status of the newly imported head cert. 
                this.reloadComboFromModel();
                this.setComboSelectedItemByAlias(newHeadCertImportAlias);

                KeyStoreEntryWrapper kew = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
                if (caKeyStoreModel.onlineUpdateKeyStoreEntry(kew)) {
                    // we don't need to reStore (no online state is saved to keystore file)
                    //caKeyStoreModel.getClientKeyStore().reStore(); 
                }
                // don't want to reload keystore because any online state (CertificateCSRInfo) 
                // for the existing keyStoreEntryWrapperS will be lost. 
                //this.caKeyStoreModel.loadFromFile(); 
            }
            
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Importing Certificate", ex);
        }
        this.updateKeyStoreGuiFromModel();
    }

    /**
     * Called by the Apply button. 
     */
    private void doApplyForNewCertificateAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
        if (isOnlinePing()) {
            Apply apply = new Apply(PASSPHRASE);
            apply.setModal(true);
            apply.setVisible(true);
            
            // if a new CSR entry was added to the keystore, set as selected
            if (apply.getStoredAlias() != null) {
                
                // reload the combo entries before we select the selected entry
                this.reloadComboFromModel();
                this.setComboSelectedItemByAlias(apply.getStoredAlias());
                try {
                    KeyStoreEntryWrapper kew = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
                    if (caKeyStoreModel.onlineUpdateKeyStoreEntry(kew)) {
                        // we don't need to reStore (no online state is saved to keystore file)
                        //caKeyStoreModel.getClientKeyStore().reStore(); 
                    }
                } catch (KeyStoreException ex) {
                    DThrowable.showAndWait(null, "Problem Applying for Certificate", ex);
                }
            }
            this.updateKeyStoreGuiFromModel();
        }
    }

    private boolean confirmBackgroundTaskRunning() {
        if (this.onlineUpdateTask != null && !this.onlineUpdateTask.isDone()) {
            //if(this.onlineUpdateTaskRunning.get()){
            JOptionPane.showMessageDialog(this,
                    "Cannot run task while executing background online update task. "
                    + "\nCancel the task or wait for its completion.",
                    "Executing background task", JOptionPane.WARNING_MESSAGE);
            return true;
        } else {
            return false;
        }
    }

    ///////////////////////////////////////////////////////////////////////////
    // The next 6 methods (changeKeyStorePW, delete, viewDetails, export, install, change alias)
    // are generic keystore actions that do not require the CA service.
    ///////////////////////////////////////////////////////////////////////////
    
    /**
     * Change the keyStore password.
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

        if (!(sPkcs12Password.equals(sCurrentPassword))) {
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
        this.caKeyStoreModel.getClientKeyStore().reStorePassword(PASSPHRASE);

        JOptionPane.showMessageDialog(this, "Key Store password has successfully been changed",
                    "Password Change Successful", JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Called by the Delete button to delete selected keyStore entry (not
     * revocation)
     */
    private void doDeleteAction() {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
        } else {
            int delete = JOptionPane.showConfirmDialog(this, "Are you sure you want to delete this KeyStore entry ?", "Delete KeyStore Entry", JOptionPane.OK_CANCEL_OPTION);
            if (delete == JOptionPane.OK_OPTION) {
                try {
                    // delete calls reStore 
                    this.caKeyStoreModel.deleteEntry(((KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem()).getAlias());
                    this.updateKeyStoreGuiFromModel();
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
     *
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
        if (selectedType == null || selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        String sAlias = selectedKSEW.getAlias();
        // Get snapshot of the keystore (prevents interferance from background update thread)
        KeyStore keyStoreCopy = this.caKeyStoreModel.getClientKeyStore().getKeyStoreCopy();

        try {
            // Get the entry's certificates
            X509Certificate[] certs;
            if (this.caKeyStoreModel.getClientKeyStore().isKeyEntry(sAlias)) {
                // If entry is a key pair
                certs = X509CertUtil.convertCertificates(keyStoreCopy.getCertificateChain(sAlias));
            } else {
                // If entry is a trusted certificate
                certs = new X509Certificate[1];
                certs[0] = X509CertUtil.convertCertificate(keyStoreCopy.getCertificate(sAlias));
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
     * Let the user export the selected entry. Based on Portecle.
     *
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
        if (selectedType == null || selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return false;
        }
        // Get the entry
        String sAlias = selectedKSEW.getAlias();
        try {
            CertificateExportUtil certExportUtil = new CertificateExportUtil(this, PASSPHRASE);
            return certExportUtil.doExportAction(sAlias);
        } catch (KeyStoreException ex) {
            DThrowable.showAndWait(null, null, ex);
        }
        return false;
    }

    /**
     * Install the selected cert as '$HOME/.globus/usercert.pem' and
     * '$HOME/.globus/userkey.pem' for subsequent globus usage. TODO - move
     * logic into new class to reduce size of this class
     */
    private void doInstallPemsSelectedCertificateAction() {
        // check that a certificate is selected
        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || !selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate and key pair!", "No certificate key pair selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        FileOutputStream certfos = null;

        try {
            // work with a snapshot of the keystore at this point in time. 
            KeyStore keyStoreCopy = this.caKeyStoreModel.getClientKeyStore().getKeyStoreCopy();
            // prevent install of self signed certs (CSRs)
            X509Certificate testValidCertificateToExport = (X509Certificate) keyStoreCopy.getCertificate(selectedKSEW.getAlias());
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
                        + "Are you sure you want to install this certificate ?");
                if (ret != JOptionPane.YES_OPTION) {
                    return;
                }
            } else {
                if (!"VALID".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus())) {
                    int ret = JOptionPane.showConfirmDialog(this, "According to our CA this certificate is not VALID\n"
                            + "Are you sure you want to install this certificate ?");
                    if (ret != JOptionPane.YES_OPTION) {
                        return;
                    }
                }
            }

            // ok, install the selected cert
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
            X509Certificate certificate = (X509Certificate) keyStoreCopy.getCertificate(alias);
            PrivateKey privateKey = (PrivateKey) keyStoreCopy.getKey(alias, PASSPHRASE);
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
            DThrowable.showAndWait(null, null, ex);
        } finally {
            try {
                if (certfos != null) {
                    certfos.close();
                }
            } catch (Exception ignore) {
            }
        }
    }

    /**
     * Let the user change the alias for the selected keypair or trusted
     * certificate entry. Based on Portecle.
     *
     * @see FPortecle#renameSelectedEntry()
     */
    private void doChangeAliasAction() {

        if (this.jComboBox1.getSelectedIndex() == -1) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
        KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE selectedType = selectedKSEW.getEntryType();
        if (selectedType == null || selectedType.equals(KEYSTORE_ENTRY_TYPE.KEY_ENTRY)) {
            JOptionPane.showMessageDialog(this, "Please select a certificate!", "No certificate selected", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        // Get the entry
        String sAliasOld = selectedKSEW.getAlias();
        //KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStoreCopy();

        try {
            //retrieve the new alias from the user
            String sAliasNew = getNewEntryAliasHelper(sAliasOld, "FPortecle.KeyPairEntryAlias.Title", false);
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
            if (this.caKeyStoreModel.getClientKeyStore().containsAlias(sAliasNew)) {
                JOptionPane.showMessageDialog(
                        this,
                        MessageFormat.format("The keystore already contains an entry with the alias " + sAliasNew + "\n"
                        + "Please enter a unique alias", sAliasNew),
                        RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
                return;
            }
            WaitDialog.showDialog("General");

            // Create the new entry with the new name and copy the old entry across

            // If the entry is a key pair...
            if (this.caKeyStoreModel.getClientKeyStore().isKeyEntry(sAliasOld)) {
                // Do the copy
                Key key = this.caKeyStoreModel.getClientKeyStore().getKey(sAliasOld, this.PASSPHRASE);
                Certificate[] certs = this.caKeyStoreModel.getClientKeyStore().getCertificateChain(sAliasOld);
                this.caKeyStoreModel.getClientKeyStore().setKeyEntry(sAliasNew, key, this.PASSPHRASE, certs);

            } else {
                // ...if the entry is a trusted certificate
                // Do the copy
                Certificate cert = this.caKeyStoreModel.getClientKeyStore().getCertificate(sAliasOld);
                this.caKeyStoreModel.getClientKeyStore().setCertificateEntry(sAliasNew, cert);
            }

            // Delete the old entry
            this.caKeyStoreModel.getClientKeyStore().deleteEntry(sAliasOld);

            // Update the frame's components and title
            //this.reloadKeystoreUpdateGUI();
            //this.updateCombo();
            KeyStoreEntryWrapper changedKSEW = this.caKeyStoreModel.getKeyStoreEntryMap().get(sAliasOld);
            changedKSEW.setAlias(sAliasNew);
            this.caKeyStoreModel.getKeyStoreEntryMap().remove(sAliasOld);
            this.caKeyStoreModel.getKeyStoreEntryMap().put(sAliasNew, changedKSEW);
            this.updateKeyStoreGuiFromModel();
            WaitDialog.hideDialog();

        } catch (Exception ex) {
            DThrowable.showAndWait(null, null, ex);
        } finally {
            WaitDialog.hideDialog();
        }
    }

    /**
     * Start a background task to online update the keyStore entries and update GUI. 
     * 
     * @param all if true updates all entries, otherwise will only attempt to update 
     * the currently selected entry. 
     */
    private void doRefreshActionAsBackgroundTask(boolean all) {
        if (this.confirmBackgroundTaskRunning()) {
            return;
        }

        if (this.jComboBox1.getSelectedIndex() == -1) {
            //JOptionPane.showMessageDialog(this, "There are no certificates in the keystore", "No certificate in the keystore!", JOptionPane.WARNING_MESSAGE);
        } else {
            Map<String, KeyStoreEntryWrapper> updateEntries;
            if (all) {
                updateEntries = this.caKeyStoreModel.getKeyStoreEntryMap();
            } else {
                KeyStoreEntryWrapper selectedKSEW = (KeyStoreEntryWrapper) this.jComboBox1.getSelectedItem();
                updateEntries = new HashMap(1);
                updateEntries.put(selectedKSEW.getAlias(), selectedKSEW);
            }
            //this.onlineUpdateTask = new OnlineUpdateKeyStoreEntries(updateEntries, this.caKeyStoreModel, this.onlineUpdateTaskRunning);
            //this.onlineUpdateTask.addObserver(this); 
            //this.invokeOnceBackgroundExec.execute(onlineUpdateTask);
            this.onlineUpdateTask = new OnlineUpdateKeyStoreEntriesSwingWorker(
                    updateEntries, caKeyStoreModel, this);
            this.onlineUpdateTask.addPropertyChangeListener(onlineUpdateTaskPropertyListener);
            this.onlineUpdateTask.execute();
            this.btnRefreshAll.setEnabled(false);
        }
    }
    
    /**
     * Cancel the background online update task (if running) 
     */
    private void doCancelOnlineUpdateAction(){
        if(this.onlineUpdateTask != null){
            this.onlineUpdateTask.cancel(true); 
        }
    }
    

    /**
     * Gets a new entry alias from user, handling overwrite issues. Based on
     * Portecle.
     *
     * @see FPortecle#getNewEntryAlias(java.security.KeyStore, java.lang.String,
     * java.lang.String, boolean)
     *
     * @param sAlias suggested alias
     * @param dialogTitleKey message key for dialog titles
     * @param selectAlias whether to pre-select alias text in text field
     * @return alias for new entry, null if user cancels the operation
     */
    private String getNewEntryAliasHelper(String sAlias, String dialogTitleKey,
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
            setRedMOD(stringMotDOffline);
        }
        return online;
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        btnNewCertificateRequest = new javax.swing.JButton();
        btnImportCertificate = new javax.swing.JButton();
        pnlAllDetails = new javax.swing.JPanel();
        subjectDnTextField = new javax.swing.JTextField();
        jLabel1 = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();
        issuerDnTextField = new javax.swing.JTextField();
        caCertStatusTextField = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        aliasTextField = new javax.swing.JTextField();
        jLabel9 = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        certificateTypeLabel = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        vFrom = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        dRemaining = new javax.swing.JTextField();
        jLabel4 = new javax.swing.JLabel();
        vTo = new javax.swing.JTextField();
        jLabel6 = new javax.swing.JLabel();
        rDue = new javax.swing.JTextField();
        btnRenew = new javax.swing.JButton();
        btnRevoke = new javax.swing.JButton();
        btnChangeAlias = new javax.swing.JButton();
        btnInstall = new javax.swing.JButton();
        btnExport = new javax.swing.JButton();
        btnDelete = new javax.swing.JButton();
        viewCertDetailsButton = new javax.swing.JButton();
        jLabel12 = new javax.swing.JLabel();
        jScrollPane1 = new javax.swing.JScrollPane();
        TextMOD = new javax.swing.JTextArea();
        jPanel2 = new javax.swing.JPanel();
        btnChangePasswd = new javax.swing.JButton();
        jComboBox1 = new javax.swing.JComboBox();
        btnRefreshAll = new javax.swing.JButton();
        btnCancelOnlineUpdate = new javax.swing.JButton();
        labelOnlineUpdate = new javax.swing.JLabel();
        jProgressBar1 = new javax.swing.JProgressBar();

        setMinimumSize(new java.awt.Dimension(0, 0));

        jPanel1.setBorder(javax.swing.BorderFactory.createTitledBorder("Add Certificate to Keystore"));

        btnNewCertificateRequest.setText("Apply For Cert");
        btnNewCertificateRequest.setToolTipText("Apply for a new certificate from the UK eScience CA. The certificate will be added to your keystore. ");
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

        btnImportCertificate.setText("Import Cert");
        btnImportCertificate.setToolTipText("Import an existing certificate from a .p12/.pfx file (this file is normally exported from a web browser). ");
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
                .add(jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(btnImportCertificate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                    .add(btnNewCertificateRequest, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .add(btnNewCertificateRequest)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btnImportCertificate)
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel1Layout.linkSize(new java.awt.Component[] {btnImportCertificate, btnNewCertificateRequest}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetails.setBorder(javax.swing.BorderFactory.createTitledBorder("Selected Certificate Details"));

        subjectDnTextField.setEditable(false);
        subjectDnTextField.setAutoscrolls(true);
        subjectDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));
        subjectDnTextField.setMaximumSize(new java.awt.Dimension(2, 18));

        jLabel1.setText("Subject DN:");

        jLabel8.setText("Issuer DN:");

        issuerDnTextField.setEditable(false);
        issuerDnTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        caCertStatusTextField.setEditable(false);
        caCertStatusTextField.setFont(new java.awt.Font("Tahoma", 1, 11)); // NOI18N
        caCertStatusTextField.setText("Unknown");
        caCertStatusTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel2.setText("Status:");

        aliasTextField.setEditable(false);
        aliasTextField.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel9.setText("Alias:");

        jLabel10.setText("Type:");

        certificateTypeLabel.setText("CertificateType");

        jLabel3.setText("Valid From:");

        vFrom.setEditable(false);
        vFrom.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel5.setText("Days Remain:");

        dRemaining.setEditable(false);
        dRemaining.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel4.setText("Valid To:");

        vTo.setEditable(false);
        vTo.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        jLabel6.setText("Renewal Due:");

        rDue.setEditable(false);
        rDue.setBorder(javax.swing.BorderFactory.createLineBorder(new java.awt.Color(153, 153, 153)));

        btnRenew.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/icon_renew.GIF"))); // NOI18N
        btnRenew.setText("Renew");
        btnRenew.setToolTipText("Renew the selected certificate");
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

        btnRevoke.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/revoke.png"))); // NOI18N
        btnRevoke.setText("Revoke");
        btnRevoke.setToolTipText("Revoke the selected certificate");
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

        btnChangeAlias.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/edit_icon.gif"))); // NOI18N
        btnChangeAlias.setText("Change Alias");
        btnChangeAlias.setToolTipText("Change the Alias of the selected certificate (a user friendly name)");
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

        btnInstall.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/install.PNG"))); // NOI18N
        btnInstall.setText("Install");
        btnInstall.setToolTipText("Install the selected certifcate so grid applications can use it.");
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

        btnExport.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/icon_exportBib.gif"))); // NOI18N
        btnExport.setText("Export");
        btnExport.setToolTipText("Export the selected certificate as a backup file.");
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

        btnDelete.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/delete_icon.png"))); // NOI18N
        btnDelete.setText("Delete");
        btnDelete.setToolTipText("Delete the selected certificate from you keystore.");
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

        viewCertDetailsButton.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/view_icon.gif"))); // NOI18N
        viewCertDetailsButton.setToolTipText("View the selected certificate details");
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

        jLabel12.setText("Actions:");

        org.jdesktop.layout.GroupLayout pnlAllDetailsLayout = new org.jdesktop.layout.GroupLayout(pnlAllDetails);
        pnlAllDetails.setLayout(pnlAllDetailsLayout);
        pnlAllDetailsLayout.setHorizontalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap()
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(jLabel8)
                            .add(jLabel2)
                            .add(jLabel1)
                            .add(jLabel9)
                            .add(jLabel10)
                            .add(jLabel3)
                            .add(jLabel4))
                        .add(29, 29, 29)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(pnlAllDetailsLayout.createSequentialGroup()
                                .add(vTo)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(jLabel6)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(rDue, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 174, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                            .add(pnlAllDetailsLayout.createSequentialGroup()
                                .add(vFrom)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(jLabel5)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(dRemaining, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 174, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                            .add(pnlAllDetailsLayout.createSequentialGroup()
                                .add(certificateTypeLabel)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .add(viewCertDetailsButton, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 32, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                            .add(org.jdesktop.layout.GroupLayout.TRAILING, caCertStatusTextField)
                            .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .add(issuerDnTextField)
                            .add(aliasTextField)))
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(jLabel12)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(pnlAllDetailsLayout.createSequentialGroup()
                                .add(btnInstall, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btnExport, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btnDelete, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                            .add(pnlAllDetailsLayout.createSequentialGroup()
                                .add(btnRenew, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 106, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btnRevoke, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 104, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btnChangeAlias, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 131, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))))))
        );

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {btnChangeAlias, btnDelete, btnExport, btnInstall, btnRenew, btnRevoke}, org.jdesktop.layout.GroupLayout.HORIZONTAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {dRemaining, rDue}, org.jdesktop.layout.GroupLayout.HORIZONTAL);

        pnlAllDetailsLayout.setVerticalGroup(
            pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(pnlAllDetailsLayout.createSequentialGroup()
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(subjectDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel1))
                .add(6, 6, 6)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(issuerDnTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel8))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(caCertStatusTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                    .add(jLabel2))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                    .add(jLabel9)
                    .add(aliasTextField, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 22, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                    .add(jLabel10)
                    .add(certificateTypeLabel)
                    .add(viewCertDetailsButton))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.TRAILING)
                        .add(jLabel5)
                        .add(dRemaining, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                    .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                        .add(jLabel3)
                        .add(vFrom, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 23, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)))
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                        .add(jLabel6)
                        .add(rDue, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                    .add(jLabel4)
                    .add(vTo, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(pnlAllDetailsLayout.createSequentialGroup()
                        .add(39, 39, 39)
                        .add(jLabel12)
                        .add(61, 61, 61))
                    .add(org.jdesktop.layout.GroupLayout.TRAILING, pnlAllDetailsLayout.createSequentialGroup()
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(btnRenew, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(btnRevoke, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(btnChangeAlias, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(pnlAllDetailsLayout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                            .add(btnInstall, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 27, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(btnExport, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(btnDelete, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 26, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
                        .add(28, 28, 28))))
        );

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {issuerDnTextField, subjectDnTextField}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {dRemaining, rDue, vFrom, vTo}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {btnDelete, btnExport, btnInstall, btnRenew, btnRevoke}, org.jdesktop.layout.GroupLayout.VERTICAL);

        pnlAllDetailsLayout.linkSize(new java.awt.Component[] {btnChangeAlias, viewCertDetailsButton}, org.jdesktop.layout.GroupLayout.VERTICAL);

        TextMOD.setColumns(20);
        TextMOD.setWrapStyleWord(true);
        TextMOD.setLineWrap(true);
        TextMOD.setRows(5);
        jScrollPane1.setViewportView(TextMOD);

        jPanel2.setBorder(javax.swing.BorderFactory.createTitledBorder("Certificates in my Keystore"));

        btnChangePasswd.setText("Change Password");
        btnChangePasswd.setToolTipText("Your certificates are stored in a password protected keystore file.");
        btnChangePasswd.setActionCommand("Change KeyStore Password");
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

        btnRefreshAll.setIcon(new javax.swing.ImageIcon(getClass().getResource("/help_panel_html/images/ajax-refresh-icon.gif"))); // NOI18N
        btnRefreshAll.setToolTipText("Refresh all keystore certificates");
        btnRefreshAll.setEnabled(false);
        btnRefreshAll.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnRefreshAllActionPerformed(evt);
            }
        });

        org.jdesktop.layout.GroupLayout jPanel2Layout = new org.jdesktop.layout.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .add(btnChangePasswd)
                .add(25, 25, 25)
                .add(jComboBox1, 0, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(btnRefreshAll, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 37, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(org.jdesktop.layout.GroupLayout.TRAILING, jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(btnRefreshAll)
                    .add(jPanel2Layout.createParallelGroup(org.jdesktop.layout.GroupLayout.BASELINE)
                        .add(jComboBox1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 28, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .add(btnChangePasswd)))
                .addContainerGap(org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        btnCancelOnlineUpdate.setIcon(new javax.swing.ImageIcon(getClass().getResource("/net/sf/portecle/images/action/exit.gif"))); // NOI18N
        btnCancelOnlineUpdate.setEnabled(false);
        btnCancelOnlineUpdate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                btnCancelOnlineUpdateActionPerformed(evt);
            }
        });

        labelOnlineUpdate.setText("...");
        labelOnlineUpdate.setToolTipText("");

        jProgressBar1.setToolTipText("Online CA update task");

        org.jdesktop.layout.GroupLayout layout = new org.jdesktop.layout.GroupLayout(this);
        this.setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .addContainerGap()
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(layout.createSequentialGroup()
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING, false)
                            .add(jScrollPane1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .add(jPanel1, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.UNRELATED)
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .add(layout.createSequentialGroup()
                                .add(0, 0, Short.MAX_VALUE)
                                .add(labelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 111, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(jProgressBar1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 56, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                                .add(btnCancelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 23, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                                .add(6, 6, 6))))
                    .add(jPanel2, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .add(13, 13, 13))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
            .add(layout.createSequentialGroup()
                .add(12, 12, 12)
                .add(jPanel2, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                    .add(layout.createSequentialGroup()
                        .add(jPanel1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED)
                        .add(jScrollPane1))
                    .add(layout.createSequentialGroup()
                        .add(pnlAllDetails, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 332, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(org.jdesktop.layout.LayoutStyle.RELATED, 8, Short.MAX_VALUE)
                        .add(layout.createParallelGroup(org.jdesktop.layout.GroupLayout.LEADING)
                            .add(org.jdesktop.layout.GroupLayout.TRAILING, jProgressBar1, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, org.jdesktop.layout.GroupLayout.DEFAULT_SIZE, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(org.jdesktop.layout.GroupLayout.TRAILING, btnCancelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 19, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE)
                            .add(org.jdesktop.layout.GroupLayout.TRAILING, labelOnlineUpdate, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE, 14, org.jdesktop.layout.GroupLayout.PREFERRED_SIZE))))
                .add(8, 8, 8))
        );
    }// </editor-fold>//GEN-END:initComponents

    private void jComboBox1ActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jComboBox1ActionPerformed
        this.updateGUIPanel();
    }//GEN-LAST:event_jComboBox1ActionPerformed

    private void btnNewCertificateRequestActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestActionPerformed
        this.doApplyForNewCertificateAction();
    }//GEN-LAST:event_btnNewCertificateRequestActionPerformed

    private void btnImportCertificateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnImportCertificateActionPerformed
        this.doImportCertificateAction();
    }//GEN-LAST:event_btnImportCertificateActionPerformed

    private void btnExportActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnExportActionPerformed
        this.doExportAction();
    }//GEN-LAST:event_btnExportActionPerformed

    private void btnRenewActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRenewActionPerformed
        this.doRenewAction();
    }//GEN-LAST:event_btnRenewActionPerformed

    private void btnRevokeActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRevokeActionPerformed
        this.doRevokeAction();
    }//GEN-LAST:event_btnRevokeActionPerformed

    private void btnDeleteActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnDeleteActionPerformed
        this.doDeleteAction();
    }//GEN-LAST:event_btnDeleteActionPerformed

    private void btnNewCertificateRequestMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseEntered
        setMOD("Request a new user certificate");
    }//GEN-LAST:event_btnNewCertificateRequestMouseEntered

    private void btnNewCertificateRequestMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnNewCertificateRequestMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnNewCertificateRequestMouseExited

    private void btnImportCertificateMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseEntered
        setMOD("Import an existing certificate file into the certificate wizard.");
    }//GEN-LAST:event_btnImportCertificateMouseEntered

    private void jComboBox1MouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseEntered
        setMOD("Your current certificates and certificate requests.");
    }//GEN-LAST:event_jComboBox1MouseEntered

    private void btnRenewMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseEntered
        setMOD("Renew the selected certificate 30 days before it expires (the certificate must be valid).");
    }//GEN-LAST:event_btnRenewMouseEntered

    private void btnExportMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseEntered
        setMOD("Export the selected certificate to a file for back up, or for use in other tools."
                + "You will be prompted to create a password to protect your exported certificate");
    }//GEN-LAST:event_btnExportMouseEntered

    private void btnRevokeMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseEntered
        setMOD("Revoke your certificate if it is compromised or invalid.");
    }//GEN-LAST:event_btnRevokeMouseEntered

    private void btnDeleteMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseEntered
        setMOD("Remove your certificate from the tool. "
                + "This will not delete any other copies of the certificate from your computer.");
    }//GEN-LAST:event_btnDeleteMouseEntered

    private void btnInstallActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnInstallActionPerformed
        this.doInstallPemsSelectedCertificateAction();
    }//GEN-LAST:event_btnInstallActionPerformed

    private void btnInstallMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseEntered
        setMOD("Install the selected certificate to local PEM files: \n\n"
                + "'$HOME/.globus/usercert.pem' \n"
                + "'$HOME/.globus/usercert.pem' ");
    }//GEN-LAST:event_btnInstallMouseEntered

    private void btnInstallMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnInstallMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnInstallMouseExited

    private void btnImportCertificateMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnImportCertificateMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnImportCertificateMouseExited

    private void mouseExitedActionPerformed(java.awt.event.MouseEvent evt) {
        if (SystemStatus.getInstance().getIsOnline()) {
            setMOD(stringMotD);
        } else {
            setRedMOD(stringMotDOffline);
        }
    }

    private void jComboBox1MouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_jComboBox1MouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_jComboBox1MouseExited

    private void btnRenewMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRenewMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnRenewMouseExited

    private void btnExportMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnExportMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnExportMouseExited

    private void btnRevokeMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnRevokeMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnRevokeMouseExited

    private void btnDeleteMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnDeleteMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnDeleteMouseExited

    private void jComboBox1ItemStateChanged(java.awt.event.ItemEvent evt) {//GEN-FIRST:event_jComboBox1ItemStateChanged
        // TODO add your handling code here:
    }//GEN-LAST:event_jComboBox1ItemStateChanged

    private void viewCertDetailsButtonActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonActionPerformed
        this.doViewCertificateDetailsAction();
    }//GEN-LAST:event_viewCertDetailsButtonActionPerformed

    private void btnChangeAliasActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnChangeAliasActionPerformed
        this.doChangeAliasAction();
    }//GEN-LAST:event_btnChangeAliasActionPerformed

    private void btnChangePasswdActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnChangePasswdActionPerformed
        this.doChangePasswdAction();
    }//GEN-LAST:event_btnChangePasswdActionPerformed

    private void btnChangePasswdMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangePasswdMouseEntered
        setMOD("Change the Certificate Wizard global password used to protect all your certificates in Certificate Wizard");

    }//GEN-LAST:event_btnChangePasswdMouseEntered

    private void btnChangePasswdMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangePasswdMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnChangePasswdMouseExited

    private void btnChangeAliasMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangeAliasMouseExited
        this.mouseExitedActionPerformed(evt);
    }//GEN-LAST:event_btnChangeAliasMouseExited

    private void viewCertDetailsButtonMouseExited(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonMouseExited
        this.mouseExitedActionPerformed(evt);

    }//GEN-LAST:event_viewCertDetailsButtonMouseExited

    private void btnChangeAliasMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_btnChangeAliasMouseEntered
        setMOD("Give the selected certificate a unique user friendly name (Alias)");
    }//GEN-LAST:event_btnChangeAliasMouseEntered

    private void viewCertDetailsButtonMouseEntered(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_viewCertDetailsButtonMouseEntered
        setMOD("View further details of the selected certificate. If you have imported and selected a certificate chain, "
                + "you will be able to view details of the individual certificates contained in the certificate chain.");
    }//GEN-LAST:event_viewCertDetailsButtonMouseEntered

    private void btnRefreshAllActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnRefreshAllActionPerformed
        int keyPairCount = getComboCertEntryCount();
        if (keyPairCount > 0) {
            if (keyPairCount == 1) {
                doRefreshActionAsBackgroundTask(true);
            } else {
                //Custom button text
                Object[] options = {"All", "Selected Only"};
                int n = JOptionPane.showOptionDialog(this,
                        "Refresh all certificates or selected certificate only ",
                        "Refresh certificate status with UK CA",
                        JOptionPane.YES_NO_OPTION,
                        JOptionPane.QUESTION_MESSAGE,
                        null,
                        options,
                        options[1]);
                if (JOptionPane.YES_OPTION == n) {
                    doRefreshActionAsBackgroundTask(true);
                } else {
                    doRefreshActionAsBackgroundTask(false);
                }
            }
        }
    }//GEN-LAST:event_btnRefreshAllActionPerformed

    private void btnCancelOnlineUpdateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_btnCancelOnlineUpdateActionPerformed
        doCancelOnlineUpdateAction(); 
    }//GEN-LAST:event_btnCancelOnlineUpdateActionPerformed

    private void setRedMOD(String text) {
        TextMOD.setForeground(Color.RED);
        TextMOD.setText(text);
    }

    private void setMOD(String text) {
        TextMOD.setForeground(Color.BLACK);
        TextMOD.setText(text);
    }

  
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JTextArea TextMOD;
    private javax.swing.JTextField aliasTextField;
    private javax.swing.JButton btnCancelOnlineUpdate;
    private javax.swing.JButton btnChangeAlias;
    private javax.swing.JButton btnChangePasswd;
    private javax.swing.JButton btnDelete;
    private javax.swing.JButton btnExport;
    private javax.swing.JButton btnImportCertificate;
    private javax.swing.JButton btnInstall;
    private javax.swing.JButton btnNewCertificateRequest;
    private javax.swing.JButton btnRefreshAll;
    private javax.swing.JButton btnRenew;
    private javax.swing.JButton btnRevoke;
    private javax.swing.JTextField caCertStatusTextField;
    private javax.swing.JLabel certificateTypeLabel;
    private javax.swing.JTextField dRemaining;
    private javax.swing.JTextField issuerDnTextField;
    private javax.swing.JComboBox jComboBox1;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel12;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JProgressBar jProgressBar1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JLabel labelOnlineUpdate;
    private javax.swing.JPanel pnlAllDetails;
    private javax.swing.JTextField rDue;
    private javax.swing.JTextField subjectDnTextField;
    private javax.swing.JTextField vFrom;
    private javax.swing.JTextField vTo;
    private javax.swing.JButton viewCertDetailsButton;
    // End of variables declaration//GEN-END:variables
}
