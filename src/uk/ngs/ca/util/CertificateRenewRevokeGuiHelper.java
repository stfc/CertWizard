/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.util;

import java.awt.Component;
import java.security.KeyStoreException;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import javax.swing.JOptionPane;
import net.sf.portecle.DGetAlias;
import net.sf.portecle.FPortecle;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;
import uk.ngs.ca.certificate.OnLineUserCertificateReKey;
import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.certwizard.gui.WaitDialog;

/**
 * Helper class for performing certificate renewals and revocations. 
 * The methods invoked by this class present GUI components during their processing. 
 * 
 * @author David Meredith
 */
public class CertificateRenewRevokeGuiHelper {

    private ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    private Component parentCompoent;
    //private char[] PASSPHRASE;
    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);

    public CertificateRenewRevokeGuiHelper(Component parentCompoent, ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        this.parentCompoent = parentCompoent;
        //this.PASSPHRASE = passphrase;
        this.caKeyStoreModel = caKeyStoreModel;
    }

    /**
     * Lead the user through the revocation process for the given keyStore entry.
     * The method generates GUI components during its processing. 
     * The method does not make any changes to the application's keyStore file. 
     * 
     * @param selectedKSEW
     * @return true if revoked, otherwise false. 
     */
    public boolean doRevoke(KeyStoreEntryWrapper selectedKSEW) {
        if (selectedKSEW != null
                && KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                && selectedKSEW.getServerCertificateCSRInfo() != null
                && "VALID".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus())) {

            int ok = JOptionPane.showConfirmDialog(parentCompoent, "Are you sure you want to revoke the selected certificate?", "Revoke Certificate", JOptionPane.OK_CANCEL_OPTION);
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
                //this.updateKeyStoreGuiFromModel();

                WaitDialog.hideDialog();


                if (revoked) {
                    JOptionPane.showMessageDialog(parentCompoent, revokeRequest.getMessage(), "Certificate revoked", JOptionPane.INFORMATION_MESSAGE);
                    return true;
                } else {
                    return false;
                }
            }
        } else {
            JOptionPane.showMessageDialog(parentCompoent, "Only VALID certificates issued by the UK CA can be revoked",
                    "No suitable certificate selected", JOptionPane.WARNING_MESSAGE);
        }
        return false;
    }

    /**
     * Lead the user through the renewal process for the given keyStore entry.
     * The method generates GUI components during its processing. 
     * The method creates and persists a new CSR certificate in the application's keyStore file. 
     *
     * @param selectedKSEW
     * @return the keyStore alias of the newly added renewal CSR.  
     */
    public String doRenew(KeyStoreEntryWrapper selectedKSEW) {
        // Can only renew key_pairs types issued by our CA
        if (selectedKSEW != null
                && KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                && selectedKSEW.getServerCertificateCSRInfo() != null
                && "VALID".equals(((KeyStoreEntryWrapper) selectedKSEW).getServerCertificateCSRInfo().getStatus())) {

            int ok = JOptionPane.showConfirmDialog(parentCompoent, "Are you sure you want to renew the selected certificate?", "Renew Certificate", JOptionPane.OK_CANCEL_OPTION);
            if (JOptionPane.OK_OPTION == ok) {

                JOptionPane.showMessageDialog(parentCompoent, "You will now be prompted to enter a new unique alias\n"
                        + "for your certificate to be renewed.", "Certificate Renewal", JOptionPane.INFORMATION_MESSAGE);
                //let the user alter the alias
                //KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStoreCopy();
                String newCsrRenewalAlias = selectedKSEW.getAlias();

                try {
                    newCsrRenewalAlias = getNewEntryAliasHelper(newCsrRenewalAlias, "FPortecle.KeyPairEntryAlias.Title", false);

                    if (newCsrRenewalAlias == null) {
                        WaitDialog.hideDialog(); //user hit cancel
                        return null;
                    }

                    // Check alias entry does not already exist in the keystore
                    //if (keyStore.containsAlias(sAlias)) {
                    if (this.caKeyStoreModel.getClientKeyStore().containsAlias(newCsrRenewalAlias)) {
                        JOptionPane.showMessageDialog(
                                parentCompoent,
                                MessageFormat.format("The keystore already contains an entry with the alias " + newCsrRenewalAlias + "\n"
                                + "Please enter a unique alias", newCsrRenewalAlias),
                                RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
                        WaitDialog.hideDialog();
                        return null;

                    }

                } catch (KeyStoreException ex) {
                    DThrowable.showAndWait(null, null, ex);
                }

                // Submit the renewal request saving the new csr renewal under the 
                // new alias in the keystore. The existing cert that is selected 
                // for renewal is left untouched.  
                WaitDialog.showDialog("Please wait, submitting renewal request");
                String cert_id = selectedKSEW.getServerCertificateCSRInfo().getId();
                CertificateDownload certDownload = new CertificateDownload(cert_id);
                OnLineUserCertificateReKey rekey = new OnLineUserCertificateReKey( 
                        this.caKeyStoreModel, 
                        newCsrRenewalAlias, certDownload.getCertificate());
                boolean isReadyForReKey = rekey.isValidReKey();

                if (isReadyForReKey) {
                    // Submit renewal here (does not reStore keyStore but does add a new entry for CSR) 
                    boolean submittedOk = rekey.doPosts();
                    WaitDialog.hideDialog();
                    if (submittedOk) {
                        JOptionPane.showMessageDialog(parentCompoent, "The renewal request has been submitted", "Renewal request successful", JOptionPane.INFORMATION_MESSAGE);

                        try {
                            // Persist the keystore to file 
                            this.caKeyStoreModel.getClientKeyStore().reStore();

                            // Add a new keystore entry to the model (don't
                            // reload all the entries from model as exsisting online
                            // state of the different entries will be lost) 
                            KeyStoreEntryWrapper newCsrEntry = this.caKeyStoreModel.createKSEntryWrapperInstanceFromEntry(newCsrRenewalAlias);
                            this.caKeyStoreModel.getKeyStoreEntryMap().put(newCsrRenewalAlias, newCsrEntry);
                            if (caKeyStoreModel.onlineUpdateKeyStoreEntry(newCsrEntry)) {
                                // Don't need to reStore (no online state is saved to file)
                                //caKeyStoreModel.getClientKeyStore().reStore(); 
                            }
                            return newCsrRenewalAlias;

                        } catch (Exception ex) {
                            DThrowable.showAndWait(null, "Problem Saving Renewal Certificate", ex);
                        }

                    } else {
                        String messageTitle = rekey.getErrorMessage();
                        String moreMessage = rekey.getDetailErrorMessage();
                        JOptionPane.showMessageDialog(parentCompoent, moreMessage, messageTitle, JOptionPane.ERROR_MESSAGE);
                    }
                    //this.updateKeyStoreGuiFromModel();

                } else {
                    WaitDialog.hideDialog();
                    JOptionPane.showMessageDialog(parentCompoent, "The selected certificate is not valid to renew", "wrong certificate", JOptionPane.WARNING_MESSAGE);
                }
            }
        } else {
            JOptionPane.showMessageDialog(parentCompoent, "Only VALID certificates issued by the UK CA can be renewed",
                    "No suitable certificate selected", JOptionPane.WARNING_MESSAGE);
        }
        return null;
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
            dGetAlias.setLocationRelativeTo(parentCompoent);
            SwingHelper.showAndWait(dGetAlias);

            sAlias = dGetAlias.getAlias();
            if (sAlias == null) {
                return null;
            }
            return sAlias;
        }
    }
}
