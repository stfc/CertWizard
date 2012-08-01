/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.util;

import java.awt.Component;
import java.awt.Cursor;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import javax.swing.JOptionPane;
import net.sf.portecle.DGetAlias;
import net.sf.portecle.FPortecle;
import net.sf.portecle.gui.SwingHelper;
import org.apache.commons.validator.routines.EmailValidator;
import uk.ngs.ca.certificate.OnlineCertRenewRequest;
import uk.ngs.ca.certificate.client.RevokeRequest;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;
import uk.ngs.ca.certificate.management.KeyStoreEntryWrapper;
import uk.ngs.ca.common.CAKeyPair;
import uk.ngs.ca.common.Pair;
import uk.ngs.certwizard.gui.GeneralMessageDialog;
//import uk.ngs.certwizard.gui.WaitDialog;

/**
 * Helper class for performing certificate renewals and revocations. The methods
 * invoked by this class present GUI components during their processing.
 *
 * @author David Meredith
 */
public class CertificateRenewRevokeGuiHelper {

    private ClientKeyStoreCaServiceWrapper caKeyStoreModel;
    private Component parentComponent;
    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);

    public CertificateRenewRevokeGuiHelper(Component parentCompoent, ClientKeyStoreCaServiceWrapper caKeyStoreModel) {
        this.parentComponent = parentCompoent;
        this.caKeyStoreModel = caKeyStoreModel;
    }

    /**
     * Lead the user through the revocation process for the given keyStore
     * entry. The method generates GUI components during its processing. The
     * method does not make any changes to the application's keyStore file.
     *
     * @param selectedKSEW
     * @return true if revoked, otherwise false.
     */
    public boolean doRevoke(KeyStoreEntryWrapper selectedKSEW) throws KeyStoreException, IOException, CertificateException {
        // First MUST refresh the online status of the selected keyStoreEntryWrapper
        // to guard against TOCTAU attacks and stale data (when was the online status last fetched). 
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            if (caKeyStoreModel.onlineUpdateKeyStoreEntry(selectedKSEW)) 
                caKeyStoreModel.getClientKeyStore().reStore();
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
        
        if (selectedKSEW == null
                || !KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                || selectedKSEW.getServerCertificateCSRInfo() == null
                || !"VALID".equals(selectedKSEW.getServerCertificateCSRInfo().getStatus())) {
            
            JOptionPane.showMessageDialog(parentComponent, "Only VALID certificates known by the UK CA can be revoked",
                    "Suitable certificate not selected", JOptionPane.WARNING_MESSAGE);
            return false; 
            
        } 
  
        if (JOptionPane.showConfirmDialog(parentComponent, 
                "Are you sure you want to revoke the selected certificate?\n\n"
                    + "Alias: ["+ selectedKSEW.getAlias()+"]\n"
                    + "DN: ["+ selectedKSEW.getX500PrincipalName()+"]\n"
                    + "Email: ["+selectedKSEW.getServerCertificateCSRInfo().getUserEmail()+"]", 
                "Renew Certificate", JOptionPane.YES_NO_OPTION) 
                != JOptionPane.YES_OPTION) {
            return false; 
        }
        
        
        String reason = this.getNewRevocationReasonHelper(""); 
        if(reason == null) return false; 
        //if(true) return false; 
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));

            final long cert_id = new Long(selectedKSEW.getServerCertificateCSRInfo().getId()).longValue();
            RevokeRequest revokeRequest = new RevokeRequest(
                    this.caKeyStoreModel.getClientKeyStore().getPrivateKey(selectedKSEW.getAlias()),
                    cert_id, reason);
            // do the revokation with the CA and block (note, this has 
            // no interaction with the keystore) 
            final boolean revoked = revokeRequest.doPosts();

            // Just reload the selected entry rather than refreshing all   
            if (caKeyStoreModel.onlineUpdateKeyStoreEntry(selectedKSEW)) {
                // Don't need to reStore (no online state is saved to file)
            }

            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));

            if (revoked) {
                JOptionPane.showMessageDialog(parentComponent, revokeRequest.getMessage(), "Certificate revoked", JOptionPane.INFORMATION_MESSAGE);
                return true;
            } else {
                return false;
            }
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }              
    }
    
    

    /**
     * Lead the user through the renewal process for the given keyStore entry.
     * The method generates GUI components during its processing. The method
     * creates and persists a new CSR certificate in the application's keyStore
     * file.
     *
     * @param selectedKSEW
     * @return the keyStore alias of the newly added renewal CSR or null if
     * cancelled or not added for whatever reason.
     */
    public String doRenew(KeyStoreEntryWrapper selectedKSEW) 
            throws KeyStoreException, IOException, CertificateException, NoSuchProviderException, SecurityException, SignatureException, InvalidKeyException {
        // First MUST refresh the online status of the selected keyStoreEntryWrapper
        // to guard against TOCTAU attacks and stale data (when was the online status last fetched). 
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            if (caKeyStoreModel.onlineUpdateKeyStoreEntry(selectedKSEW)) 
                caKeyStoreModel.getClientKeyStore().reStore();
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
        
        // Now test that the selected keyStoreEntryWrapper is eligible for renewal. 
        if (selectedKSEW == null
                || !KeyStoreEntryWrapper.KEYSTORE_ENTRY_TYPE.KEY_PAIR_ENTRY.equals(selectedKSEW.getEntryType())
                || selectedKSEW.getServerCertificateCSRInfo() == null
                || !"VALID".equals(((KeyStoreEntryWrapper) selectedKSEW).getServerCertificateCSRInfo().getStatus())
                || this.caKeyStoreModel.getClientKeyStore().getX509Certificate(selectedKSEW.getAlias()) == null ) {
            // Can only renew key_pairs types issued by our CA    
            JOptionPane.showMessageDialog(parentComponent, "Only VALID certificates known by the UK CA can be renewed",
                    "Suitable certificate not selected", JOptionPane.WARNING_MESSAGE);
            return null; 
        }

//        if (selectedKSEW.getX500PrincipalName().contains(".")) {
//            JOptionPane.showMessageDialog(parentCompoent, "Host cert renewals not yet supported. Coming very soon !",
//                    "Host cert renewals not yet supported", JOptionPane.WARNING_MESSAGE);
//            return null;
//        }

        if (JOptionPane.showConfirmDialog(parentComponent, 
                "Are you sure you want to renew the selected certificate?\n\n"
                    + "Alias: ["+ selectedKSEW.getAlias()+"]\n"
                    + "DN: ["+ selectedKSEW.getX500PrincipalName()+"]\n"
                    + "Email: ["+selectedKSEW.getServerCertificateCSRInfo().getUserEmail()+"]", 
                "Renew Certificate", JOptionPane.YES_NO_OPTION) 
                != JOptionPane.YES_OPTION) {
            return null; 
        }

        // Ask user for a new alias for the renewal (provide suitable suggestion)
        JOptionPane.showMessageDialog(parentComponent, "You will now be prompted to enter a new unique alias\n"
                + "for your certificate to be renewed.", "Certificate Renewal", JOptionPane.INFORMATION_MESSAGE);
        String newCsrRenewalAlias = selectedKSEW.getAlias();
        newCsrRenewalAlias = getNewEntryAliasHelper(newCsrRenewalAlias+"_renew", "FPortecle.KeyPairEntryAlias.Title", false);
        if (newCsrRenewalAlias == null) {
            return null; //user hit cancel
        }

        // Get and assert email. 
        // There are instances where we have no email address recorded against 
        // a host certificate in the CA db (this is due to unrelated CA issues). 
        // Must code defensively to ensure that an email is always provided. 
        // We also want to provide the opportunity to change the email on renew. 
        String email = selectedKSEW.getServerCertificateCSRInfo().getUserEmail();
        if (!EmailValidator.getInstance().isValid(email)) {
            email = this.getNewEmailHelper(email); 
        } else {
            // TODO The email currently recorded against this certificate is ... 
            // Do you want to update the email? 
            //email = this.getNewEmailHelper(email); 
        }
        if(email == null){
            return null; // user hit cancel 
        }

        //if(true) return null; 
        try {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            // Get the cert to be renewed (and its private key) and validate
            X509Certificate toRenewCert = this.caKeyStoreModel.getClientKeyStore().getX509Certificate(selectedKSEW.getAlias());
            PrivateKey toRenewPrivateKey = this.caKeyStoreModel.getClientKeyStore().getPrivateKey(toRenewCert.getPublicKey());
            try {
                // check validity now to prevent TOCTOU issues 
                toRenewCert.checkValidity();
            } catch (CertificateExpiredException ex) {
                parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
                JOptionPane.showMessageDialog(parentComponent, "Renewal Certificate has expired", "Invalid Certificate", JOptionPane.ERROR_MESSAGE);
                return null;
            } catch (CertificateNotYetValidException ex) {
                parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
                JOptionPane.showMessageDialog(parentComponent, "Renewal Certificate is not yet valid", "Invalid Certificate", JOptionPane.ERROR_MESSAGE);
                return null;
            }
            //if(true){
            //    String dnname = toRenewCert.getSubjectDN().getName();
            //    System.out.println("dnname: "+dnname);
            //    return null; 
            //}
            // Create a new key pair for the PKCS#10 renewal request and for the 
            // new self signed cert that is stored in the keyStore. 
            KeyPair csrKeyPair = CAKeyPair.getNewKeyPair();
            // Submit the renewal
            OnlineCertRenewRequest renewal = new OnlineCertRenewRequest(toRenewCert, toRenewPrivateKey, csrKeyPair, email);
            Pair<Boolean, String> result = renewal.doRenewal();

            // If submitted ok, save a new self-signed cert in the keyStore 
            // created with the PKCS#10 key pair and ReStore. 
            if (result.first) {             
                X509Certificate cert = CAKeyPair.createSelfSignedCertificate(csrKeyPair, renewal.getOU(), renewal.getL(), renewal.getCN());
                X509Certificate[] certs = {cert};

                // reStore the keystore 
                caKeyStoreModel.getClientKeyStore().setKeyEntry(newCsrRenewalAlias, csrKeyPair.getPrivate(), caKeyStoreModel.getPassword(), certs);
                caKeyStoreModel.getClientKeyStore().reStore();
                
                // Add the new entry to the model map
                KeyStoreEntryWrapper newCsrEntry = caKeyStoreModel.createKSEntryWrapperInstanceFromEntry(newCsrRenewalAlias);
                caKeyStoreModel.getKeyStoreEntryMap().put(newCsrRenewalAlias, newCsrEntry);
                
                // Inform user of successful submission 
                parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
                JOptionPane.showMessageDialog(parentComponent, "The renewal request has been submitted", "Renewal request successful", JOptionPane.INFORMATION_MESSAGE);
                return newCsrRenewalAlias;
            } else {
                parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
                GeneralMessageDialog.showAndWait(this.parentComponent, "Server responded an error: " + result.second, "CSR Renew Error", JOptionPane.ERROR_MESSAGE);
                return null;
            }
        } finally {
            parentComponent.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
        }
    }

    /**
     * Gets a new entry alias from user, handling overwrite/unique alias issues. 
     * Based on Portecle.
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
            boolean selectAlias) throws KeyStoreException {

        // Get the alias for the new entry
        DGetAlias dGetAlias =
                new DGetAlias(null, RB.getString(dialogTitleKey), sAlias.toLowerCase(), selectAlias);
        dGetAlias.setLocationRelativeTo(parentComponent);
        SwingHelper.showAndWait(dGetAlias);

        sAlias = dGetAlias.getAlias();
        if (sAlias == null) {
            return null;
        }

        if (this.caKeyStoreModel.getClientKeyStore().containsAlias(sAlias)) {
            JOptionPane.showMessageDialog(
                    parentComponent,
                    MessageFormat.format("The keystore already contains an entry with the alias " + sAlias + "\n"
                    + "Please enter a unique alias", sAlias),
                    RB.getString("FPortecle.RenameEntry.Title"), JOptionPane.ERROR_MESSAGE);
            // recurse  
            return getNewEntryAliasHelper(sAlias, dialogTitleKey, selectAlias);
        } else {
            return sAlias;
        }
    }
    
    /**
     * Gets a new valid email address or null if user cancels. 
     * @param sEmail
     * @return valid email or null if cancelled. 
     */
    private String getNewEmailHelper(String sEmail) {
        if (sEmail == null) sEmail = "";
        sEmail = JOptionPane.showInputDialog(parentComponent, "Enter Email:", sEmail);
        if (sEmail == null) return null;

        if (!EmailValidator.getInstance().isValid(sEmail)) {
            JOptionPane.showMessageDialog(parentComponent,
                    "Invalid Email - Please enter a valid email value",
                    "Invalid Email", JOptionPane.ERROR_MESSAGE);
            // recurse  
            return getNewEmailHelper(sEmail);
        } else {
            return sEmail;
        }
    }
    
    /**
     * Gets a new reason for revocation or null if user cancels. 
     * @param sReason
     * @return reason or null if cancelled. 
     */
    private String getNewRevocationReasonHelper(String sReason) {
        if (sReason == null) sReason = "";
        sReason = JOptionPane.showInputDialog(parentComponent, "Reason to Revoke:", sReason);
        if (sReason == null) return null;

        if (sReason.trim().length() < 5) {
            JOptionPane.showMessageDialog(parentComponent,
                    "Invalid Revocation Reason - Please enter a reason for revocation (min 5 chars)",
                    "Invalid Revocation", JOptionPane.ERROR_MESSAGE);
            // recurse  
            return getNewRevocationReasonHelper(sReason);
        } else {
            return sReason;
        }
    }
}
