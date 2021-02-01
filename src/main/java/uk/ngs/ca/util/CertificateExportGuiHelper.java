/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.util;

import java.awt.Component;
import java.awt.Window;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.ResourceBundle;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import net.sf.portecle.DExport;
import net.sf.portecle.FPortecle;
import net.sf.portecle.FileChooserFactory;
import net.sf.portecle.KeyStoreWrapper;
import net.sf.portecle.crypto.CryptoException;
import net.sf.portecle.crypto.KeyStoreType;
import net.sf.portecle.crypto.X509CertUtil;
import net.sf.portecle.gui.LastDir;
import net.sf.portecle.gui.SwingHelper;
import net.sf.portecle.gui.error.DThrowable;
import net.sf.portecle.gui.password.DGetNewPassword;
import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import uk.ngs.ca.certificate.management.ClientKeyStoreCaServiceWrapper;

/**
 * Helper class for assisting with exporting of certificates from the
 * applications managed keyStore. The methods invoked by this class present GUI
 * components during their processing.
 *
 * @author David Meredith
 */
public class CertificateExportGuiHelper {

    /**
     * The last directory accessed by the application
     */
    private final LastDir m_lastDir = new LastDir();
    //private char[] PASSPHRASE;
    /**
     * Portecle Resource bundle base name
     */
    private static final String RB_BASENAME = FPortecle.class.getPackage().getName() + "/resources";
    /**
     * Portecle Resource bundle
     */
    public static final ResourceBundle RB = ResourceBundle.getBundle(RB_BASENAME);
    private ClientKeyStoreCaServiceWrapper caKeyStoreModel = null;
    private Component parentCompoent;

    public CertificateExportGuiHelper(Component parentCompoent, ClientKeyStoreCaServiceWrapper caKeyStoreModel) throws KeyStoreException, IOException, CertificateException {
        this.parentCompoent = parentCompoent;
        this.caKeyStoreModel = caKeyStoreModel;
    }

    public static Window findWindow(Component c) {
        if (c == null) {
            return JOptionPane.getRootFrame();
        } else if (c instanceof Window) {
            return (Window) c;
        } else {
            return findWindow(c.getParent());
        }
    }

    /**
     * Let the user export the selected entry. Based on Portecle.
     *
     * @see FPortecle#exportSelectedEntry()
     *
     * @return True if the export is successful, false otherwise
     */
    public boolean doExportAction(String sAlias) {

        try {
            // Display the Generate Key Pair dialog to get the key
            // pair generation parameters from the user. We create
            // a new KeyStoreWrapper because this is required by
            // the DExport constructor.
            // Pass a snapshot of the keystore when exporting. 

            DExport dExport = new DExport(findWindow(parentCompoent),
                    new KeyStoreWrapper(this.caKeyStoreModel.getClientKeyStore().getKeyStoreCopy()), sAlias);
            dExport.setLocationRelativeTo(this.parentCompoent);
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
                JOptionPane.showMessageDialog(this.parentCompoent, "Your certificate has been exported successfully.\n"
                        + "Please ensure that you make a backup of this\n"
                        + "certificate somewhere away from your computer.\n"
                        + "E.g. USB dongle, CD/DVD\n",
                        RB.getString("FPortecle.Export.Title"), JOptionPane.INFORMATION_MESSAGE);
            }
        } catch (Exception ex) {
            DThrowable.showAndWait(null, "Problem Exporting Certificate", ex);
            return false;
        }
        return true;
    }

    ////////////////////////////////////////////////////////////////////////////
    // The next set of methods starting with export and choose are soley used
    // for exporting keystore entries to different file formats. They are
    // largely copied verbatum from Portecle. TODO: They could be refactored into
    // a helper class to make this class smaller.
    ////////////////////////////////////////////////////////////////////////////
    /**
     * Export the private key and certificates of the keystore entry to a PKCS
     * #12 keystore file. Based on Portecle.
     *
     * @see FPortecle#exportPrivKeyCertChainPKCS12(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportPrivKeyCertChainPKCS12(String sEntryAlias) {

        //KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStoreCopy();
        //char[] cPassword = this.PASSPHRASE;
        File fExportFile = null;
        FileOutputStream fos = null;
        try {

            // First get a new password for the PKCS #12 keystore
            DGetNewPassword dGetNewPassword
                    = new DGetNewPassword(findWindow(parentCompoent), RB.getString("FPortecle.Pkcs12Password.Title"));
            dGetNewPassword.setLocationRelativeTo(parentCompoent);
            SwingHelper.showAndWait(dGetNewPassword);
            char[] newPKCS12Password = dGetNewPassword.getPassword();
            if (newPKCS12Password == null) {
                return false;
            }

            // Get the private key and certificate chain from the entry
            Key privKey = this.caKeyStoreModel.getClientKeyStore().getKey(sEntryAlias, this.caKeyStoreModel.getPassword());
            Certificate[] certs = this.caKeyStoreModel.getClientKeyStore().getCertificateChain(sEntryAlias);

            // Create a new PKCS12 keystore
            // DM: Important note. We Cannot use portecle's 'KeyStoreUtil.createKeyStore' 
            // method because we have modified it to return a different KeyStore provider 
            // impl; originally portecle created a keystore using Bouncy Castle 
            // (i.e. 'keystore = KeyStore.getInstance(keyStoreType.name(), "BC");' ) 
            // and then we modified it to use 'keyStore = PKCS12KeyStoreUnlimited.getInstance();'. 
            // However, as of 09/11/2012 both of these crypto providers create 
            // pkcs12 keystores that gives firefox problems. Therefore, we need 
            // to fall back on using the default Java provider as below. 
            // Creating and ENCRYTPING keystores with passwords longer than 7chars does 
            // not seem to conflict with Java's limited strength jurisdiction policy file
            // limitations (which may apply to DECRYPTION only) - so we are ok 
            // to use it for creating new keystores. 
            // http://www.ngs.ac.uk/tools/jcepolicyfiles 
            //KeyStore newPkcs12 = KeyStoreUtil.createKeyStore(KeyStoreType.PKCS12);
            KeyStore newPkcs12 = KeyStore.getInstance(KeyStoreType.PKCS12.name());
            newPkcs12.load(null, null);

            // Place the private key and certificate chain into the PKCS #12 keystore under the same alias as
            // it has in the loaded keystore
            newPkcs12.setKeyEntry(sEntryAlias, privKey, newPKCS12Password, certs);

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

            // Store the keystore to disk. DM: note, cannot use portecle's 
            // keyStoreUtil.savekeyStore because it re-loads it afterwards using
            // the BC provider (See issues described above). 
            //KeyStoreUtil.saveKeyStore(newPkcs12, fExportFile, cPKCS12Password);
            fos = new FileOutputStream(fExportFile);
            newPkcs12.store(fos, newPKCS12Password);

            m_lastDir.updateLastDir(fExportFile);
            return true;

        } catch (FileNotFoundException ex) {
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(parentCompoent, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
            return false;
        } catch (IOException ex) {
            DThrowable.showAndWait(null, "Problem exporting private key", ex);
            return false;
        } catch (GeneralSecurityException ex) {
            DThrowable.showAndWait(null, "Problem exporting private key", ex);
            return false;
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (Exception ex) {
                DThrowable.showAndWait(null, "Problem exporting private key", ex);
                return false;
            }
        }
    }

    /**
     * Export the private key and certificates of the keystore entry to a PEM
     * encoded "OpenSSL" format bundle. Based on Portecle.
     *
     * @see FPortecle#exportPrivKeyCertChainPEM(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportPrivKeyCertChainPEM(String sEntryAlias) {

        //KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStoreCopy();
        //char[] cPassword = this.PASSPHRASE;
        File fExportFile = null;
        JcaPEMWriter pw = null;

        try {
            // Get the private key and certificate chain from the entry
            Key privKey = this.caKeyStoreModel.getClientKeyStore().getKey(sEntryAlias, this.caKeyStoreModel.getPassword());
            Certificate[] certs = this.caKeyStoreModel.getClientKeyStore().getCertificateChain(sEntryAlias);

            // Get a new password to encrypt the private key with
            DGetNewPassword dGetNewPassword
                    = new DGetNewPassword(null, RB.getString("FPortecle.PrivateKeyExportPassword.Title"));
            dGetNewPassword.setLocationByPlatform(true);
            dGetNewPassword.setLocationRelativeTo(this.parentCompoent);
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
            pw = new JcaPEMWriter(new FileWriter(fExportFile));

            if (password.length == 0) {
                pw.writeObject(privKey);
            } else {
                // TODO: make algorithm configurable/ask user?
                String algorithm = "DES-EDE3-CBC";
                SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
                PEMEncryptor encryptor = new JcePEMEncryptorBuilder("DES-EDE3-CBC").setSecureRandom(rand).build(password);
                pw.writeObject(privKey, encryptor);
            }

            for (Certificate cert : certs) {
                pw.writeObject(cert);
            }
            pw.flush();

            m_lastDir.updateLastDir(fExportFile);

            return true;
        } catch (FileNotFoundException ex) {
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(parentCompoent, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
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
     *
     * @see FPortecle#exportAllCertsPkcs7(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportAllCertsPkcs7(String sEntryAlias) {
        // Get the certificates
        X509Certificate[] certChain;
        try {
            certChain = X509CertUtil.convertCertificates(this.caKeyStoreModel.getClientKeyStore().getCertificateChain(sEntryAlias));
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
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
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
     *
     * @see FPortecle#exportHeadCertOnlyPkcs7(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPkcs7(String sEntryAlias) {
        X509Certificate cert;
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
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
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
     *
     * @see FPortecle#exportHeadCertOnlyPem(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPem(String sEntryAlias) {
        X509Certificate cert;
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

        JcaPEMWriter pw = null;
        try {
            pw = new JcaPEMWriter(new FileWriter(fExportFile));
            pw.writeObject(cert);
            m_lastDir.updateLastDir(fExportFile);
            return true;
        } catch (FileNotFoundException ex) {
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(parentCompoent, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
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
     *
     * @see FPortecle#exportHeadCertOnlyDER(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyDER(String sEntryAlias) {
        X509Certificate cert;
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
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(parentCompoent, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
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
     *
     * @see FPortecle#exportHeadCertOnlyPkiPath(java.lang.String)
     *
     * @param sEntryAlias Entry alias
     * @return True if the export is successful, false otherwise
     */
    private boolean exportHeadCertOnlyPkiPath(String sEntryAlias) {
        X509Certificate cert;
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
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoWriteFile.message"), fExportFile.getName());
            JOptionPane.showMessageDialog(parentCompoent, sMessage, "File not found", JOptionPane.WARNING_MESSAGE);
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
     * Let the user choose a PKCS #12 file to export to. Based on Portecle.
     *
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
        int iRtnValue = chooser.showDialog(parentCompoent, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a PKCS #7 file to export to. Based on Portecle.
     *
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
        int iRtnValue = chooser.showDialog(parentCompoent, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a PEM file to export to. Based on Portecle.
     *
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
        int iRtnValue = chooser.showDialog(parentCompoent, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a PkiPath file to export to. Based on Portecle.
     *
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
        int iRtnValue = chooser.showDialog(parentCompoent, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * Let the user choose a certificate file to export to. Based on Portecle.
     *
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
        int iRtnValue = chooser.showDialog(parentCompoent, RB.getString("FPortecle.Export.button"));
        if (iRtnValue == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }
        return null;
    }

    /**
     * File overwrite confirmation dialog. Based on Portecle.
     *
     * @see FPortecle#confirmOverwrite(java.io.File, java.lang.String)
     *
     * @param file the file possibly being overwritten
     * @param title window title
     * @return true if the write operation should continue
     */
    private boolean confirmOverwrite(File file, String title) {
        if (file.isFile()) {
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.OverWriteFile.message"), file.getName());
            int iSelected = JOptionPane.showConfirmDialog(parentCompoent, sMessage, title, JOptionPane.YES_NO_OPTION);
            return iSelected == JOptionPane.YES_OPTION;
        }
        return true;
    }

    /**
     * Get the keystore entry's head certificate. Based on Portecle.
     *
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
            //KeyStore keyStore = this.keyStoreCaWrapper.getClientKeyStore().getKeyStoreCopy();
            // Get the entry's head certificate
            X509Certificate cert;
            if (this.caKeyStoreModel.getClientKeyStore().isKeyEntry(sEntryAlias)) {
                cert
                        = X509CertUtil.orderX509CertChain(X509CertUtil.convertCertificates(this.caKeyStoreModel.getClientKeyStore().getCertificateChain(sEntryAlias)))[0];
            } else {
                cert = X509CertUtil.convertCertificate(this.caKeyStoreModel.getClientKeyStore().getCertificate(sEntryAlias));
            }
            return cert;
        } catch (KeyStoreException ex) {
            String sMessage
                    = MessageFormat.format(RB.getString("FPortecle.NoAccessEntry.message"), sEntryAlias);
            throw new CryptoException(sMessage, ex);
        }
    }
    // Variables declaration - do not modify
}
