/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate;

import java.io.File;
import java.io.FileInputStream;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Observable;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.Key;

import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.x500.X500Principal;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.common.ClientCertKeyStore;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * This class imports certificate in the local disk and update the configure xml file by calling updateXML class.
 * @author xw75
 */
public class ImportCertificate extends Observable {

    private KeyStore importKeyStore;
    private String Message = null;
    private String certFile;
    private char[] keyStorePassphrase;
    private char[] fileProtectionPassphrase;
    private String Alias = null;

    public ImportCertificate() {
    }

    /**
     * Adds up a Certificate File
     * @param certFile certificate file path string
     */
    public void addCertificateFile(String certFile) {
        this.certFile = certFile;
    }

    /**
     * Addsa up a Certificate File
     * @param file certificate file
     */
    public void addCertificateFile(File file) {
        this.certFile = file.toString();
    }

    /**
     * Adds up a KeyStore passphrase
     * @param keyStorePassphrase key store passphrase
     */
    public void addKeyStorePassphrase(char[] keyStorePassphrase) {
        this.keyStorePassphrase = keyStorePassphrase;
    }

    /**
     * Adds up imported file protection passphrase
     * @param fileProtectionPassphrase imported file protection passphrase
     */
    public void addFileProtectionPassphrase(char[] fileProtectionPassphrase) {
        this.fileProtectionPassphrase = fileProtectionPassphrase;
    }

    /**
     * Constructors importcertificate
     * @param certFile certificate file
     * @param keyStorePassphrase keystore passphrase
     * @param fileProtectionPassphrase imported file protection passphrase
     */
    public ImportCertificate(String certFile, char[] keyStorePassphrase, char[] fileProtectionPassphrase) {
        this.certFile = certFile;
        this.keyStorePassphrase = keyStorePassphrase;
        this.fileProtectionPassphrase = fileProtectionPassphrase;
    }

    /**
     * Constructors importcertificate
     * @param file certificate file
     * @param keyStorePassphrase keystore passphrase
     * @param fileProtectionPassphrase imported file protection passphrase
     */
    public ImportCertificate(File file, char[] keyStorePassphrase, char[] fileProtectionPassphrase) {
        this.certFile = file.toString();
        this.keyStorePassphrase = keyStorePassphrase;
        this.fileProtectionPassphrase = fileProtectionPassphrase;
    }

    /**
     * Checks if importing to keystore successful
     * @return true if successful, otherwise false
     */
    public boolean importToKeyStore( JFrame frame ) {
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
                _cert = this.importKeyStore.getCertificate(selectedAlias);
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

                ClientKeyStore clientKeyStore = new ClientKeyStore(this.keyStorePassphrase);
                String _dn = x509_cert.getSubjectDN().getName();
                String _value = SysProperty.getValue("ngsca.cert.o");

                int _index = _dn.indexOf(_value);

                                  //find out if the e-mail extension exists, and hence prevent host cert from getting imported
                    String dn = x509_cert.getSubjectDN().getName();
                    System.out.println("====================VALUE IS HERE ========" + dn + "=======================");


                    ///ADDED: CHECK FOR HOST CERTIFICATES AS WELL AS NON E-SCIENCE CERTIFICATES

                if ((_index == -1) || dn.contains(".")) {
                            //this message will display the certificate issued by UK e-Science CA cannot be supported.
                    String _message = SysProperty.getValue("ngsca.cert.limit");
                    _message = _message + "\nYou may have tried to import a certificate which is not issued by e-Science CA, or \n"
                            + "you may have tried to import a host certificate, which is not yet supported by this \n"
                            + "version of Certificate Wizard Management." + "\nYour certificate DN is " + _dn + "\nPlease select a UK e-Science "
                            + "personal certificate to import.";
                    this.Message = _message;
                    JOptionPane.showMessageDialog(frame, _message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                    isSuccess = false;
                } else {
                    PublicKey publicKey = x509_cert.getPublicKey();
                    ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey( publicKey );
                    if( ! resourcesPublicKey.isExist() ){
                        this.Message = "Your imported certificate looks valid, but there is no any record in the service database. Please contact with Helpdesk";
                        JOptionPane.showMessageDialog(frame, this.Message, "Certificate File Extraction", JOptionPane.ERROR_MESSAGE);
                        isSuccess = false;
                    }
                    
                    if (clientKeyStore.addNewKey(priv_key, x509_cert)) {
                        this.Alias = clientKeyStore.getAlias(x509_cert);

                        ClientCertKeyStore clientCertKeyStore = new ClientCertKeyStore(keyStorePassphrase);
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
    }
    
    /**
     * Notofies MainWindow any change.
     */
    public void notifyObserver() {
        setChanged();
        notifyObservers( this.Alias );
    }

    /**
     * Gets error message. It will be null if isExistToKeyStore is true.
     * @return
     */
    public String getMessage() {
        return this.Message;
    }

    private boolean isExistFile(String certFile) {
        File file = new File(certFile);
        return file.exists();
    }

}
