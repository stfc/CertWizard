/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import uk.ngs.ca.common.CAKeyPair;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * A thread safe singleton that wraps the managed <tt>'$HOME/.ca/cakeystore.pkcs12'</tt> KeyStore file.
 * <p>
 * It provides thread safe methods for adding/creating/deleting entries from the managed keyStore file. 
 * Access to the managed keyStore object is guarded by an instance of <code>this</code>. 
 * <p>
 * Visibility of <code>getInstance()</code> is limited to package-protected 
 * so that retrieval can be managed by other higher level classes in this package
 * that control access to the managed keyStore. 
 * 
 * @todo DM: Lots, more refactoring is needed, exception swallowing to fix 
 * @author xw75 (Xiao Wang) 
 * @author David Meredith (refactoring - still lots to fix)
 */
public final class ClientKeyStore {
    
    private static final Logger myLogger = Logger.getLogger(ClientKeyStore.class);

    // keyStore is an in-mem object that represents shared mutable state and 
    // so access to its entries must by synchronized in order to;  
    // a) prevent one thread from modifying the state of the object when 
    // another thread is using it, and 
    // b) prevent dirty reads by different threads (visiblity) 
    // The keyStore is confined to this object, it is never leaked/published. 
    private volatile KeyStore keyStore; 
    private final String key_KeyStoreFilePath ;
    private char[] PASSPHRASE = null;
    private String errorMessage = null;

  
    private static ClientKeyStore clientKeyStore = null;

    /**
     * Get a shared singleton <code>ClientKeyStore</code> instance.
     * @param passphrase for the '$HOME/.ca/cakeystore.pkcs12' keystore file. 
     * @return
     * @throws IllegalStateException if there is problem creating or loading the KeyStore
     */
    static synchronized ClientKeyStore getClientkeyStore(char[] passphrase) {
        // Static factory method allows us to choose whether we return the same instance
        // or create a new instance (easy to remove the if statement below so that
        // each invocation of this method will create/return a new keyStore
        // which replicates the previous public constructor).
        //
        // Check if keyStore has already been created succesfully,
        // (a composite action, i.e. check if null then act, but this is ok
        // provided this method is synchronized). Lets create the keystore only
        // if it has not been created yet or if the password has changed.
        if (clientKeyStore == null ){//|| (passphrase != null && !Arrays.equals(passphrase,clientKeyStore.PASSPHRASE))) {
            clientKeyStore = new ClientKeyStore(passphrase);
        }
        return clientKeyStore;
    }

    /**
     * Force non-instantiation with private constructor
     *
     * If $HOME/.ca/cakeystore.pkcs12 already exists, load it otherwise
     * create an empty pkcs12 file.
     * @param passphrase
     * @throws IllegalStateException if the KeyStore cannot be initialized.
     */
    private ClientKeyStore(char[] passphrase) {
        String caDir = System.getProperty("user.home") + File.separator + ".ca";
        this.PASSPHRASE = passphrase;
        this.key_KeyStoreFilePath = caDir + File.separator + SysProperty.getValue("ngsca.key.keystore.file");
        this.keyStore = this.getKeyStoreCopy();
    }
    

    /**
     * Change the keystore password
     * @param passphrase
     */
    public synchronized void reStorePassword(char[] passphrase) {
        this.PASSPHRASE = passphrase;
        this.reStore();
    }

    /**
     * Method that returns the directory to keystore
     * @return keystore directory as a String
     */
    public String returnKeystoreDir() {
        return this.key_KeyStoreFilePath;
    }

    /**
     * Create a new KeyStore instance by loading state from the 
     * '$HOME/.ca/cakeystore.pkcs12' file. If file does not exist, then 
     * load an empty keyStore. This newly created KeyStore object is a copy of 
     * the KeyStore that is managed in this class. 
     * 
     * @return A newly created KeyStore 
     */
    public KeyStore getKeyStoreCopy(){
        try {
            KeyStore ks = PKCS12KeyStoreUnlimited.getInstance();
            myLogger.debug("[ClientKeyStore] get keystore ...");
            FileInputStream fis = null;
            try {
                File f = new File(this.key_KeyStoreFilePath);
                if (f.exists() && f.length() != 0L) {
                    fis = new FileInputStream(key_KeyStoreFilePath);
                    ks.load(fis, this.PASSPHRASE);
                } else {
                    ks.load(null, null);
                    //reStore(); // create empty keystore
                }
                return ks; 
            } finally {
                try {
                    if (fis != null) {
                        fis.close();
                    }
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        } catch (Exception ke) {
            throw new IllegalStateException("[ClientKeyStore] failed to init keyStore handle: ", ke);
        }
    }


    public synchronized String getErrorMessage(){
        return this.errorMessage;
    }



    /**
     * Save the managed keyStore file to its default location and re-init
     * the managed key store <code>this.keyStore</code>.
     * @return
     */
    public synchronized boolean reStore() {
        FileOutputStream fos = null;
        try {
            File f = new File(this.key_KeyStoreFilePath);
            fos = new FileOutputStream(f);
            // store will overwrite the file if it already exists
            this.keyStore.store(fos, PASSPHRASE); 
            
            // We Need to re-load this.keyStore object from file - 
            // the act of persisting then reloading seems to re-organize the
            // keystore entries so that Trusted certs that exist in an
            // imported cert chain are also stored as standalone entries in the
            // keyStore file? 
            this.keyStore = this.getKeyStoreCopy();
            return true;
            
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
            return false;
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(ClientKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /*
     * DM: Methods below provide thread-safe read/write access to the keystore and 
     * its contained entries since all code paths that access the encapsulated 
     * keystore are guarded by this classes intrinsic lock. 
     * This is known as 'instance confinement' and the java 'monitor pattern' 
     */
   
    
    
    public synchronized boolean isExistPublicKey(PublicKey publicKey) {
        try {
            Enumeration aliases = this.keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
                    if(cert.getPublicKey().equals(publicKey)){
                        return true;
                    }
                }
            }  
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        }
        return false;
    }

    public synchronized boolean isExistPrivateKey(PrivateKey privateKey) {
        try {
            Enumeration aliases = this.keyStore.aliases();
             while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    if( this.keyStore.getKey(alias, PASSPHRASE).equals(privateKey) ){
                        return true;
                    }
                }
            }
        } catch (Exception ke) {
            ke.printStackTrace();
        }
        return false;
    }


    public synchronized PrivateKey getPrivateKey(PublicKey publicKey) {
        try {
            Enumeration aliases = this.keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
                    if(cert.getPublicKey().equals(publicKey)){
                        String _alias = this.keyStore.getCertificateAlias(cert);
                        return (PrivateKey) this.keyStore.getKey(_alias, PASSPHRASE);
                    }
                }
            }     
        } catch (Exception ke) {
            ke.printStackTrace();
        }
        return null;
    }

    /**
     * Create a new key pair in the keyStore file and save to file.
     * @param alias a suggested alias (can be null)
     * @return alias
     */
    public synchronized String createNewKeyPair(String alias, String ou, String l, String cn) {
        try {
            KeyPair keyPair = CAKeyPair.getNewKeyPair();
            // the self signed certificate has some hardwired values - why?
            X509Certificate cert = CAKeyPair.createSelfSignedCertificate(keyPair, ou, l, cn );
            X509Certificate[] certs = {cert};
            // Alias not valid so create a meaningless alias instead. 
            if(alias == null || alias.trim().length() == 0 || this.keyStore.containsAlias(alias)){
               alias = new Long(new Date().getTime()).toString();
            }
            this.keyStore.setKeyEntry(alias, keyPair.getPrivate(), PASSPHRASE, certs);
            reStore();
            return alias;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public synchronized String getAlias( X509Certificate cert ){
        try{
            return this.keyStore.getCertificateAlias(cert);
        }catch( Exception ep ){
            ep.printStackTrace();
            return null;
        }
    }


    public synchronized boolean addNewKey(PrivateKey privateKey, X509Certificate cert) {
        if ((privateKey == null) || (cert == null)) {
            return false;
        }
        PublicKey publicKey = cert.getPublicKey();
        if (isExistPublicKey(publicKey) && isExistPrivateKey(privateKey)) {
            return true;
        }
        X509Certificate[] chain = {cert}; //new X509Certificate[1];
        long _alias = new Date().getTime();
        String my_alias = new Long(_alias).toString();
        try {
            this.keyStore.setKeyEntry(my_alias, privateKey, PASSPHRASE, chain);
            reStore();
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            return false;
        }
    }

    public synchronized X509Certificate getX509Certificate(String alias) {
        try {
            X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
            return cert;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }
        
    public synchronized PublicKey getPublicKey(String alias) {
        try {
            X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
            return cert.getPublicKey();
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public synchronized PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) this.keyStore.getKey(alias, PASSPHRASE);
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }


    public synchronized boolean removeKey(PrivateKey privateKey) {
        boolean isSuccess = true;
        try {
            if (isExistPrivateKey(privateKey)) {
                Enumeration aliases = this.keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = (String) aliases.nextElement();
                    PrivateKey _privateKey = (PrivateKey) this.keyStore.getKey(alias, PASSPHRASE);
                    if (privateKey.equals(_privateKey)) {
                       this.keyStore.deleteEntry(alias); 
                    }
                }
                reStore();
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            isSuccess = false;
        } finally {
            return isSuccess;
        }
    }
    
    
    /**
     * @see java.security.KeyStore#deleteEntry(java.lang.String)  
     */
    public synchronized void deleteEntry(String alias) throws KeyStoreException {
        this.keyStore.deleteEntry(alias);
    }

    /**
     * @see java.security.KeyStore#isCertificateEntry(java.lang.String)  
     */
    public synchronized boolean isCertificateEntry(String alias) throws KeyStoreException {
        return this.keyStore.isCertificateEntry(alias);
    }

    /**
     * @see java.security.KeyStore#isKeyEntry(java.lang.String) 
     */
    public synchronized boolean isKeyEntry(String alias) throws KeyStoreException {
        return this.keyStore.isKeyEntry(alias);
    }
    
    /**
     * @see java.security.KeyStore#aliases() 
     */
    public synchronized Enumeration<String> aliases() throws KeyStoreException {
        return this.keyStore.aliases();
    }
    
    /**
     * @see java.security.KeyStore#getCertificate(java.lang.String) 
     */
    public synchronized java.security.cert.Certificate getCertificate(String alias) throws KeyStoreException {
        return this.keyStore.getCertificate(alias);
    }

    /**
     * @see java.security.KeyStore#getCertificateChain(java.lang.String) 
     */
    public synchronized java.security.cert.Certificate[] getCertificateChain(String alias) throws KeyStoreException {
        return this.keyStore.getCertificateChain(alias);
    }

    /**
     * @see java.security.KeyStore#getCreationDate(java.lang.String) 
     */
    public synchronized Date getCreationDate(String alias) throws KeyStoreException {
        return this.keyStore.getCreationDate(alias);
    }

    /**
     * @see java.security.KeyStore#getKey(java.lang.String, char[]) 
     */
    public synchronized Key getKey(String alias, char[] pass) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        return this.keyStore.getKey(alias, pass);
    }

    /**
     * @see java.security.KeyStore#setKeyEntry(java.lang.String, byte[], java.security.cert.Certificate[]) 
     */
    public synchronized void setKeyEntry(String alias, Key key, char[] password, java.security.cert.Certificate[] chain) throws KeyStoreException {
        this.keyStore.setKeyEntry(alias, key, password, chain);
    }

    /**
     * @see java.security.KeyStore#containsAlias(java.lang.String) 
     */
    public synchronized boolean containsAlias(String alias) throws KeyStoreException {
        return this.keyStore.containsAlias(alias);
    }

    /**
     * @see java.security.KeyStore#setCertificateEntry(java.lang.String, java.security.cert.Certificate) 
     */
    public synchronized void setCertificateEntry(String alias, java.security.cert.Certificate cert) throws KeyStoreException {
        this.keyStore.setCertificateEntry(alias, cert);
    }

}
