/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.security.PublicKey;
import java.security.PrivateKey;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.util.Enumeration;
import java.util.Date;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.logging.Level;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import uk.ngs.ca.tools.property.SysProperty;

/**
 * A wrapper around the '$HOME/.ca/cakeystore.pkcs12' KeyStore file.
 * On class creation, a new PKCS12 key store file is created if it does not
 * already exist. Provides methods for adding/creating/deleting entries from
 * this keyStore file.
 * 
 * @author xw75
 */
public final class ClientKeyStore {
    
    private static final Logger myLogger = Logger.getLogger(ClientKeyStore.class);

    // keyStore represents shared mutable state and so must by synchronized.
    private KeyStore keyStore;
    private String key_KeyStoreFilePath = null;
    private char[] PASSPHRASE = null;
    private String errorMessage = null;

  
    private static ClientKeyStore clientKeyStore = null;

    /**
     * Get a shared singleton <code>ClientKeyStore</code> instance.
     * @param passphrase for the '$HOME/.ca/cakeystore.pkcs12' keystore file. If
     * a new passphrase is given that is different from  the previous,
     * a new instance is created and returned.
     * @return
     * @throws IllegalStateException if there is problem creating or loading the KeyStore
     */
    public static synchronized ClientKeyStore getClientkeyStore(char[] passphrase) {
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
        //return new ClientKeyStore(passphrase);
    }

    /**
     * Force non-instantiability with private constructor
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
        this.loadKeyStoreFromFile();

    }

    /**
     * Change the keystore password
     * @param passphrase
     */
    public void reStorePassword(char[] passphrase) {
        this.PASSPHRASE = passphrase;
        this.reStore();
    }


    /**
     * Load <code>this.keyStore</code> from file if it exists otherwise touch
     * the file.
     */
    private void loadKeyStoreFromFile(){
        try {
            this.keyStore = PKCS12KeyStoreUnlimited.getInstance();
            myLogger.debug("[ClientKeyStore] get keystore ...");
            FileInputStream fis = null;
            try {
                File f = new File(this.key_KeyStoreFilePath);
                if (f.exists() && f.length() != 0L) {
                    fis = new FileInputStream(key_KeyStoreFilePath);
                    this.keyStore.load(fis, this.PASSPHRASE);
                } else {
                    this.keyStore.load(null, null);
                    reStore(); // touch it
                }
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

   
    /**
     * @return a handle to the <code>KeyStore</code> object managed by this class
     */
    public KeyStore getKeyStore(){
        // hmm, releasing internal state here, not good but necessary without
        // massive amounts of re-coding.
        return this.keyStore; 
    }



    public String getErrorMessage(){
        return this.errorMessage;
    }

    public boolean isExistPublicKey(PublicKey publicKey) {
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

    public boolean isExistPrivateKey(PrivateKey privateKey) {
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


    public PrivateKey getPrivateKey(PublicKey publicKey) {
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
     * create a new keypair in the keystore file and save to file.
     * @param alias a suggested alias (can be null)
     * @return alias
     */
    public String createNewKeyPair(String alias, String ou, String l, String cn) {
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

    public String getAlias( X509Certificate cert ){
        try{
            return this.keyStore.getCertificateAlias(cert);
        }catch( Exception ep ){
            ep.printStackTrace();
            return null;
        }
    }


    public boolean addNewKey(PrivateKey privateKey, X509Certificate cert) {
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

    public PublicKey getPublicKey(String alias) {
        try {
            X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(alias);
            return cert.getPublicKey();
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) this.keyStore.getKey(alias, PASSPHRASE);
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }


    public boolean removeKey(PrivateKey privateKey) {
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
     * Save the managed keyStore file to its default location and re-init
     * <code>this.keyStore</code>.
     * @return
     */
    public boolean reStore() {
        //System.out.println("in reStore");
        FileOutputStream fos = null;
        try {
            File f = new File(this.key_KeyStoreFilePath);
            fos = new FileOutputStream(f);
            // presumabley, store will overwrite the file if it already exists
            this.keyStore.store(fos, PASSPHRASE);

            // Need to re-load this.keyStore pointer object from file because
            // the act of persisting then reloading seems to re-organize the
            // keystore entries so that Trusted certs that exist in an
            // imported cert chain are also stored as standalone entries in the
            // keyStore file.
            this.loadKeyStoreFromFile();

            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
            // not sure we want to explicitly delete the user's keyStore file
            // bit too dangerous.
            /*File file = new File(this.key_KeyStoreFilePath);
            if (file.exists()) {
                return file.delete();
            }*/
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


}
