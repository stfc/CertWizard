/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.security.PublicKey;
import java.security.PrivateKey;

import java.security.KeyStore;
import java.security.NoSuchProviderException;
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
 * Read or create file $HOME/.ca/cakeystore.pkcs12 (create if it does not
 * already exist). This file holds CSR requests (it is populated after applying for a
 * cert when online) and VALID/expired cert/key entries that are recognised by our CA.
 * The class provides methods for adding/creating/deleting entries from this
 * keyStore file.
 * 
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
        //if (clientKeyStore == null || (passphrase != null && !Arrays.equals(passphrase,clientKeyStore.PASSPHRASE))) {
            clientKeyStore = new ClientKeyStore(passphrase);
        //}
        return clientKeyStore;
    }

    // force non-instantiability with private constructor
    private ClientKeyStore(char[] passphrase) {
        String caDir = System.getProperty("user.home") + File.separator + ".ca";
        this.PASSPHRASE = passphrase;
        this.key_KeyStoreFilePath = caDir + File.separator + SysProperty.getValue("ngsca.key.keystore.file");

        try {
            this.keyStore = PKCS12KeyStoreUnlimited.getInstance();
        } catch (KeyStoreException ke) {
            throw new IllegalStateException("[ClientKeyStore] failed to create a keyStore: ", ke);
        } catch (NoSuchProviderException ne) {
            throw new IllegalStateException("[ClientKeyStore] failed to create a keystore without suitable provider: ", ne);
        }
        // load this.keyStore from file if it exists.
        this.loadKeyStoreFileFromFile(passphrase);
    }

    /**
     * If $HOME/.ca/cakeystore.pkcs12 already exists, load it otherwise
     * create an empty pkcs12 file.
     * @param passphrase
     */
    private void loadKeyStoreFileFromFile(char[] passphrase)  {
        myLogger.debug("[ClientKeyStore] get keystore ...");
        FileInputStream fis = null;
        try {
            File f = new File(this.key_KeyStoreFilePath);
            if (f.exists() && f.length() != 0L) {
                fis = new FileInputStream(key_KeyStoreFilePath);
                this.keyStore.load(fis, passphrase);             
            } else {
                this.keyStore.load(null, null);
                reStore();
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
        } finally {
            try {if(fis != null) fis.close();} catch (IOException ex) {}
        }
    }


    public synchronized String getErrorMessage(){
        return this.errorMessage;
    }

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
     * create a new keypair in the keystore file and save to file.
     *
     * @return alias
     */
    public synchronized String createNewKeyPair() {
        try {
            KeyPair keyPair = CAKeyPair.getKeyPair();
            PrivateKey privKey = keyPair.getPrivate();
            X509Certificate cert = CAKeyPair.createSelfSignedCertificate(keyPair);
            X509Certificate[] certs = {cert};
            // meaningless alias.
            String _alias = new Long(new Date().getTime()).toString();
            this.keyStore.setKeyEntry(_alias, privKey, PASSPHRASE, certs);
            reStore();
            return _alias;
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



    private boolean reStore() {
        FileOutputStream fos = null;
        try {
            File f = new File(this.key_KeyStoreFilePath);
            fos = new FileOutputStream(f);
            this.keyStore.store(fos, PASSPHRASE);
            return true;
        } catch (Exception ep) {
            errorMessage = ep.getMessage();
            File file = new File(this.key_KeyStoreFilePath);
            if (file.exists()) {
                return file.delete();
            }
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
