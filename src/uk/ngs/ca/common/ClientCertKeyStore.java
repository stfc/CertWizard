/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import java.security.PublicKey;
import java.security.PrivateKey;

import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import java.util.Enumeration;
import java.util.Date;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;

import java.security.KeyStoreException;
import java.util.logging.Level;

import org.apache.log4j.Logger;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import java.util.Properties;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;

import uk.ngs.ca.tools.property.SysProperty;

/**
 * Read or create file $HOME/.ca/cacertkeystore.pkcs12 (create if it does not
 * already exist). This file is intended to hold....what.
 * The cacertkeystore contains a collection of the valid and expired certificates only.
 *
 * @author xw75
 */
public final class ClientCertKeyStore {

    private char[] PASSPHRASE = null;
    private static final Logger myLogger = Logger.getLogger(ClientCertKeyStore.class);
    // certKeyStore represents shared mutable state, so its access must be thread safe.
    private KeyStore certKeyStore = null;
    private static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private Properties properties = new Properties();
    private final String FILEPATH = ".ca";
    private String keyStoreFileAbsPath = null;
    private String errorMessage = null;

    private static ClientCertKeyStore clientCertKeyStore = null;

    public static synchronized ClientCertKeyStore getClientCertKeyStore(char[] passphrase) {
        // Static factory method allows us to choose whether we return the same instance
        // or create a new instance (easy to remove the if check below so that
        // each invocation of this method will create/return a new certKeyStore
        // which replicates the previous public constructor.
        //
        // (a composite action, i.e. check if null then act, but this is ok
        // provided this method is synchronized). Lets create the keystore only
        // if it has not been created yet or if the password has changed.
        //if (clientCertKeyStore == null || (passphrase != null && !Arrays.equals(passphrase,clientCertKeyStore.PASSPHRASE))) {
            clientCertKeyStore = new ClientCertKeyStore(passphrase);
        //}
        return clientCertKeyStore;
    }

    private ClientCertKeyStore(char[] passphrase) {
        //System.out.println("ClientCertKeyStore constructor");
        PASSPHRASE = passphrase;
        init();
        setupCertKeyStoreFile(passphrase);
    }

    /*public ClientCertKeyStore(char[] passphrase) {
        PASSPHRASE = passphrase;
        init();
        setupCertKeyStoreFile(passphrase);
    }*/

    /*public KeyStore getCertKeyStore() {
        return certKeyStore;
    }*/

    private void init() {
        myLogger.debug("[ClientKeyStore] init...");
        InputStream input = null;
        try {
            this.certKeyStore = PKCS12KeyStoreUnlimited.getInstance();
            input = SysProperty.class.getResourceAsStream(PROP_FILE);
            this.properties.load(input);
            
        } catch (IOException ioe) {
            ioe.printStackTrace();
            myLogger.error("[ClientKeyStore] Property file is failed to load.");
            errorMessage = ioe.getMessage();
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[ClientKeyStore] failed to create a keyStore: " + ke.getMessage());
            errorMessage = ke.getMessage();
        } catch (NoSuchProviderException ne) {
            ne.printStackTrace();
            myLogger.error("[ClientKeyStore] failed to create a keystore without suitable provider: " + ne.getMessage());
            errorMessage = ne.getMessage();
        } finally {
            try {
                if(input !=null) input.close();
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(ClientCertKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    /**
     * If $HOME/.ca/cacertkeystore.pkcs12 already exists, load it otherwise
     * create an empty pkcs12 file.
     *
     * @param passphrase
     */
    private void setupCertKeyStoreFile(char[] passphrase) {
        myLogger.debug("[ClientCertKeyStore] get keystore ...");
        String key = "ngsca.cert.keystore.file";
        String value = properties.getProperty(key);
        if (value == null) {
            myLogger.error("[ClientCertKeyStore] could not find out the value of " + key + " in your property file.");
        }
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + FILEPATH;
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
        }
        homePath = homePath + System.getProperty("file.separator") + value;
        this.keyStoreFileAbsPath = homePath;
        FileInputStream fis = null;
        FileOutputStream fos = null;
        try {
            // if certkeystore already exists, load it
            if (new File(this.keyStoreFileAbsPath).exists()) {
                fis = new FileInputStream(this.keyStoreFileAbsPath);
                this.certKeyStore.load(fis, passphrase);
            } else {
                // otherwise create an empty keystore protected by passphrase
                this.certKeyStore.load(null, null);
                File f = new File(this.keyStoreFileAbsPath);
                fos = new FileOutputStream(f);
                this.certKeyStore.store(fos, PASSPHRASE);
                //System.out.println("this should print: creating: "+this.keyStoreFileAbsPath); // this should print: creating: C:\Documents and Settings\djm76\.ca\cacertkeystore.pkcs12
                //if(true)System.exit(0);
             }
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
        } finally {
            try {if(fis !=null)fis.close();} catch (IOException ex) {}
            try {if(fos !=null)fos.close();} catch (IOException ex) {}
        }
    }

    public synchronized String getErrorMessage(){
        return errorMessage;
    }

    public synchronized String getAlias( PublicKey publicKey ){
        String alias = null;
        try {
            Enumeration aliases = this.certKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String _alias = (String) aliases.nextElement();
                if (this.certKeyStore.isKeyEntry(_alias)) {
                    X509Certificate cert = (X509Certificate)this.certKeyStore.getCertificate(_alias);
                    PublicKey _publicKey = cert.getPublicKey();
                    if( _publicKey.equals(publicKey)){
                        alias = _alias;
                    }
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return alias;
        }

    }

    public synchronized boolean removeEntry( String alias ){
        try{
          certKeyStore.deleteEntry(alias);
          reStore();
          return true;
        }catch( KeyStoreException ke ){
            ke.printStackTrace();
            return false;
        }
    }

    public synchronized boolean addNewKey(PrivateKey privateKey, X509Certificate cert) {
        if (!isExistKey(privateKey, cert)) {
            X509Certificate[] chain = new X509Certificate[1];
            chain[ 0] = cert;
            long _alias = new Date().getTime();
            String my_alias = new Long(_alias).toString();
            try {
                certKeyStore.setKeyEntry(my_alias, privateKey, PASSPHRASE, chain);
                reStore();
                return true;
            } catch (Exception ep) {
                ep.printStackTrace();
                return false;
            }
        } else {
            return true;
        }
    }

    private synchronized boolean reStore() {
        FileOutputStream fos = null;
        try {
            File f = new File(keyStoreFileAbsPath);
            fos = new FileOutputStream(f);
            certKeyStore.store(fos, PASSPHRASE);
            return true;
        } catch (FileNotFoundException fe) {
            fe.printStackTrace();
            myLogger.error("[ClientCertKeyStore] failed to get pkcs file: " + fe.getMessage());
            return false;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[ClientCertKeyStore] failed to get keystore file: " + ke.getMessage());
            return false;
        } catch (IOException ie) {
            ie.printStackTrace();
            myLogger.error("[ClientCertKeyStore] failed to access pkcs file: " + ie.getMessage());
            return false;
        } catch (NoSuchAlgorithmException ne) {
            ne.printStackTrace();
            myLogger.error("[ClientCertKeyStore] no such algorithm: " + ne.getMessage());
            return false;
        } catch (CertificateException ce) {
            ce.printStackTrace();
            myLogger.error("[ClientCertKeyStore] certificate error: " + ce.getMessage());
            return false;
        } finally {
            if(fos != null) try {fos.close();} catch (IOException ex) {}
        }

    }

    private synchronized boolean isExistKey(PrivateKey privateKey, X509Certificate cert) {
        boolean isExist = false;
        try {
            Enumeration aliases = certKeyStore.aliases();
            PublicKey publicKey = cert.getPublicKey();

            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (certKeyStore.isKeyEntry(alias)) {
                    X509Certificate _cert = (X509Certificate) certKeyStore.getCertificate(alias);
                    PrivateKey _privateKey = (PrivateKey) certKeyStore.getKey(alias, PASSPHRASE);
                    PublicKey _publicKey = _cert.getPublicKey();
                    if ((publicKey.equals(_publicKey)) && (privateKey.equals(_privateKey))) {
                        isExist = true;
                    }
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return isExist;
        }
    }
}
