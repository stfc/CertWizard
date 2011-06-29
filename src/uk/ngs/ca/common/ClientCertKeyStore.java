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
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;
import java.security.KeyStoreException;
import org.apache.log4j.Logger;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;

import uk.ngs.ca.tools.property.SysProperty;

/**
 * Read or create file $HOME/.ca/cacertkeystore.pkcs12 (create if it does not
 * already exist). This file contains a collection of the valid and expired 
 * certificates only.  The class provides methods for adding/creating/deleting
 * entries from this keyStore file.
 *
 * @author xw75
 */
public final class ClientCertKeyStore {
    private static final Logger myLogger = Logger.getLogger(ClientCertKeyStore.class);
    
    // certKeyStore represents shared mutable state, so its access must be thread safe.
    private KeyStore certKeyStore = null;
    private String keyStoreFileAbsPath = null;
    private char[] PASSPHRASE = null;
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
        String caDir = System.getProperty("user.home") + File.separator + ".ca";
        this.PASSPHRASE = passphrase;
        this.keyStoreFileAbsPath = caDir + File.separator + SysProperty.getValue("ngsca.cert.keystore.file");

        try {
            this.certKeyStore = PKCS12KeyStoreUnlimited.getInstance();
        } catch (KeyStoreException ke) {
            throw new IllegalStateException("[ClientCertKeyStore] failed to create a keyStore: " , ke);
        } catch (NoSuchProviderException ne) {
            throw new IllegalStateException("[ClientCertKeyStore] failed to create a keystore without suitable provider: ", ne);
        }
        // load this.certKeyStore from file if it exists.
        this.loadCertKeyStoreFileFromFile(passphrase);
    }



    /**
     * If $HOME/.ca/cacertkeystore.pkcs12 already exists, load it otherwise
     * create an empty pkcs12 file.
     */
    private void loadCertKeyStoreFileFromFile(char[] passphrase) {
        myLogger.debug("[ClientCertKeyStore] get keystore ...");
        
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
            Enumeration<String> aliases = this.certKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String _alias = aliases.nextElement();
                if (this.certKeyStore.isKeyEntry(_alias)) {
                    X509Certificate cert = (X509Certificate)this.certKeyStore.getCertificate(_alias);
                    if( cert.getPublicKey().equals(publicKey) ){
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
            X509Certificate[] chain = {cert}; //new X509Certificate[1];
            String my_alias = new Long(new Date().getTime()).toString();
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
            myLogger.error("[ClientCertKeyStore] failed to get pkcs file: " + fe.getMessage());           
        } catch (KeyStoreException ke) {
            myLogger.error("[ClientCertKeyStore] failed to get keystore file: " + ke.getMessage());
        } catch (IOException ie) {
            myLogger.error("[ClientCertKeyStore] failed to access pkcs file: " + ie.getMessage());
        } catch (NoSuchAlgorithmException ne) {
            myLogger.error("[ClientCertKeyStore] no such algorithm: " + ne.getMessage());
        } catch (CertificateException ce) {
            myLogger.error("[ClientCertKeyStore] certificate error: " + ce.getMessage());
        } finally {
            if(fos != null) try {fos.close();} catch (IOException ex) {}
        }
        return false;
    }

    private synchronized boolean isExistKey(PrivateKey privateKey, X509Certificate cert) {
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
                        return true;
                    }
                }
            }
        } catch (Exception ke) {
            ke.printStackTrace();
        }
        return false;
    }
}
