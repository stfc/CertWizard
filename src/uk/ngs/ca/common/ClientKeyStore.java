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
import java.util.Arrays;

import java.util.Enumeration;
//import java.util.Vector;
import java.util.Date;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
//import java.util.logging.Level;

import org.apache.log4j.Logger;

import java.util.Properties;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ClientKeyStore {

    // keyStore represents shared mutable state and so must by synchronized.
    private KeyStore keyStore;
    private static final Logger myLogger = Logger.getLogger(ClientKeyStore.class);
    private static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private Properties properties = new Properties();
    private final String FILEPATH = ".ca";
    private String keyStoreFile = null;
    private char[] PASSPHRASE;
    //private String Alias = "Client Certificate";
    private String errorMessage = null;

   
    private static ClientKeyStore clientKeyStore = null;

    public static synchronized ClientKeyStore getClientkeyStore(char[] passphrase) {
        // Static factory method allows us to choose whether we return the same instance
        // or create a new instance (easy to remove the if check below so that
        // each invocation of this method will create/return a new keyStore
        // which replicates the previous public constructor.
        //
        // check if class keyStore has already been created succesfully,
        // (a composite action, i.e. check if null then act, but this is ok
        // provided this method is synchronized). Lets create the keystore only
        // if it has not been created yet or if the password has changed.
        if (clientKeyStore == null || (passphrase != null && !Arrays.equals(passphrase,clientKeyStore.PASSPHRASE))) {
            clientKeyStore = new ClientKeyStore(passphrase);
        }
        return clientKeyStore;
    }

    // force non-instantiability with private constructor
    private ClientKeyStore(char[] passphrase)  {
        PASSPHRASE = passphrase;
        init();
        setupKeyStoreFile(passphrase);
    }
    

    /*public ClientKeyStore(char[] passphrase)  {
        PASSPHRASE = passphrase;
        init();
        setupKeyStoreFile(passphrase);
    }*/

    public String getErrorMessage(){
        return this.errorMessage;
    }

    public synchronized boolean isExistPublicKey(PublicKey publicKey) {
        boolean isExist = false;
        try {
            Enumeration aliases = this.keyStore.aliases();
            List vector = new ArrayList(0);
            //Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    vector.add(this.keyStore.getCertificate(alias));
                }
            }
            for (int i = 0; i < vector.size(); i++) {
                X509Certificate cert = (X509Certificate) vector.get(i); //vector.elementAt(i);
                PublicKey _publicKey = cert.getPublicKey();
                if (publicKey.equals(_publicKey)) {
                    isExist = true;
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return isExist;
        }
    }

    public synchronized boolean isExistPrivateKey(PrivateKey privateKey) {
        boolean isExist = false;
        try {
            Enumeration aliases = this.keyStore.aliases();
            List vector = new ArrayList(0);
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    vector.add((PrivateKey) this.keyStore.getKey(alias, PASSPHRASE));
                }
            }
            for (int i = 0; i < vector.size(); i++) {
                PrivateKey _privateKey = (PrivateKey) vector.get(i);
                if (_privateKey.equals(privateKey)) {
                    isExist = true;
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return isExist;
        }
    }

    public synchronized PrivateKey getPrivateKey(PublicKey publicKey) {
        PrivateKey privateKey = null;
        try {
            Enumeration aliases = this.keyStore.aliases();
            List vector = new ArrayList(0);
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    vector.add(this.keyStore.getCertificate(alias));
                }
            }
            for (int i = 0; i < vector.size(); i++) {
                X509Certificate cert = (X509Certificate) vector.get(i);
                PublicKey _publicKey = cert.getPublicKey();
                if (publicKey.equals(_publicKey)) {
                    String _alias = this.keyStore.getCertificateAlias(cert);
                    privateKey = (PrivateKey) this.keyStore.getKey(_alias, PASSPHRASE);
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return privateKey;
        }
    }

    public synchronized PrivateKey getLatestPrivateKey() {
        PrivateKey privateKey = null;
        try {
            Enumeration aliases = this.keyStore.aliases();
            List vector = new ArrayList(0);
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    vector.add(alias);
                }
            }
            String _alias = (String) vector.get(0);
            long initialValue = new Long(_alias).longValue();
            for (int i = 0; i < vector.size(); i++) {
                String my_alias = (String) vector.get(i);
                long tempValue = new Long(my_alias).longValue();
                if (initialValue <= tempValue) {
                    initialValue = tempValue;
                }
            }
            privateKey = (PrivateKey) this.keyStore.getKey(new Long(initialValue).toString(), PASSPHRASE);

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return privateKey;
        }
    }

    public synchronized PublicKey getLatestPublicKey() {
        PublicKey publicKey = null;
        try {
            Enumeration aliases = this.keyStore.aliases();
            List vector = new ArrayList(0);
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (this.keyStore.isKeyEntry(alias)) {
                    vector.add(alias);
                }
            }
            String _alias = (String) vector.get(0);
            long initialValue = new Long(_alias).longValue();
            for (int i = 0; i < vector.size(); i++) {
                String my_alias = (String) vector.get(i);
                long tempValue = new Long(my_alias).longValue();
                if (initialValue <= tempValue) {
                    initialValue = tempValue;
                }
            }
            X509Certificate cert = (X509Certificate) this.keyStore.getCertificate(new Long(initialValue).toString());
            publicKey = cert.getPublicKey();
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return publicKey;
        }
    }

    /**
     * create a new keypair and restore in the keystore file.
     *
     * @return alias
     */
    public synchronized String createNewKeyPair() {
        try {
            KeyPair keyPair = CAKeyPair.getKeyPair();
            PrivateKey privKey = keyPair.getPrivate();
            X509Certificate cert = CAKeyPair.createSelfSignedCertificate(keyPair);
            X509Certificate[] certs = new X509Certificate[1];
            certs[ 0] = cert;
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
        X509Certificate[] chain = new X509Certificate[1];
        chain[ 0 ] = cert;
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

    //public String getErrorMessage() {
    //    return errorMessage;
    //}

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

    private void init()  {
        myLogger.debug("[ClientKeyStore] init...");
        InputStream input =null;
        try {
            this.keyStore = PKCS12KeyStoreUnlimited.getInstance();
            input = SysProperty.class.getResourceAsStream(PROP_FILE);
            properties.load(input);
            
        } catch (IOException ioe) {
            ioe.printStackTrace();
            myLogger.error("[ClientKeyStore] Property file is failed to load.");
            System.out.println("[ClientKeyStore]: ioexception = " + ioe.getMessage());
            errorMessage = ioe.getMessage();
            //throw ioe;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[ClientKeyStore] failed to create a keyStore: " + ke.getMessage());
            System.out.println("[ClientKeyStore]: keystoreexception = " + ke.getMessage());
            //errorMessage = ke.getMessage();
            //throw ke;

        } catch (NoSuchProviderException ne) {
            ne.printStackTrace();
            myLogger.error("[ClientKeyStore] failed to create a keystore without suitable provider: " + ne.getMessage());
            System.out.println("[ClientKeyStore]: nosuchproviderexception = " + ne.getMessage());
            errorMessage = ne.getMessage();
            //throw ne;
        } finally {
            try {
               if(input !=null) input.close();
            } catch (IOException ex) {
                //java.util.logging.Logger.getLogger(ClientKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void setupKeyStoreFile(char[] passphrase)  {
        myLogger.debug("[ClientKeyStore] get keystore ...");
        String key = "ngsca.key.keystore.file";
        String value = properties.getProperty(key);
        if (value == null) {
            myLogger.error("[ClientKeyStore] could not find out the value of " + key + " in your property file.");
        }
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + FILEPATH;
        if (!new File(homePath).isDirectory()) {
            new File(homePath).mkdir();
        }
        homePath = homePath + System.getProperty("file.separator") + value;
        keyStoreFile = homePath;
        FileInputStream fis = null;
        try {
            if (new File(keyStoreFile).exists()) {
                fis = new FileInputStream(keyStoreFile);
                this.keyStore.load(fis, passphrase);
                
                if (this.keyStore.size() == 0) {
                    _createDefaultKeyStore();
                }
            } else {
                _createDefaultKeyStore();
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
        } finally {
            try {if(fis != null) fis.close();} catch (IOException ex) {}
        }
    }

    public synchronized boolean removeCertKeyStore() {
        String fileName = SysProperty.getValue("ngsca.key.keystore.file");
        String homePath = System.getProperty("user.home");
        homePath = homePath + System.getProperty("file.separator") + ".ca";
        homePath = homePath + System.getProperty("file.separator") + fileName;
        File _file = new File(homePath);
        if (_file.exists()) {
            return _file.delete();
        } else {
            return true;
        }
    }

    private boolean _createDefaultKeyStore() {
        try {
            this.keyStore.load(null, null);
            reStore();
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
            return false;
        }
    }

    private boolean reStore() {
        FileOutputStream fos = null;
        try {
            File f = new File(keyStoreFile);
            fos = new FileOutputStream(f);
            this.keyStore.store(fos, PASSPHRASE);
            
            return true;
        } catch (Exception ep) {
            errorMessage = ep.getMessage();
            removeCertKeyStore();
            return false;
        } finally {
            try {
                if(fos != null) fos.close();
            } catch (IOException ex) {
                //java.util.logging.Logger.getLogger(ClientKeyStore.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }


}
