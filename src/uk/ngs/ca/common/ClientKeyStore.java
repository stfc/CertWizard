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
import java.util.Vector;
import java.util.Date;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import org.apache.log4j.Logger;

import java.util.Properties;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ClientKeyStore {

    KeyStore keyStore;
    static final Logger myLogger = Logger.getLogger(ClientKeyStore.class);
    static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private Properties properties = new Properties();
    private final String FILEPATH = ".ca";
    private String keyStoreFile = null;
    char[] PASSPHRASE;
    private String Alias = "Client Certificate";
    private String errorMessage = null;

    public ClientKeyStore(char[] passphrase) {
        PASSPHRASE = passphrase;
        init();
        setupKeyStoreFile(passphrase);
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public boolean isExistPublicKey(PublicKey publicKey) {
        boolean isExist = false;
        try {
            Enumeration aliases = keyStore.aliases();
            Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    vector.addElement(keyStore.getCertificate(alias));
                }
            }
            for (int i = 0; i < vector.size(); i++) {
                X509Certificate cert = (X509Certificate) vector.elementAt(i);
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

    public boolean isExistPrivateKey(PrivateKey privateKey) {
        boolean isExist = false;
        try {
            Enumeration aliases = keyStore.aliases();
            Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    vector.addElement((PrivateKey) keyStore.getKey(alias, PASSPHRASE));
                }
            }
            for (int i = 0; i < vector.size(); i++) {
                PrivateKey _privateKey = (PrivateKey) vector.elementAt(i);
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

    public PrivateKey getPrivateKey(PublicKey publicKey) {
        PrivateKey privateKey = null;
        try {
            Enumeration aliases = keyStore.aliases();
            Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    vector.addElement(keyStore.getCertificate(alias));
                }
            }
            for (int i = 0; i < vector.size(); i++) {
                X509Certificate cert = (X509Certificate) vector.elementAt(i);
                PublicKey _publicKey = cert.getPublicKey();
                if (publicKey.equals(_publicKey)) {
                    String _alias = keyStore.getCertificateAlias(cert);
                    privateKey = (PrivateKey) keyStore.getKey(_alias, PASSPHRASE);
                }
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return privateKey;
        }
    }

    public PrivateKey getLatestPrivateKey() {
        PrivateKey privateKey = null;
        try {
            Enumeration aliases = keyStore.aliases();
            Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    vector.addElement(alias);
                }
            }
            String _alias = (String) vector.elementAt(0);
            long initialValue = new Long(_alias).longValue();
            for (int i = 0; i < vector.size(); i++) {
                String my_alias = (String) vector.elementAt(i);
                long tempValue = new Long(my_alias).longValue();
                if (initialValue <= tempValue) {
                    initialValue = tempValue;
                }
            }
            privateKey = (PrivateKey) keyStore.getKey(new Long(initialValue).toString(), PASSPHRASE);

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        } finally {
            return privateKey;
        }

    }

    public PublicKey getLatestPublicKey() {
        PublicKey publicKey = null;
        try {
            Enumeration aliases = keyStore.aliases();
            Vector vector = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                if (keyStore.isKeyEntry(alias)) {
                    vector.addElement(alias);
                }
            }
            String _alias = (String) vector.elementAt(0);
            long initialValue = new Long(_alias).longValue();
            for (int i = 0; i < vector.size(); i++) {
                String my_alias = (String) vector.elementAt(i);
                long tempValue = new Long(my_alias).longValue();
                if (initialValue <= tempValue) {
                    initialValue = tempValue;
                }
            }
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(new Long(initialValue).toString());
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
    public String createNewKeyPair() {
        try {
            KeyPair keyPair = CAKeyPair.getKeyPair();
            PrivateKey privKey = keyPair.getPrivate();
            X509Certificate cert = CAKeyPair.createSelfSignedCertificate(keyPair);
            X509Certificate[] certs = new X509Certificate[1];
            certs[ 0] = cert;
            String _alias = new Long(new Date().getTime()).toString();
            keyStore.setKeyEntry(_alias, privKey, PASSPHRASE, certs);
            reStore();
            return _alias;
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
        X509Certificate[] chain = new X509Certificate[1];
        chain[ 0 ] = cert;
        long _alias = new Date().getTime();
        String my_alias = new Long(_alias).toString();
        try {
            keyStore.setKeyEntry(my_alias, privateKey, PASSPHRASE, chain);
            reStore();
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            return false;
        }
    }

    public PublicKey getPublicKey(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            return cert.getPublicKey();
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public PrivateKey getPrivateKey(String alias) {
        try {
            return (PrivateKey) keyStore.getKey(alias, PASSPHRASE);
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public boolean removeKey(PrivateKey privateKey) {

        boolean isSuccess = true;
        try {
            if (isExistPrivateKey(privateKey)) {
                Enumeration aliases = keyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = (String) aliases.nextElement();
                    PrivateKey _privateKey = (PrivateKey) keyStore.getKey(alias, PASSPHRASE);
                    if (privateKey.equals(_privateKey)) {
                        keyStore.deleteEntry(alias);
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

    private void init() {
        myLogger.debug("[ClientKeyStore] init...");
        try {
            keyStore = PKCS12KeyStoreUnlimited.getInstance();
            InputStream input = SysProperty.class.getResourceAsStream(PROP_FILE);
            properties.load(input);
            input.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            myLogger.error("[ClientKeyStore] Property file is failed to load.");
            System.out.println("[ClientKeyStore]: ioexception = " + ioe.getMessage());
            errorMessage = ioe.getMessage();
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[ClientKeyStore] failed to create a keyStore: " + ke.getMessage());
            System.out.println("[ClientKeyStore]: keystoreexception = " + ke.getMessage());
            errorMessage = ke.getMessage();
        } catch (NoSuchProviderException ne) {
            ne.printStackTrace();
            myLogger.error("[ClientKeyStore] failed to create a keystore without suitable provider: " + ne.getMessage());
            System.out.println("[ClientKeyStore]: nosuchproviderexception = " + ne.getMessage());
            errorMessage = ne.getMessage();
        }
    }

    private void setupKeyStoreFile(char[] passphrase) {
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
        try {
            if (new File(keyStoreFile).exists()) {
                FileInputStream fis = new FileInputStream(keyStoreFile);
                keyStore.load(fis, passphrase);
                fis.close();
                if (keyStore.size() == 0) {
                    _createDefaultKeyStore();
                }
            } else {
                _createDefaultKeyStore();
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();

        }
    }

    public boolean removeCertKeyStore() {
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
            keyStore.load(null, null);
            reStore();
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
            return false;
        }
    }

    private boolean reStore() {
        try {
            File f = new File(keyStoreFile);
            FileOutputStream fos = new FileOutputStream(f);
            keyStore.store(fos, PASSPHRASE);
            fos.close();
            return true;
        } catch (Exception ep) {
            errorMessage = ep.getMessage();
            removeCertKeyStore();
            return false;
        }
    }
}
