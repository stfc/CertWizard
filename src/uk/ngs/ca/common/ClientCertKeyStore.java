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

import org.apache.log4j.Logger;

import java.security.NoSuchAlgorithmException;

import java.util.Properties;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;

import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ClientCertKeyStore {

    private char[] PASSPHRASE = null;
    static final Logger myLogger = Logger.getLogger(ClientCertKeyStore.class);
    private KeyStore certKeyStore = null;
    static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private Properties properties = new Properties();
    private final String FILEPATH = ".ca";
    private String keyStoreFile = null;

    private String errorMessage = null;

    public ClientCertKeyStore(char[] passphrase) {
        PASSPHRASE = passphrase;
        init();
        setupCertKeyStoreFile(passphrase);
    }

    public KeyStore getCertKeyStore() {
        return certKeyStore;
    }

    private void init() {
        myLogger.debug("[ClientKeyStore] init...");
        try {
            certKeyStore = PKCS12KeyStoreUnlimited.getInstance();
            InputStream input = SysProperty.class.getResourceAsStream(PROP_FILE);
            properties.load(input);
            input.close();
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
        }
    }

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
        keyStoreFile = homePath;
        try {
            if (new File(homePath).exists()) {
                FileInputStream fis = new FileInputStream(homePath);
                certKeyStore.load(fis, passphrase);
                fis.close();
            } else {
                certKeyStore.load(null, null);
                File f = new File(homePath);
                FileOutputStream fos = new FileOutputStream(f);
                certKeyStore.store(fos, PASSPHRASE);
                fos.close();

            }
        } catch (Exception ep) {
            ep.printStackTrace();
            errorMessage = ep.getMessage();
        }
    }

    public String getErrorMessage(){
        return errorMessage;
    }

    public String getAlias( PublicKey publicKey ){
        String alias = null;
        try {
            Enumeration aliases = certKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String _alias = (String) aliases.nextElement();
                if (certKeyStore.isKeyEntry(_alias)) {
                    X509Certificate cert = (X509Certificate)certKeyStore.getCertificate(_alias);
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

    public boolean removeEntry( String alias ){
        try{
        certKeyStore.deleteEntry(alias);
        reStore();
        return true;
        }catch( KeyStoreException ke ){
            ke.printStackTrace();
            return false;
        }
    }

    public boolean addNewKey(PrivateKey privateKey, X509Certificate cert) {
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

    private boolean reStore() {
        try {
            File f = new File(keyStoreFile);
            FileOutputStream fos = new FileOutputStream(f);
            certKeyStore.store(fos, PASSPHRASE);
            fos.close();
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
        }

    }

    private boolean isExistKey(PrivateKey privateKey, X509Certificate cert) {
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
