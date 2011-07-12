/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package unused; //was in uk.ngs.ca.certificate.management;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import java.util.Enumeration;
import java.util.Vector;
import java.util.Collection;
import java.util.Iterator;
import java.util.Date;
import java.util.Properties;

import java.text.DateFormat;
import java.text.SimpleDateFormat;

import java.io.InputStream;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileNotFoundException;

import org.apache.log4j.Logger;

import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import uk.ngs.ca.tools.property.SysProperty;

import uk.ngs.ca.info.ExpiredReKey;

/**
 *
 * @author xw75
 */
public class OnlineCertificateManager {

    KeyStore keyStore;
    static final Logger myLogger = Logger.getLogger(OnlineCertificateManager.class);
    static final String PROP_FILE = "/uk/ngs/ca/tools/property/configure.properties";
    private Properties properties = new Properties();
    private final String FILEPATH = ".ca";
    private String keyStoreFile = null;
    char[] PASSPHRASE;

    /**
     * this is a class to manage all certificates in keystore.
     *
     * @param passphrase passphrase to protect keystore
     *
     */
    public OnlineCertificateManager(char[] passphrase) {
        PASSPHRASE = passphrase;
        init();
        setupKeyStoreFile(passphrase);
    }

    /**
     * gets all alias from the keystore
     *
     * @return all alias in array. null if no alias found
     *
     */
    public String[] getAllAliases() {
        String[] names = null;
        try {
            Enumeration aliases = keyStore.aliases();
            Vector vector = new Vector();

            while (aliases.hasMoreElements()) {
                String n = (String) aliases.nextElement();
                if (keyStore.isKeyEntry(n)) {
                    vector.addElement(n);
                }
            }
            names = new String[vector.size()];
            for (int i = 0; i < names.length; i++) {
                names[i] = (String) vector.elementAt(i);
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve aliases: " + ke.getMessage());
        }
        return names;
    }

    /**
     * gets certificate status from server side.
     *
     * @param alias alias
     * @return certificate status. null if no status found
     *
     */
    public String getStatus(String alias) {
        try {
            //we need private key, not certificate
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            String serialNumber = cert.getSerialNumber().toString();

            //todo: access server by using serialNumber, PPPK
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
        }
        return null;
    }

    /**
     * gets certificate subject DN.
     *
     * @param alias alias
     * @return certificate DN. null if no DN found
     *
     */
    public String getDN(String alias) {
        return alias;
    }

    public String getDN(int index) {
        return getAllAliases()[index];
    }

    /**
     * gets Issuer DN
     *
     * @param alias alias
     * @return issuer DN. null if no issuer DN found
     *
     */
    public String getIssuerDN(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            return cert.getIssuerDN().getName();

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
            return null;
        }
    }

    /**
     * gets start date of the selected certificate
     *
     * @param alias alias
     * @return start date. null if no start date found
     *
     */
    public String getStartDate(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            Date date = cert.getNotBefore();

            //
            // Display a date in day, month, year format
            //
            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String result = formatter.format(date);
            return result;

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
            return null;
        }
    }

    /**
     * gets end date of selected certificate
     *
     * @param alias alias
     * @return end date of the certificate. null if no end date found
     *
     */
    public String getEndDate(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            Date date = cert.getNotAfter();

            //
            // Display a date in day, month, year format
            //
            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            String result = formatter.format(date);
            return result;

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve certificate: " + ke.getMessage());
            return null;
        }
    }

    /**
     * gets valid days left of the certificate
     * @param alias alias
     * @return valid days. null if no valid days found
     *
     */
    public String getLiveDays(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            long startMillis = cert.getNotBefore().getTime();
            long endMillis = cert.getNotAfter().getTime();
            if (endMillis < startMillis) {
                return "N/A";
            }

            long diffDays = (endMillis - startMillis) / (24 * 60 * 60 * 1000);

            //the live days would include the extra rekey days.
            ExpiredReKey reKey = new ExpiredReKey();
            int reKeyDays = reKey.getMaxReKeyTime();

            diffDays = diffDays + reKeyDays;

            return new Long(diffDays).toString();
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        }

        return null;
    }

    /**
     * gets renew date. talk to server at /CA/policy/maxrekeydate?????
     *
     * @param alias alias
     * @return renew date
     *
     */
    public String getRenewDate(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);

            DateFormat formatter = new SimpleDateFormat("dd/MM/yyyy");
            Date endDate = cert.getNotAfter();

            String result = formatter.format(endDate);

            return result;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
        }
        return null;
    }

    /**
     * gets algorithm of the certificate
     * @param alias alias
     * @return algorithm of the certificate. null if no algorithm found
     *
     */
    public String getAlgorithm(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            return cert.getSigAlgName();

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve algorithm: " + ke.getMessage());
            return null;
        }
    }

    /**
     * gets serial number of the selected certificate
     *
     * @param alias alias
     * @return serial number. null if no serial number found
     *
     */
    public String getSerialNumber(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            return cert.getSerialNumber().toString();

        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve serial number: " + ke.getMessage());
            return null;
        }
    }

    /**
     * gets email of the selected certificate. this email is the contacted email, not the administrator email.
     *
     * @param alias alias
     * @return email. null if no email found
     *
     */
    public String getEmail(String alias) {
        try {
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
//we need to decide to retrieve email from DN or from extension of the certificate??????
            //but in here we are retrieveing email from Extension....
            Collection col = cert.getSubjectAlternativeNames();
            if (!(col == null)) {
                Iterator iterator = col.iterator();
                while (iterator.hasNext()) {
                    java.util.List list = (java.util.List) iterator.next();
                    return (String) list.get(1);
                }
                return null;
            } else {
                return null;
            }
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to retrieve algorithm: " + ke.getMessage());
            return null;
        } catch (CertificateParsingException ce) {
            ce.printStackTrace();
            myLogger.error("[OnlineCertificateManager] certificate parsing exception: " + ce.getMessage());
            return null;
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[OnlineCertificateManager] exception: " + ep.getMessage());
            return null;
        }
    }

    /**
     * gets CN of the certificate
     * @param alias alias
     * @return CN of the certificate. null if no CN found
     */
    public String getName(String alias) {
        String name = null;

        String dn = getDN(alias).trim();
        if (dn.equals("") || dn == null) {
            return null;
        } else {
            int index = dn.indexOf("CN=");
            index = index + 3;
            int size = dn.length();
            String cn = dn.substring(index, size);
            int _index = cn.indexOf(",");
            if (_index == -1) {
                name = cn;
            } else {
                cn = cn.substring(0, _index);
                name = cn;
            }
        }
        return name;
    }

    /**
     * sets certificate in keystore
     *
     * @param alias alias
     * @param cert X509Certificate setup in keystore
     * @return true if setup successfully, otherwise false
     *
     */
    public boolean setCertificate(String alias, X509Certificate cert) {
        try {
            keyStore.setCertificateEntry(alias, cert);
            return true;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to set certificate: " + ke.getMessage());
            return false;
        }
    }

    /**
     * setup private key in keystore
     *
     * @param alias alias
     * @param key private key
     * @return true if setup successfully, otherwise false
     *
     */
    public boolean setPrivateKey(String alias, byte[] key) {
        try {
            keyStore.setKeyEntry(alias, key, null);
            return true;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to set private key: " + ke.getMessage());
            return false;
        }
    }

    /**
     * removes entry from keystore
     * 
     * @param alias
     * @return true if the entry has been removed from keystore and the keystore has been updated,
     * otherwise false
     */
    public boolean remove(String alias) {
        try {
            keyStore.deleteEntry(alias);
            if( store() ){
                return true;
            }else{
                return false;
            }
        } catch (Exception ep) {
            ep.printStackTrace();
            return false;
        }

    }

    /**
     * store keystore in user.home/.ca/cakeystore.pkcs12
     *
     * @return true if store successfully, otherwise false
     *
     */
    public boolean store() {
        try {
            File f = new File(keyStoreFile);
            FileOutputStream fos = new FileOutputStream(f);
            keyStore.store(fos, PASSPHRASE);
            fos.close();
            return true;
        } catch (FileNotFoundException fe) {
            fe.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to get pkcs file: " + fe.getMessage());
            return false;
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to get keystore file: " + ke.getMessage());
            return false;
        } catch (IOException ie) {
            ie.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to access pkcs file: " + ie.getMessage());
            return false;
        } catch (NoSuchAlgorithmException ne) {
            ne.printStackTrace();
            myLogger.error("[OnlineCertificateManager] no such algorithm: " + ne.getMessage());
            return false;
        } catch (CertificateException ce) {
            ce.printStackTrace();
            myLogger.error("[OnlineCertificateManager] certificate error: " + ce.getMessage());
            return false;
        }

    }

    private void init() {
        myLogger.debug("[OnlineCertificateManager] init...");
        try {
            keyStore = PKCS12KeyStoreUnlimited.getInstance();
            InputStream input = SysProperty.class.getResourceAsStream(PROP_FILE);
            properties.load(input);
            input.close();
        } catch (IOException ioe) {
            ioe.printStackTrace();
            myLogger.error("[OnlineCertificateManager] Property file is failed to load.");
        } catch (KeyStoreException ke) {
            ke.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to create a keyStore: " + ke.getMessage());
        } catch (NoSuchProviderException ne) {
            ne.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to create a keystore without suitable provider: " + ne.getMessage());
        }
    }

    private void setupKeyStoreFile(char[] passphrase) {
        myLogger.debug("[OnlineCertificateManager] get keystore ...");
        String key = "ngsca.cert.keystore.file";
        String value = properties.getProperty(key);
        if (value == null) {
            myLogger.error("[OnlineCertificateManager] could not find out the value of " + key + " in your property file.");
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
            } else {
                keyStore.load(null, null);
            }
        } catch (IOException iep) {
            iep.printStackTrace();
            myLogger.error("[OnlineCertificateManager] failed to read keystore file from: " + keyStoreFile + ". with the message: " + iep.getMessage());
        } catch (NoSuchAlgorithmException nae) {
            nae.printStackTrace();
            myLogger.error("[OnlineCertificateManager] algorithm error: " + nae.getMessage());
        } catch (CertificateException ce) {
            ce.printStackTrace();
            myLogger.error("[OnlineCertificateManager] certificate error: " + ce.getMessage());
        }
    }

}
