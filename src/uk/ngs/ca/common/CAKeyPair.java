/* Copyright 2009 NGS
 * This file is part of NGS CA project.
 */
package uk.ngs.ca.common;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509Name;
import java.security.cert.X509Certificate;

/*import java.io.IOException;
import java.io.PrintStream;
import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import org.bouncycastle.util.encoders.Base64;
import java.io.StringWriter;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.openssl.PEMWriter;
import java.io.ByteArrayOutputStream;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
*/

import java.util.Date;
import java.math.BigInteger;
import java.util.Calendar;

/**
 * A special keypair class for this application. It holds a private key which is
 * compatible to an openssl-generated one and a RSA private key.
 * 
 * @author xw75
 */
public class CAKeyPair {

    private static final int KEYSIZE = 1024;
    private static final String KEY_ALG = "RSA";

    //private static final String KEY_HEADER = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
    //private static final String KEY_FOOTER = "-----END ENCRYPTED PRIVATE KEY-----";
    //private static final byte[] SALT = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    //private static int ITERATIONCOUNT = 100;
    //private static final String ENCRYPT_ALG = "PBEWithSHA1AndDESede";
    private static final Logger myLogger = Logger.getLogger(CAKeyPair.class.getName());
    private static final String SIG_ALG = "MD5withRSA";

   
    /**
     * Constructor does nothing.
     */
    public CAKeyPair() {
    }

    /*
     * This factory function generates a new pair of keys suitable for the use with NGS.
     * The default keyzise is 1024.
     *
     * @return The created KeyPair
     */
    public static KeyPair getNewKeyPair() {
        return getNewKeyPairHelper(KEYSIZE);
    }

    /*
     * This factory function generates a new pair of keys suitable for the use with NGS.
     *
     * @return The created KeyPair
     * @param keysize the keysize of keypair
     */
    private static KeyPair getNewKeyPairHelper(int keysize) {
        try {
            Provider provider = new BouncyCastleProvider();
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(KEY_ALG, provider);
            keyGenerator.initialize(keysize);
            KeyPair key = keyGenerator.generateKeyPair();
            myLogger.debug("[CAKeyPair] successfully create a key pair.");
            return key;
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[CAKeyPair] failed to create key pair.");
            return null;
        }
    }

    /*
     * retrieves a private key from the keypair
     *
     * @return private key
     * @param keypair
     */
    /*public static PrivateKey getPrivateKey(KeyPair keyPair) {
        return keyPair.getPrivate();
    }*/

    /*
     * Retrieve a Public Key from the KeyPair
     *
     * @return Public Key
     * @param KeyPair
     */
    /*public static PublicKey getPublicKey(KeyPair keyPair) {
        return keyPair.getPublic();
    }*/

    /*
     * Encrypt a Private Key and store in local disk
     *
     * @return true if successfully, otherwise false
     * @param passphrase passphrase to protect the Private Key
     * @param privateKey Private Key
     * @param file a file to store the encrypted Private Key
     */
    /*public static boolean encryptPrivateKey(char[] passphrase, PrivateKey privateKey, File file) {
        return encryptPrivateKey(passphrase, privateKey, SALT, ITERATIONCOUNT, ENCRYPT_ALG, file);
    }*/

    /*
     * Encrypt a Private Key and store in local disk
     *
     * @return true if successfully, otherwise false
     * @param passphrase passphrase to protect the Private Key
     * @param privateKey Private Key
     * @param file a file path to store the encrypted Private Key
     */
    /*public static boolean encryptPrivateKey(char[] passphrase, PrivateKey privateKey, String file) {
        File f = new File(file);
        return encryptPrivateKey(passphrase, privateKey, SALT, ITERATIONCOUNT, ENCRYPT_ALG, f);
    }*/

    /*
     * Encrypt a Private Key and restore in local disk.
     * Please note, the same passphrase, salt, algorithm and iteration should be used for encryption and decryption.
     *
     * @return true if successfully, otherwise false
     * @param passphrase passphrase to protect the Private Key
     * @param privateKey Private Key
     * @param salt salt for the encryption
     * @param iterationCount iteration count for the encryption
     * @param algorithm encryption algorithm
     * @file a file to restore the encrypted Private Key.
     */
    /*public static boolean encryptPrivateKey(char[] passphrase, PrivateKey privateKey, byte[] salt, int iterationCount, String algorithm, File file) {
        PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(algorithm);
            params.init(defParams);
            PBEKeySpec pbeSpec = new PBEKeySpec(passphrase);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), params);
            byte[] wrappedKey = cipher.wrap(privateKey);
            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(params, wrappedKey);
            PrintStream ps = new PrintStream(file);
            ps.println(KEY_HEADER);
            String myEncodedKey = new String(Base64.encode(pInfo.getEncoded()));
            ps.println(myEncodedKey);

            ps.println(KEY_FOOTER);
            ps.close();
            myLogger.debug("[CAKeyPair] successfully encrypt private key and store in " + file.getAbsolutePath());
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[CAKeyPair] failed to encrypt private key or failed to store in " + file.getAbsolutePath());
            return false;
        }
    }*/

    /*
     * Decrypt Private Key
     *
     * @return decrypted Private Key
     * @passphrase the passphrase to decrypt the Private Key
     * @param file a file to restore the encrypted Private Key
     */
    /*public static PrivateKey decryptPrivateKey(char[] passphrase, File file) {
        return decryptPrivateKey(passphrase, SALT, ITERATIONCOUNT, ENCRYPT_ALG, file);
    }*/

    /*
     * Decrypt Private Key
     *
     * @return decrypted Private Key
     * @passphrase the passphrase to decrypt the Private Key
     * @param file a file path to restore the encrypted Private Key
     */
    /*public static PrivateKey decryptPrivateKey(char[] passphrase, String file) {
        File f = new File(file);
        return decryptPrivateKey(passphrase, SALT, ITERATIONCOUNT, ENCRYPT_ALG, f);
    }*/

    /*
     * Decrypt Private Key.
     * Please note, the same passphrase, salt, algorithm and iteration should be used for encryption and decryption.
     *
     * @return decrypted Private Key
     * @param passphrase passphrase to protect the Private Key
     * @param salt salt for the decryption
     * @param iterationCount iteration count for the decryption
     * @param algorithm decryption algorithm
     * @file a file to restore the encrypted Private Key.
     */
    /*private static PrivateKey decryptPrivateKey(char[] passphrase, byte[] salt, int iterationCount, String algorithm, File file) {

        String myKey = removeHeadFootString(getContents(file));
        PBEKeySpec pbeSpec = new PBEKeySpec(passphrase);

        PBEParameterSpec defParams = new PBEParameterSpec(salt, iterationCount);

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(algorithm);
            params.init(defParams);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(algorithm);
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, keyFact.generateSecret(pbeSpec), params);
            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(Base64.decode(myKey));

            PKCS8EncodedKeySpec keySpec = pInfo.getKeySpec(cipher);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALG);
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);
            myLogger.debug("[CAKeyPair] successfully decrypt private key.");
            return privKey;
        } catch (Exception ep) {
            myLogger.error("[CAKeyPair] failed to decrypt the private key.");
            ep.printStackTrace();
            return null;
        }
    }*/

    /*private static String getContents(File aFile) {
        //...checks on aFile are elided
        StringBuilder contents = new StringBuilder();
        try {
            //use buffering, reading one line at a time
            //FileReader always assumes default encoding is OK!
            BufferedReader input = new BufferedReader(new FileReader(aFile));
            try {
                String line = null; //not declared within while loop
                 // readLine is a bit quirky :
                 // it returns the content of a line MINUS the newline.
                 // it returns null only for the END of the stream.
                 // it returns an empty String if two newlines appear in a row.
                while ((line = input.readLine()) != null) {
                    contents.append(line);
                    contents.append(System.getProperty("line.separator"));
                }
            } finally {
                myLogger.debug("[CAKeyPair] successfully read out the encrypted private key from " + aFile.getAbsolutePath());
                input.close();
            }

        } catch (IOException ex) {
            myLogger.error("[CAKeyPair] failed to read our private key from " + aFile.getAbsolutePath());
            ex.printStackTrace();
        }
        return contents.toString();
    }*/

    /*private static String removeHeadFootString(String originalString) {
        String _originalString = originalString;
        int longString = _originalString.length();
        int _start = _originalString.indexOf(KEY_HEADER);
        int _end = KEY_HEADER.length();
        _start =
                _start + _end;
        _originalString =
                _originalString.substring(_start, longString);
        longString =
                _originalString.length();
        _start =
                _originalString.indexOf(KEY_FOOTER);
        _originalString =
                _originalString.substring(0, _start);
        return _originalString;

    }*/

    /*public static String createCSR(KeyPair keyPair) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DERSet derset = new DERSet();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        PKCS10CertificationRequest request = null;
        X509Name dn = new X509Name("CN=test cert, L=DL, OU=CLRC, O=eScienceDev, C=UK");
        X500Principal subjectName = new X500Principal(dn.toString());

        try {
            request = new PKCS10CertificationRequest(SIG_ALG, subjectName, publicKey, derset, privateKey);
            StringWriter writer = new StringWriter();
            PEMWriter pemWrite = new PEMWriter(writer);
            pemWrite.writeObject(request);
            pemWrite.close();

            myLogger.debug("[CAKeyPair] createCSR: successful");
            return writer.toString();
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[CAKeyPair] createCSR: failed. " + ep.toString());
            return null;
        }
    }*/

    /**
     * create a self signed certificate. the certificate is restore in keystore file with private key.
     *
     * @param keyPair
     * @return X509Certificate
     */
    /*public static X509Certificate createSelfSignedCertificate(KeyPair keyPair) {

        KeyPair _rootKeyPair = CAKeyPair.getNewKeyPair();
        X509Certificate rootCert = null;
        X509Certificate createdCert = null;

        Date startDate = new Date(110, 1, 1);
        Date expiryDate = new Date(121, 1, 1);
        BigInteger serialNumber = new BigInteger("123456789");

        X509Name dnName = new X509Name("CN=root cert, L=DL, OU=CLRC, O=eScienceDev, C=UK");


        //X509V1CertificateGenerator v1certGen = new X509V1CertificateGenerator();
        //v1certGen.setSerialNumber(serialNumber);
        //v1certGen.setIssuerDN(dnName);
        //v1certGen.setSubjectDN(dnName);
        //v1certGen.setNotBefore(startDate);
        //v1certGen.setNotAfter(expiryDate);
        //v1certGen.setPublicKey(_rootKeyPair.getPublic());
        //v1certGen.setSignatureAlgorithm(SIG_ALG);
        
          //Date _startDate = new Date(110, 1, 1);
          //Date _expiryDate = new Date(120, 1, 1);
          //BigInteger _serialNumber = new BigInteger("1111111");

        X509V3CertificateGenerator v3certGen = new X509V3CertificateGenerator();

        // test only
        java.util.Hashtable attrs = new java.util.Hashtable();
        attrs.put(org.bouncycastle.jce.X509Principal.C, "UK");
        attrs.put(org.bouncycastle.jce.X509Principal.O, "eScience");
        attrs.put(org.bouncycastle.jce.X509Principal.OU, "STFC");
        attrs.put(org.bouncycastle.jce.X509Principal.L, "DL");
        attrs.put(org.bouncycastle.jce.X509Principal.CN, "self sign");
        attrs.put(org.bouncycastle.jce.X509Principal.EmailAddress, "xiao.wang@stfc.ac.uk");

        java.util.Vector order = new java.util.Vector();
        order.addElement(org.bouncycastle.jce.X509Principal.C);
        order.addElement(org.bouncycastle.jce.X509Principal.O);
        order.addElement(org.bouncycastle.jce.X509Principal.OU);
        order.addElement(org.bouncycastle.jce.X509Principal.L);
        order.addElement(org.bouncycastle.jce.X509Principal.CN);
        order.addElement(org.bouncycastle.jce.X509Principal.EmailAddress);

        v3certGen.reset();
        v3certGen.setSerialNumber(serialNumber);
        v3certGen.setIssuerDN(dnName);
        v3certGen.setSubjectDN(new org.bouncycastle.jce.X509Principal(order, attrs));
        v3certGen.setNotBefore(startDate);
        v3certGen.setNotAfter(expiryDate);
        v3certGen.setPublicKey(keyPair.getPublic());

        //can we put the different signature algorithm between CA certificate and this certificate???
        v3certGen.setSignatureAlgorithm(SIG_ALG);

        try {
            //rootCert = v1certGen.generateX509Certificate(_rootKeyPair.getPrivate(), "BC");
            createdCert = v3certGen.generateX509Certificate(_rootKeyPair.getPrivate(), "BC");
          
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return createdCert;
        }
    }*/


    /**
     * create a self signed certificate. the certificate is restore in keystore file with private key.
     *
     * @param keyPair
     * @return X509Certificate
     */
    public static X509Certificate createSelfSignedCertificate(KeyPair keyPair) {
        //KeyPair _rootKeyPair = CAKeyPair.getNewKeyPair();
        X509Certificate createdCert = null;

        
        Calendar now = Calendar.getInstance();
        Date startDate = now.getTime();
        now.add(Calendar.YEAR, 1);
        Date expiryDate = now.getTime();

        //Date startDate = new Date();
        //Date expiryDate = new Date(121, 1, 1);

        BigInteger serialNumber = new BigInteger("123456789");

       
        /*X509V1CertificateGenerator v1certGen = new X509V1CertificateGenerator();
        v1certGen.setSerialNumber(serialNumber);
        v1certGen.setIssuerDN(dnName);
        v1certGen.setSubjectDN(dnName);
        v1certGen.setNotBefore(startDate);
        v1certGen.setNotAfter(expiryDate);
        v1certGen.setPublicKey(_rootKeyPair.getPublic());
        v1certGen.setSignatureAlgorithm(SIG_ALG);
        */
        //Date _startDate = new Date(110, 1, 1);
        //Date _expiryDate = new Date(120, 1, 1);
        //BigInteger _serialNumber = new BigInteger("1111111");

        X509V3CertificateGenerator v3certGen = new X509V3CertificateGenerator();

        // TODO: here we need to fill the attributes from user given values or
        // agree on sensible defaults for the following values. Note, this
        // certificate is simply a placeholder that will be replaced by the
        // cert that is issued from the CA (which will have the same public key) 
        java.util.Hashtable attrs = new java.util.Hashtable();
        attrs.put(org.bouncycastle.jce.X509Principal.C, "UK");
        attrs.put(org.bouncycastle.jce.X509Principal.O, "eScience");
        attrs.put(org.bouncycastle.jce.X509Principal.OU, "STFC");
        attrs.put(org.bouncycastle.jce.X509Principal.L, "DL");
        attrs.put(org.bouncycastle.jce.X509Principal.CN, "self signed CSR cert");
        //attrs.put(org.bouncycastle.jce.X509Principal.EmailAddress, "dummy@stfc.ac.uk");

        java.util.Vector order = new java.util.Vector();
        order.addElement(org.bouncycastle.jce.X509Principal.C);
        order.addElement(org.bouncycastle.jce.X509Principal.O);
        order.addElement(org.bouncycastle.jce.X509Principal.OU);
        order.addElement(org.bouncycastle.jce.X509Principal.L);
        order.addElement(org.bouncycastle.jce.X509Principal.CN);
        //order.addElement(org.bouncycastle.jce.X509Principal.EmailAddress);

        //X509Name issuerDN = new X509Name(CAKeyPair.CSR_ISSUER_DN);

        v3certGen.reset();
        v3certGen.setSerialNumber(serialNumber);
        //v3certGen.setIssuerDN(issuerDN); //wrong, different DN !
        v3certGen.setIssuerDN(new org.bouncycastle.jce.X509Principal(order, attrs));
        v3certGen.setSubjectDN(new org.bouncycastle.jce.X509Principal(order, attrs));
        v3certGen.setNotBefore(startDate);
        v3certGen.setNotAfter(expiryDate);
        v3certGen.setPublicKey(keyPair.getPublic());

        v3certGen.setSignatureAlgorithm(SIG_ALG);
     

        try {
            //rootCert = v1certGen.generateX509Certificate(_rootKeyPair.getPrivate(), "BC");
            createdCert = v3certGen.generateX509Certificate(keyPair.getPrivate(), "BC");

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return createdCert;
        }
    }

}
