/* Copyright 2009 NGS
 * This file is part of NGS CA project.
 */
package uk.ngs.ca.common;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;
import java.util.logging.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * A special keypair class for this application. It holds a private key which is
 * compatible to an openssl-generated one and a RSA private key.
 *
 * @author xw75 (Xiao Wang)
 */
public class CAKeyPair {

    private static final int KEYSIZE = 2048; //1024; 
    private static final String KEY_ALG = "RSA";

    private static final Logger myLogger = LogManager.getLogger(CAKeyPair.class.getName());
    private static final String SIG_ALG = "SHA1WITHRSA";  // was MD5withRSA 

    /**
     * Constructor does nothing.
     */
    public CAKeyPair() {
    }

    /*
     * This factory function generates a new pair of keys suitable for the use with NGS.
     * The default keyzise is 2048.
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

    /**
     * Create a self signed certificate using the given keyPair and DN
     * parameters.
     *
     * @param keyPair
     * @param ou
     * @param l
     * @param cn
     * @return the newly created certificate .
     * @throws IllegalStateException if an issue occurs when creating the cert.
     */
    public static X509Certificate createSelfSignedCertificate(KeyPair keyPair, String ou, String l, String cn) {

        // See https://www.misterpki.com/how-to-generate-a-self-signed-certificate-with-java-and-bouncycastle/ for more info on how to do this
        Calendar now = Calendar.getInstance();
        Date startDate = now.getTime();
        now.add(Calendar.YEAR, 1);
        Date expiryDate = now.getTime();

        BigInteger serialNumber = new BigInteger("123456789");

        X500NameBuilder nameBuilder = new X500NameBuilder();
        nameBuilder.addRDN(BCStyle.C, "UK");
        nameBuilder.addRDN(BCStyle.O, "eScience");
        nameBuilder.addRDN(BCStyle.OU, ou);
        nameBuilder.addRDN(BCStyle.L, l);
        nameBuilder.addRDN(BCStyle.CN, cn + " CSR cert");

        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder(SIG_ALG).build(keyPair.getPrivate());

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(nameBuilder.build(), serialNumber, startDate, expiryDate, Locale.UK, nameBuilder.build(), SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));

            return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(builder.build(contentSigner));

            // For now lets throw an IllegalStateException; the application is 
            // in control of generating the cert and so if an exception is thrown
            // here it is not due to bad input and is not something we can control. 
        } catch (CertificateException | OperatorCreationException ex) {
            java.util.logging.Logger.getLogger(CAKeyPair.class.getName()).log(Level.SEVERE, null, ex);
            throw new IllegalStateException(ex);
        }
    }
}
