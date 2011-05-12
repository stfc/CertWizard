/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

import org.apache.log4j.Logger;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.Provider;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.PBEParameterSpec;
import java.security.AlgorithmParameters;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;

/**
 *
 * @author xw75
 */
public class EncryptUtil {

    static final Logger myLogger = Logger.getLogger(EncryptUtil.class);

    public static byte[] SALT = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    public static int ITERATIONCOUNT = 100;
    public static String ENCRYPTIONALGORITHM = "PBEWithSHA1AndDESede";

    public static String getEncryptedPrivateKey(char[] passphrase, PrivateKey privateKey) {
        PBEParameterSpec defParams = new PBEParameterSpec(SALT, ITERATIONCOUNT);
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(ENCRYPTIONALGORITHM);
            params.init(defParams);
            PBEKeySpec pbeSpec = new PBEKeySpec(passphrase);

            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ENCRYPTIONALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTIONALGORITHM);
            cipher.init(Cipher.WRAP_MODE, keyFact.generateSecret(pbeSpec), params);
            byte[] wrappedKey = cipher.wrap(privateKey);

            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(params, wrappedKey);
            String encryptedKey = new String(Base64.encode(pInfo.getEncoded()));

            return encryptedKey;

        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public static PrivateKey getDecryptedPrivateKey(char[] passphrase, String value) {
        PBEKeySpec pbeSpec = new PBEKeySpec(passphrase);
        PBEParameterSpec defParams = new PBEParameterSpec(SALT, ITERATIONCOUNT);

        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance(ENCRYPTIONALGORITHM);
            params.init(defParams);
            SecretKeyFactory keyFact = SecretKeyFactory.getInstance(ENCRYPTIONALGORITHM);
            Cipher cipher = Cipher.getInstance(ENCRYPTIONALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, keyFact.generateSecret(pbeSpec), params);
            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(Base64.decode(value));
            PKCS8EncodedKeySpec keySpec = pInfo.getKeySpec(cipher);

            KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            PrivateKey privKey = keyFactory.generatePrivate(keySpec);

            return privKey;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public static String getEncodedPublicKey(PublicKey publicKey) {
        return new String(Base64.encode(publicKey.getEncoded()));
    }

    public static PublicKey getPublicKey(String encodedPublicKeyString) {
        try {
            Provider provider = new BouncyCastleProvider();
            byte[] decodedPubKey = Base64.decode(encodedPublicKeyString);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedPubKey);
            KeyFactory keyFactory = KeyFactory.getInstance( "RSA", provider );
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            return pubKey;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }

    }

    public static String getKeyid(String encodedPublicKeyString){ //throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyid = null;
        try{
            Provider provider = new BouncyCastleProvider();
            byte[] decodedPubKey = Base64.decode(encodedPublicKeyString);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedPubKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", provider);
            PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            String exponentHexString = rsaPublicKey.getPublicExponent().toString(16);
            String modulusHexString = rsaPublicKey.getModulus().toString(16);
            String firstTwo = modulusHexString.substring(0, 2);
            firstTwo = "0x" + firstTwo;
            int _int = Integer.decode(firstTwo).intValue();
            if (_int >= 128) {
                modulusHexString = "00" + modulusHexString;
            }

            keyid = modulusHexString + "." + exponentHexString;

            return keyid;
        }catch( Exception ep ){
            ep.printStackTrace();
        }finally{
            return keyid;
        }
    }

}
