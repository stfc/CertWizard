/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.common;

import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author xw75
 */
public class EncryptUtil {

    static final Logger myLogger = LogManager.getLogger(EncryptUtil.class);

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
            String encryptedKey = new String(Base64.encodeBase64(pInfo.getEncoded()));

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
            EncryptedPrivateKeyInfo pInfo = new EncryptedPrivateKeyInfo(Base64.decodeBase64(value));
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
        String key = new String(Base64.encodeBase64(publicKey.getEncoded()));
        return key;
    }

    public static PublicKey getPublicKey(String encodedPublicKeyString) {
        try {
            Provider provider = new BouncyCastleProvider();
            byte[] decodedPubKey = Base64.decodeBase64(encodedPublicKeyString);
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(decodedPubKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", provider);
            PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

            return pubKey;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }

    }

    public static String getKeyid(String encodedPublicKeyString) { //throws NoSuchAlgorithmException, InvalidKeySpecException {
        String keyid = null;
        try {
            Provider provider = new BouncyCastleProvider();
            byte[] decodedPubKey = Base64.decodeBase64(encodedPublicKeyString);
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
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return keyid;
        }
    }

}
