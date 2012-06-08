/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

import java.io.FileNotFoundException;

import java.io.FileOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;
import java.io.File;

import javax.crypto.spec.PBEParameterSpec;
import java.security.AlgorithmParameters;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;

import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;

import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1Sequence;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
//import org.globus.util.PEMUtil;


import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import org.bouncycastle.asn1.DERSet;

import java.security.spec.PKCS8EncodedKeySpec;


import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.Key;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.security.KeyPair;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;
import java.io.File;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.Vector;
import java.util.Date;

import java.util.Enumeration;

import uk.ngs.ca.certificate.management.ClientKeyStore;
//import uk.ngs.ca.common.ClientCertKeyStore;


import java.util.Properties;
import org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class KeyStoreTest {

    X509Certificate caCert;
    PrivateKey caKey;
    X509Certificate clientCert;
    PrivateKey clientKey;

    public KeyStoreTest() {
    }

        public String convertHexToString(String hex) {

        StringBuilder sb = new StringBuilder();
        StringBuilder temp = new StringBuilder();

        //49204c6f7665204a617661 split into two characters 49, 20, 4c...
        for (int i = 0; i < hex.length() - 1; i += 2) {
            //grab the hex in pairs
            String output = hex.substring(i, (i + 2));
            //convert hex to decimal
            int decimal = Integer.parseInt(output, 16);
            //convert the decimal to character
            sb.append((char) decimal);

            temp.append(decimal);
        }
//        System.out.println("Decimal : " + temp.toString());
        return sb.toString();
    }


    public KeyStore clientKeyStore() {
        try {

//            KeyStore certKeyStore = KeyStore.getInstance("PKCS12", "BC");
            KeyStore certKeyStore = PKCS12KeyStoreUnlimited.getInstance();
//            KeyStore certKeyStore = KeyStore.getInstance("JKS", "SUN");

            String path = "e:/cakeystore.pkcs12";
//            String path = "e:/wang-firefox.p12";

            FileInputStream fis = new FileInputStream(path);
//            certKeyStore.load(fis, "xiw19631211".toCharArray());
            certKeyStore.load(fis, "xiw19631211".toCharArray());
            fis.close();

            Enumeration aliases = certKeyStore.aliases();

            Vector v1 = new Vector();
            Vector v2 = new Vector();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                System.out.println("alias = " + alias);
                X509Certificate _cert = (X509Certificate) certKeyStore.getCertificate(alias);
                System.out.println("certificate _dn = " + _cert.getSubjectDN().getName());

                if (certKeyStore.isKeyEntry(alias)) {
                    X509Certificate cert = (X509Certificate) certKeyStore.getCertificate(alias);
                    System.out.println("certificate dn = " + cert.getSubjectDN().getName());
//                    PrivateKey privKey = (PrivateKey) certKeyStore.getKey(alias, "xiw19631211".toCharArray());
                    PrivateKey privKey = (PrivateKey) certKeyStore.getKey(alias, "xiw19631211".toCharArray());
//                    System.out.println("privateKey = " + privKey);
                    v1.addElement(cert);
                    v2.addElement(privKey);
                }
            }
            System.out.println("Number of keypair = " + v1.size());
            for (int i = 0; i < v1.size(); i++) {
                System.out.println("certificate DN [ " + i + " ] = " + ((X509Certificate) v1.elementAt(i)).getSubjectDN().getName());
//                System.out.println("public key [ " + i + " ] = " + ( (X509Certificate) v1.elementAt(i) ).getPublicKey().toString());
                PrivateKey privKey = (PrivateKey)v2.elementAt(i);
                RSAPrivateKey k = (RSAPrivateKey)privKey;
                RSAPublicKey kk = (RSAPublicKey)( (X509Certificate) v1.elementAt(i) ).getPublicKey();
//                System.out.println("public key length = " + kk.getModulus().bitLength());
//                System.out.println("bit account = " + k.getModulus().bitCount() + ", bit length = " + k.getModulus().bitLength());
//                System.out.println("priv key [" + i + " ] = " + privKey);
//                System.out.println("format private key [ " + i + " ] = " + privKey.getFormat());
                String modulus = kk.getModulus().toString();
                BigInteger in = new BigInteger( modulus );
                int bit = in.bitLength();
//                System.out.println("---modulus = " + modulus);
//                System.out.println("bit = " + bit);
//                System.out.println("exponse-16 = " + kk.getPublicExponent().toString(16) + ", exponse-10 = "+ kk.getPublicExponent().toString());
            }

            System.out.println("Number of keypair = " + v1.size());



            while (aliases.hasMoreElements()) {
                    String alias = (String) aliases.nextElement();
                    Key key = certKeyStore.getKey(alias, "xiw19631211".toCharArray());
                    if (key instanceof PrivateKey) {
System.out.println("there is private key");

/*

                        X509Certificate cert = (X509Certificate) importKeyStore.getCertificate(alias);
                        //if the imported certificate is expired, then is not allowed to import.
                        cert.checkValidity();
                        PrivateKey privateKey = (PrivateKey) key;
                        ClientKeyStore clientKeyStore = new ClientKeyStore(keyStorePassphrase);

                        String _dn = cert.getSubjectDN().getName();
                        String _value = SysProperty.getValue("ngsca.cert.o");
                        int _index = _dn.indexOf(_value);
                        if (_index == -1) {
                            Message = "CertWizard only supports certificates issued by the UK e-Science CA. \nYour certificate DN is " + _dn + ", so please select a proper certificate to import.";
                            isSuccess = false;
                        } else {
                            PublicKey publicKey = cert.getPublicKey();
                            ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey( publicKey );

                            if( resourcesPublicKey.isExist() ){

                            }else{
                                Message = "Your imported certificate looks valid, but there is no any record in the service database. Please contact with Helpdesk";
                            }
                            if (clientKeyStore.addNewKey(privateKey, cert)) {
                                ClientCertKeyStore clientCertKeyStore = new ClientCertKeyStore(keyStorePassphrase);
                                if (clientCertKeyStore.addNewKey(privateKey, cert)) {
                                    Message = "The keys have been added up in local keyStore and cert KeyStore files.";
                                    isSuccess = true;
                                } else {
                                    Message = "The keys have been added up in local KeyStore, but failed in local cert KeyStore.";
                                    isSuccess = false;
                                }
                            } else {
                                Message = "The Keys are failed to add up in local keyStore file.";
                                isSuccess = false;
                            }
                        }
*/

                    } else {
System.out.println("no private key");
                    }
            }

            return certKeyStore;

        } catch (Exception ep) {
ep.printStackTrace();
            System.out.println("Exception = " + ep.getMessage());
            return null;
        }
    }

    public void clientCertKeyStore() {
        try {

//            KeyStore certKeyStore = KeyStore.getInstance("PKCS12", "BC");
            KeyStore certKeyStore = PKCS12KeyStoreUnlimited.getInstance();

            String path = "e:/certkeystoreTest.pkcs12";
            FileInputStream fis = new FileInputStream(path);
            certKeyStore.load(fis, "mypassword".toCharArray());
            fis.close();

            Enumeration aliases = certKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                System.out.println("alias = " + alias);
                if (certKeyStore.isKeyEntry(alias)) {
                    System.out.println("certificate = " + (X509Certificate) certKeyStore.getCertificate(alias));
                    PrivateKey privKey = (PrivateKey) certKeyStore.getKey(alias, "mypassword".toCharArray());
                    System.out.println("privateKey = " + privKey);
                }
            }

        } catch (Exception ep) {

            System.out.println("Exception = " + ep.getMessage());
        }
    }

    public void importToKeyStore(KeyStore _certKeyStore) {
//        if (isExistFile(certFile)) {
        try {
//            KeyStore importKeyStore = KeyStore.getInstance("PKCS12", "BC");
            KeyStore importKeyStore = PKCS12KeyStoreUnlimited.getInstance();

//            importKeyStore.load(new FileInputStream("e:/wang2010.pfx"), "xiw19631211".toCharArray());
            importKeyStore.load(new FileInputStream("e:/wangDev2010.pfx"), "xiw19631211".toCharArray());

            Enumeration aliases = importKeyStore.aliases();
            while (aliases.hasMoreElements()) {
                System.out.println("===========================");
                String alias = (String) aliases.nextElement();
                Key key = importKeyStore.getKey(alias, "xiw19631211".toCharArray());
                if (key instanceof PrivateKey) {
                    X509Certificate cert = (X509Certificate) importKeyStore.getCertificate(alias);
//                        PublicKey publicKey = cert.getPublicKey();
                    PrivateKey privateKey = (PrivateKey) key;
                    System.out.println("alias = " + alias);
                    System.out.println("cert = " + cert);
                    System.out.println("privateKey = " + privateKey);

//_certKeyStore.

                    X509Certificate[] chain = new X509Certificate[1];
                    chain[ 0] = cert;
                    long _alias = new Date().getTime();
                    String my_alias = new Long(_alias).toString();
//        try {
                    _certKeyStore.setKeyEntry(my_alias, privateKey, "mypassword".toCharArray(), chain);


                    File f = new File("e:/newOne.pkcs12");
                    FileOutputStream fos = new FileOutputStream(f);
                    _certKeyStore.store(fos, "mypassword".toCharArray());
                    fos.close();
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
//        }
//                    }
        }
    }

    public X509Certificate v1Cert() {
//        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Date startDate = new Date(110, 3, 10);
        Date expiryDate = new Date(111, 3, 9);
        BigInteger serialNumber = new BigInteger("651");

        KeyPair key = getKeyPair();
        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();
        X500Principal dnName = new X500Principal("CN=Test CA Certificate");
//        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
X509Name x509name = new X509Name( "CN=Test CA Cert");
X509Name _x509name = new X509Name("CN=xiao wang");
        certGen.setSerialNumber(serialNumber);

        certGen.setIssuerDN(x509name);
        certGen.setSubjectDN(_x509name);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setPublicKey(key.getPublic());
//        certGen.setSignatureAlgorithm("MD5withRSA");
        certGen.setSignatureAlgorithm("MD5withRSA");
        try {
            X509Certificate cert = certGen.generateX509Certificate(key.getPrivate(), "BC");
/*
            System.out.println("certificate has been created successfully!!!");
            System.out.println("serial numer = " + cert.getSerialNumber().toString());
            System.out.println("issuer DN name = " + cert.getIssuerDN().getName());
            System.out.println("issue x500 dn name = " + cert.getIssuerX500Principal().getName());
            System.out.println("signature algorithm = " + cert.getSigAlgName());
            System.out.println("subject dn = " + cert.getSubjectDN().getName());
            System.out.println("subject x500 dn = " + cert.getSubjectX500Principal().getName());
            System.out.println("start year = " + cert.getNotBefore().getYear());
            System.out.println("expiry year = " + cert.getNotAfter().getYear());
            System.out.println("cert string = " + cert.toString());
            Date ttt = new Date();
            System.out.println("day = " + ttt.getDay() + ", month = " + ttt.getMonth() + ", year = " + ttt.getYear() + ", date = " + ttt.getDate());
*/
            caCert = cert;
            caKey = key.getPrivate();

            return cert;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

    public void v3Cert() {
        Date startDate = new Date(110, 3, 10);
        Date expiryDate = new Date(111, 3, 9);
        BigInteger serialNumber = new BigInteger("262274");

        KeyPair key = getKeyPair();
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        /* test only  */
        java.util.Vector order = new java.util.Vector();
        java.util.Hashtable attrs = new java.util.Hashtable();
        attrs.put(org.bouncycastle.jce.X509Principal.C, "UK");
        attrs.put(org.bouncycastle.jce.X509Principal.O, "eScience");
        attrs.put(org.bouncycastle.jce.X509Principal.OU, "STFC");
        attrs.put(org.bouncycastle.jce.X509Principal.L, "DL");
        attrs.put(org.bouncycastle.jce.X509Principal.CN, "xiao wang111");
        attrs.put(org.bouncycastle.jce.X509Principal.EmailAddress, "xiao.wang@stfc.ac.uk");
//        attrs.put(org.bouncycastle.jce.X509Principal.E, "xd.xiao.wang@gmail.com");
        order.addElement(org.bouncycastle.jce.X509Principal.C);
        order.addElement(org.bouncycastle.jce.X509Principal.O);
        order.addElement(org.bouncycastle.jce.X509Principal.OU);
        order.addElement(org.bouncycastle.jce.X509Principal.L);
        order.addElement(org.bouncycastle.jce.X509Principal.CN);
        order.addElement(org.bouncycastle.jce.X509Principal.EmailAddress);
//        order.addElement(org.bouncycastle.jce.X509Principal.E);

        certGen.reset();
        certGen.setSerialNumber(serialNumber);
//        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setIssuerDN(new X509Name("CN=Test CA Cert" ));
        certGen.setSubjectDN(new org.bouncycastle.jce.X509Principal(order, attrs));
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setPublicKey(key.getPublic());
//        certGen.setSignatureAlgorithm("MD5withRSA");

        //can we put the different signature algorithm between CA certificate and this certificate???
        certGen.setSignatureAlgorithm("MD5withRSA");


        /*   end of test only */
        /*
        X500Principal subjectName = new X500Principal("/C=UK/OU=eScience/O=STFC/L=DL/CN=Test V3 Certificate");
        //org.bouncycastle.asn1.x509.X509Name subjectName = new org.bouncycastle.asn1.x509.X509Name( "C=UK, O=eScience, OU=STFC, L=DL, CN=xiao wang" );
        //        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        certGen.setSerialNumber(serialNumber);
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setSubjectDN(subjectName);
        certGen.setNotBefore(startDate);
        certGen.setNotAfter(expiryDate);
        certGen.setPublicKey(key.getPublic());
        //        certGen.setSignatureAlgorithm("MD5withRSA");

        //can we put the different signature algorithm between CA certificate and this certificate???
        certGen.setSignatureAlgorithm(SIG_ALG);
         */
        try {
            certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
            certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifierStructure(key.getPublic()));

            /* test for subject alternative name */
            GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "test@stfc.ac.uk"));
            certGen.addExtension(X509Extensions.SubjectAlternativeName, true, subjectAltName);

            /* end of test of subject alternative name  */

            X509Certificate cert = certGen.generateX509Certificate(caKey, "BC");
clientCert = cert;
clientKey = key.getPrivate();
/*
            System.out.println("certificate has been created successfully!!!");
            System.out.println("serial numer = " + cert.getSerialNumber().toString());
            System.out.println("issuer DN name = " + cert.getIssuerDN().getName());
            System.out.println("issue x500 dn name = " + cert.getIssuerX500Principal().getName());
            System.out.println("signature algorithm = " + cert.getSigAlgName());
            System.out.println("subject dn = " + cert.getSubjectDN().getName());
            System.out.println("subject x500 dn = " + cert.getSubjectX500Principal().getName());
            System.out.println("start year = " + cert.getNotBefore().getYear());
            System.out.println("expiry year = " + cert.getNotAfter().getYear());
            System.out.println("cert string = " + cert.toString());
            System.out.println("cert subject alternative name  size = " + cert.getSubjectAlternativeNames().size());
*/
/*
            java.util.Collection col = cert.getSubjectAlternativeNames();
            java.util.Iterator iterator = col.iterator();
            while (iterator.hasNext()) {

                java.util.List list = (java.util.List) iterator.next();
                System.out.println("cert subject alternative name list = " + list);
                System.out.println("cert subject alternative name list = " + list.get(0));
                System.out.println("cert subject alternative name = " + list.get(1));
//    String[] t = (String[])list.toArray();
//    for( int i = 0; i < t.length; i ++ ){
//        System.out.println("cert subject alternative name = " + t[i]);
//    }
//System.out.println( "cert subject alternative name = " + iterator.next() );
            }
 */
//            Date ttt = new Date();
//            System.out.println("day = " + ttt.getDay() + ", month = " + ttt.getMonth() + ", year = " + ttt.getYear() + ", date = " + ttt.getDate());

//            clientCert = cert;
            /* test only */
/*
            ByteArrayOutputStream _out = new ByteArrayOutputStream();
// note that it will be wrong if no base64 code.
            createBase64(_out, "-----BEGIN CERTIFICATE-----", Base64.encode(clientCert.getEncoded()), "-----END CERTIFICATE-----");
            String _out_string = _out.toString();
            System.out.println("=====//////////////////////////// v3 cert = " + _out_string);
//please note that PEMWriter and base64 do the same work.
            java.io.StringWriter my = new java.io.StringWriter();
            org.bouncycastle.openssl.PEMWriter _write = new org.bouncycastle.openssl.PEMWriter(my);
            _write.writeObject(clientCert);
            _write.close();
            System.out.println("///////////////////////////////////v3 cert = " + my.toString());
*/
            /* end of test */
        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    private KeyPair getKeyPair() {
        try {
            Provider provider = new BouncyCastleProvider();
            KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA", provider);
            keyGenerator.initialize(1024);
            KeyPair key = keyGenerator.generateKeyPair();
            return key;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
    }

        public void checkPKCS12(){
        try {
//            java.security.KeyStore keyStore = java.security.KeyStore.getInstance("PKCS12", "BC");
            KeyStore keyStore = PKCS12KeyStoreUnlimited.getInstance();

            File f = new File("e:/wxd.pkcs12");
            System.out.println("exist = " + f.exists());
            if (!f.exists()) {
                f.createNewFile();
            }
/* */
            java.io.FileOutputStream fos = new java.io.FileOutputStream(f);
            keyStore.load(null, null);

            X509Certificate chain[] = new X509Certificate[1];
            chain[0] = clientCert;
            String alias = clientCert.getSubjectDN().getName();
            keyStore.setKeyEntry(alias, clientKey, "mypassword".toCharArray(), chain);
            keyStore.store(fos, "mypassword".toCharArray());
            fos.close();
/*   */
        } catch (Exception ep) {
//            ep.printStackTrace();
            System.out.println("-----------------exception = " + ep.getMessage());
        }

        readPKCS12File( "mypassword" );

    }
    public void readPKCS12File( String password ){
        try{
//java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12", "BC");
            KeyStore ks = PKCS12KeyStoreUnlimited.getInstance();
            
            String path = "e:/wxd.pkcs12";
//            String path = "e:/newOne.pkcs12";
            FileInputStream fis = new FileInputStream(path);
            ks.load(fis, password.toCharArray());
            fis.close();

//java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12", "BC");
//ks.load(new java.io.FileInputStream("e:/wxd.pkcs12"),password.toCharArray());

System.out.println("size of keystore = " + ks.size());
//System.out.println("certificate of keystore = " + ks.getCertificate("My Key"));
        }catch(Exception ep){
            ep.printStackTrace();
        }

    }


    public static void main(String[] args) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());


        KeyStoreTest test = new KeyStoreTest();
/*
        test.v1Cert();
        test.v3Cert();
        test.checkPKCS12();
 */
//        test.readPKCS12File("mypassword");


        KeyStore k = test.clientKeyStore();
//test.clientCertKeyStore();
//        test.importToKeyStore(k);
    }
}
