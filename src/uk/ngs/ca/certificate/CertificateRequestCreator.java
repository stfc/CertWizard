/*
 * This file is part of NGS CA project.
 */
package uk.ngs.ca.certificate;

import org.apache.log4j.Logger;

import java.security.PrivateKey;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.jce.PKCS10CertificationRequest;

//import java.io.ByteArrayOutputStream;
import java.io.StringWriter;

import java.util.Vector;
import java.util.ArrayList;

/**
 * A new certification request
 *
 * @author xw75
 *
 */
public class CertificateRequestCreator {

    static final Logger myLogger = Logger.getLogger(CertificateRequestCreator.class.getName());
    public String SIG_ALG = "MD5withRSA";
    private String C = "";
    private String O = "";
    private String OU = "";
    private String L = "";
    private String CN = "";
    private String AdminEmail = "";
    private X509Name DN = null;
    private String Email = "";
    private String PIN1 = "";
    private String PIN2 = "";
    private String RA = "";
    public String HEADER = "-----BEGIN CERTIFICATE REQUEST-----";
    public String FOOTER = "-----END CERTIFICATE REQUEST-----";

    /**
     * Creates a new certificate request.
     */
    public CertificateRequestCreator() {
        String value = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.c");
        C = value.trim();
        value = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.o");
        O = value.trim();
        value = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.signature.algorithm");
        SIG_ALG = value.trim();
    }

    /**
     * Gets C
     * @return C
     */
    public String getC() {
        return C;
    }

    /**
     * Gets O
     * @return O
     */
    public String getO() {
        return O;
    }

    /**
     * Sets up CN
     * @param name CN
     */
    public void setCN(String name) {
        CN = name.trim();
    }

    /**
     * Gets CN
     * @return CN
     */
    public String getCN() {
        return CN;
    }

    /**
     * Sets up email
     * @param email email
     */
    public void setEmail(String email) {
        Email = email.trim();
    }

    /**
     * Gets email
     * @return email
     */
    public String getEmail() {
        return Email;
    }

    /**
     * Sets up administratos's email
     * @param email administrator's email
     */
    public void setAdminEmail(String email) {
        AdminEmail = email.trim();
    }

    /**
     * Gets administrator's email
     * @return administrator's email
     */
    public String getAdminEmail() {
        return AdminEmail;
    }

    /**
     * Sets up RA
     * @param ou OU
     * @param l L
     */
    public void setRA(String ou, String l) {
        setOU(ou.trim());
        setL(l.trim());
        RA = ou.trim() + " " + l.trim();
    }

    /**
     * Gets RA
     * @return RA
     */
    public String getRA() {
        return RA;
    }

    /**
     * Sets up OU
     * @param ou OU
     */
    public void setOU(String ou) {
        OU = ou.trim();
    }

    /**
     * Gets OU
     * @return OU
     */
    public String getOU() {
        return OU;
    }

    /**
     * Sets up L
     * @param l L
     */
    public void setL(String l) {
        L = l.trim();
    }

    /**
     * Gets L
     * @return L
     */
    public String getL() {
        return L;
    }

    /**
     * Sets up first PIN
     * @param pin PIN
     */
    public void setPIN1(String pin) {
        PIN1 = pin;
    }

    /**
     * Gets first PIN
     * @return PIN
     */
    public String getPIN1() {
        return PIN1;
    }

    /**
     * Sets up second PIN
     * @param pin PIN
     */
    public void setPIN2(String pin) {
        PIN2 = pin;
    }

    /**
     * Gets second PIN
     * @return PIN
     */
    public String getPIN2() {
        return PIN2;
    }

    /**
     * Checks if the two PINs are same
     * @return true if two PINs are same, otherwise false.
     */
    public boolean isValidPIN() {
        if (PIN1.equals("") || PIN2.equals("")) {
            return false;
        }

        if (PIN1.equals(PIN2)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * Gets X509Name
     * @return DN in X509Name
     */
    public X509Name getDN() {
        return DN;
    }

    /**
     * Concatenates all the user information to a DN
     * @param hostcert true if to create a host DN, otherwise false.
     */
    public void createDN(boolean hostcert) {

        ArrayList<String> missingInformation = new ArrayList<String>();

        if (getCN().equals("")) {
            missingInformation.add("C");
        }
        if (getO().equals("")) {
            missingInformation.add("O");
        }
        if (getOU().equals("")) {
            missingInformation.add("OU");
        }
//        if (getL().equals("")) {
//            missingInformation.add("L");
//        }
        if (getCN().equals("")) {
            missingInformation.add("CN");
        }

//        if (getAdminEmail().trim().equals("")) {
//            missingInformation.add("ADMINEMAIL");
//        }
        if (getPIN1().trim().equals("") || getPIN2().trim().equals("")) {
            missingInformation.add("PIN");
        }
        if (!isValidPIN()) {
            missingInformation.add("mismatch PIN");
        }

        if (hostcert) {
            if (getAdminEmail().equals("")) {
                missingInformation.add("AdminEmail");
            }
        }
//        if (getEmail().equals("")) {
//            missingInformation.add("EMAIL");
//        }


        if (missingInformation.size() == 0) {
            if (!hostcert) {
                if (getL().equals("")) {
                    //user certificate
//                    DN = new X509Name("C=" + getC() + ", O=" + getO() + ", OU=" + getOU() + ", CN=" + getCN());
                    DN = new X509Name("CN=" + getCN() + ", OU=" + getOU() + ", O=" + getO() + ", C=" + getC() );

                } else {
//                    DN = new X509Name("C=" + getC() + ", O=" + getO() + ", OU=" + getOU() + ", L=" + getL() + ", CN=" + getCN());
                    DN = new X509Name("CN=" + getCN() + ", L=" + getL() + ", OU=" + getOU() + ", O=" + getO() + ", C=" + getC());

                }
            } else {
                //host certificate, please note the email is E, not
                //emaliAddress
                if (getL().equals("")) {
//                    DN = new X509Name("C=" + getC() + ", O=" + getO() + ", OU=" + getOU() + ", CN=" + getCN() + ", emailAddress=" + getAdminEmail());
                    DN = new X509Name("emailAddress=" + getAdminEmail() + ", CN=" + getCN() + ", OU=" + getOU() + ", O=" + getO() + ", C=" + getC() );
                } else {
//                    DN = new X509Name("C=" + getC() + ", O=" + getO() + ", OU=" + getOU() + ", L=" + getL() + ", CN=" + getCN() + ", emailAddress=" + getAdminEmail());
                    DN = new X509Name("emailAddress=" + getAdminEmail() + ", CN=" + getCN() + ", L=" + getL() + ", OU=" + getOU() + ", O=" + getO() + "C=" + getC() );
                }
            }
        } else {
            myLogger.error("[CertificateRequest] could not create DN: not enough information available");
        }
    }

    /**
     * Creates CSR
     * @param privkey Private Key
     * @param pubkey Public Key
     * @return CSR
     */
    public String createCertificateRequest(PrivateKey privkey, PublicKey pubkey) {

        PKCS10CertificationRequest request = null;

        X500Principal subjectName = new X500Principal( getDN().toString() );

        // create a attribute for the request
        GeneralNames subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, getEmail()));
        Vector oids = new Vector();
        Vector values = new Vector();
        oids.add(X509Extensions.SubjectAlternativeName);
        values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
        X509Extensions extensions = new X509Extensions(oids, values);
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));


        try {
//            request = new PKCS10CertificationRequest(SIG_ALG, getDN(), pubkey, new DERSet( attribute ), privkey);
            request = new PKCS10CertificationRequest(SIG_ALG, subjectName, pubkey, new DERSet(attribute), privkey);
            StringWriter writer = new StringWriter();
            PEMWriter pemWrite = new PEMWriter(writer);
            pemWrite.writeObject(request);
            pemWrite.close();

            myLogger.debug("[CertificateCreator] createCertificateRequest: successful");
            return writer.toString();
        } catch (Exception ep) {
            ep.printStackTrace();
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ep.toString());
            return null;
        }
    }


}
