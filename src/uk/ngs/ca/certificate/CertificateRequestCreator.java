/*
 * This file is part of NGS CA project.
 */
package uk.ngs.ca.certificate;

import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

/**
 * Create a new PKCS#10 certification request as a string. 
 * @see http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
 * @see https://ssl-tools.verisign.com/checker/ 
 * 
 * @author xw75 (Xiao Wang) 
 * @author David Meredith
 *
 */
public class CertificateRequestCreator {

    private static final Logger myLogger = Logger.getLogger(CertificateRequestCreator.class.getName());
    
    private final String SIG_ALG; //"MD5withRSA";
    private String C, O, OU, L, CN, Email;
    private X509Name DN;
    /**
     * Options for the PKCS#10 type. 
     */
    public enum TYPE {HOST, USER};
    private TYPE type; 

    /**
     * Create a new certificate request.
     * 
     * @throws IllegalArgumentException if any of the given values are empty. 
     */
    public CertificateRequestCreator(TYPE type, String CN, String OU, String L, String email) {
        this.C = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.c").trim();
        this.O = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.o").trim();
        this.SIG_ALG = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.signature.algorithm").trim();
        this.CN = CN.trim(); 
        this.OU = OU.trim(); 
        if(L != null){
          this.L = L.trim(); 
        }
        this.Email = email.trim(); 
        this.type = type; 
        
        // build the DN and throw IllegalArgExe if something is invaild 
        this.createDN(); 
                 
    }

    /**
     * Concatenates all the user information to a DN
     */
    private void createDN() {
        if (CN.equals("")) {
            throw new IllegalArgumentException("Invalid C");
        }
        if (O.equals("")) {
            throw new IllegalArgumentException("O");
        }
        if (OU.equals("")) {
            throw new IllegalArgumentException("OU");
        }
        // Should L be made optional ? 
        //if (L.equals("")) {
        //      throw new IllegalArgumentException("L");
        //}
        if (CN.equals("")) {
            throw new IllegalArgumentException("CN");
        }

        if (TYPE.HOST.equals(this.type)) {
            if (!EmailValidator.getInstance().isValid(Email)) {
                throw new IllegalArgumentException("AdminEmail");
            }
        }

        if (TYPE.USER.equals(this.type)) { 
            // Should L be made optional ? 
            if (L==null || L.equals("")) {
                DN = new X509Name("CN=" + CN + ", OU=" + OU + ", O=" + O + ", C=" + C);
            } else {
                DN = new X509Name("CN=" + CN + ", L=" + L + ", OU=" + OU + ", O=" + O + ", C=" + C);
            }
        } else { //host certificate
            if (L==null || L.equals("")) {
                DN = new X509Name("emailAddress=" + Email + ", CN=" + CN + ", OU=" + OU + ", O=" + O + ", C=" + C);
            } else {
                DN = new X509Name("emailAddress=" + Email + ", CN=" + CN + ", L=" + L + ", OU=" + OU + ", O=" + O + ", C=" + C);
            }
        } 
    }

    /**
     * Creates a PKCS#10 request string using the class creation parameters and  
     * the given pubkey and privkey. 
     * 
     * @param privkey Private Key
     * @param pubkey Public Key
     * @return CSR as string 
     * @throws IllegalStateException if the PKCS#10 can't be created. 
     */
    public String createCertificateRequest(PrivateKey privkey, PublicKey pubkey) {

        PKCS10CertificationRequest request;

        
        // Create an attribute for the request
        // A common use case is to include an email address in the SubjectAlternative 
        // name extension in the certificate generated from the PKCS#10 request: 
        // For a user request, the SUBJECT_ALT_NAME is the userEmail. 
        // For a host request, the SUBJECT_ALT_NAME is of the form 'DNS: host.name.ac.uk' 
        GeneralNames subjectAltName; 
        if(TYPE.HOST.equals(this.type)){
            subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, Email));
        } else {
            // TODO need to check this is correct. 
            subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "DNS: "+CN)); 
        }
        Vector oids = new Vector(); // legacy required by BC. 
        Vector values = new Vector();
        oids.add(X509Extensions.SubjectAlternativeName);
        values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
        X509Extensions extensions = new X509Extensions(oids, values);
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));


        try {
            if(TYPE.USER.equals(this.type)){
                // DM: can's specify X500Principal for host as it may contain email attribute. 
               request = new PKCS10CertificationRequest(SIG_ALG, new X500Principal(DN.toString()), pubkey, new DERSet(attribute), privkey);    
            } else {
               request = new PKCS10CertificationRequest(SIG_ALG, DN, pubkey, new DERSet(attribute), privkey); 
            }
            
            StringWriter writer = new StringWriter();
            PEMWriter pemWrite = new PEMWriter(writer);
            pemWrite.writeObject(request);
            pemWrite.close();

            myLogger.debug("[CertificateCreator] createCertificateRequest: successful");
            return writer.toString();
        } catch (Exception ex) {
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            // This could be considered a coding error because we control the 
            // security provider, algorithm and generate the private key so we 
            // don't expect any bad values. 
            throw new IllegalStateException("Failed to make PKCS#10", ex);  
        } 
    }


}
