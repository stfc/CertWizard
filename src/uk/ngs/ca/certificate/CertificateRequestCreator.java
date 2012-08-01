/*
 * This file is part of NGS CA project.
 */
package uk.ngs.ca.certificate;

import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Vector;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Set;
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
 * @author David Meredith (some modifications) 
 *
 */
public class CertificateRequestCreator {

    private static final Logger myLogger = Logger.getLogger(CertificateRequestCreator.class.getName());
    
    private final String SIG_ALG; //"MD5withRSA";
    private final String C, O, OU, L, CN, DN, Email;
    
    /**
     * Options for the PKCS#10 type. 
     */
    public enum TYPE {HOST, USER};
    private TYPE type; 

    /**
     * Create a new instance. The <tt>email</tt> value is only used when type is 
     * HOST for pre-pending the PKCS#10 DN with 'emailAddress=email@value'. 
     * 
     * @param type
     * @param CN
     * @param OU
     * @param L
     * @param email Only used when type is HOST. 
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
        } else this.L = null;
        this.type = type; 
        this.Email = email; 
        
        
        // build the DN and throw IllegalArgExe if something is invaild 
        this.DN = this.initDN(); 
                 
    }

    /**
     * Concatenates all the user information to a DN
     */
    private String initDN() {
        String csrDN; 
        if (C.equals("")) {
            throw new IllegalArgumentException("Invalid C");
        }
        if (O.equals("")) {
            throw new IllegalArgumentException("Invalid O");
        }
        if (OU.equals("")) {
            throw new IllegalArgumentException("Invalid OU");
        }
        // Should L be made optional ? 
        //if (L.equals("")) {
        //      throw new IllegalArgumentException("L");
        //}
        if (CN.equals("")) {
            throw new IllegalArgumentException("Invalid CN");
        }

        if (TYPE.HOST.equals(this.type)) {
            if (!EmailValidator.getInstance().isValid(Email)) {
                throw new IllegalArgumentException("Invalid Email");
            }
        }

        if (TYPE.USER.equals(this.type)) { 
            // Should L be made optional ? 
            if (L==null || L.equals("")) {
                csrDN = ("CN=" + CN + ", OU=" + OU + ", O=" + O + ", C=" + C);
            } else {
                csrDN = ("CN=" + CN + ", L=" + L + ", OU=" + OU + ", O=" + O + ", C=" + C);
            }
        } else { //host certificate
            if (L==null || L.equals("")) {
                csrDN = ("emailAddress=" + Email + ", CN=" + CN + ", OU=" + OU + ", O=" + O + ", C=" + C);
            } else {
                csrDN = ("emailAddress=" + Email + ", CN=" + CN + ", L=" + L + ", OU=" + OU + ", O=" + O + ", C=" + C);
            }
        } 
        return csrDN; 
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
            subjectAltName = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "DNS: "+CN)); 
        }
        Vector oids = new Vector(); // legacy required by BC. 
        Vector values = new Vector();
        oids.add(X509Extensions.SubjectAlternativeName);
        values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
        X509Extensions extensions = new X509Extensions(oids, values);
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));
      
        // TODO creating the PKCS#10 uses deprecated BC APIs. Need to update 
        // to new way of creating PKCS#10 using BC. 
        try {
            if(TYPE.USER.equals(this.type)){
                // X500Principal: The distinguished name must be specified using the 
                // grammar defined in RFC 1779 or RFC 2253 (either format is ok). e.g. 
                // "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US"
                // Note, we can't specify the email address in the DN (not RFC 1779 or 2253). 
                request = new PKCS10CertificationRequest(SIG_ALG, new X500Principal(DN), 
                       pubkey, new DERSet(attribute), privkey);    
            } else {
                // DM: can't specify X500Principal for host as it contains email attribute. 
                // X509Name: Takes an X509 dir name as a string of the format 
                // "C=AU, ST=Victoria", or some such, converting it into an ordered set of name attributes
                // Bool is for reverse DN. If reverse is true the oids and values 
                // are listed out starting with the last element in the sequence (ala RFC 2253)
                //  using 'openssl req -in pkcs10.txt -text' the DN is as follows: 
                //  default: Subject: emailAddress=david.meredith@stfc.ac.uk, CN=host.dl.ac.uk, L=RAL, OU=CLRC, O=eScienceDev, C=UK
                //  false:   Subject: emailAddress=david.meredith@stfc.ac.uk, CN=host.dl.ac.uk, L=RAL, OU=CLRC, O=eScienceDev, C=UK
                //  true:    Subject: C=UK, O=eScienceDev, OU=CLRC, L=RAL, CN=host.dl.ac.uk/emailAddress=david.meredith@stfc.ac.uk
                
                // We specify true for a reverse DN to be consistent with OpenCA
                // which seems to prefer PKCS#10 requests to have that DN style. 
                request = new PKCS10CertificationRequest(SIG_ALG, new X509Name(true, DN), 
                       pubkey, new DERSet(attribute), privkey); 
            }
            
            StringWriter writer = new StringWriter();
            PEMWriter pemWrite = new PEMWriter(writer);
            pemWrite.writeObject(request);
            pemWrite.close();
            
            //System.out.println(""+request.getCertificationRequestInfo().getSubject().toString());
            //Vector theseOids = request.getCertificationRequestInfo().getSubject().getOIDs();
            //ASN1Set set = request.getCertificationRequestInfo().getAttributes();

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
