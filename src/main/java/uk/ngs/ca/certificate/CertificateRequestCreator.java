package uk.ngs.ca.certificate;

import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.security.auth.x500.X500Principal;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import uk.ngs.ca.common.CertUtil;

public class CertificateRequestCreator {

    private static final Logger myLogger = LogManager.getLogger(CertificateRequestCreator.class.getName());

    private final String sig_alg; //"MD5withRSA";
    private final String attrCN, attrDN, email;

    /**
     * Options for the PKCS#10 type.
     */
    public enum TYPE {
        HOST, USER
    };
    private final TYPE type;

    /**
     * Create a new instance. On creation, the given dn is parsed to determine
     * if the dn is a user or host certificate request (it is considered at host
     * cert if the CN contains a dot '.' char).
     * <p/>
     * For user certificates, the <tt>emailAddress</tt> is used as the value for
     * the SubjectAlternativeName extension in the certificate generated from
     * the PKCS#10 request. For host certificates, the CN is used as the
     * SubjectAlternativeName.
     *
     * @param dn
     * @param emailAddress
     */
    public CertificateRequestCreator(String dn, String emailAddress) {
        this.sig_alg = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.signature.algorithm").trim();
        this.attrDN = dn;
        this.attrCN = CertUtil.extractDnAttribute(dn, CertUtil.DNAttributeType.CN);
        this.email = emailAddress;
        if (this.attrCN.contains(".")) {
            type = TYPE.HOST;
        } else {
            type = TYPE.USER;
        }
    }

    /**
     * Creates a PKCS#10 request string using the class creation parameters and
     * the given pubkey and privkey.
     *
     * @param privkey Private Key
     * @param pubkey Public Key
     * @return CSR as string
     * @throws java.io.IOException
     * @throws IllegalStateException if the PKCS#10 can't be created.
     */
    public String createCertificateRequest(PrivateKey privkey, PublicKey pubkey) {
        PKCS10CertificationRequest request;

        // Create an attribute for the request
        // A common use case is to include an email address in the SubjectAlternative 
        // name extension in the certificate generated from the PKCS#10 request: 
        // For a user request, the SUBJECT_ALT_NAME is the userEmail. 
        // For a host request, the SUBJECT_ALT_NAME is of the form 'DNS: host.name.ac.uk' 
        GeneralNames subjectAltNames;
        PKCS10CertificationRequestBuilder builder;

        /*Vector oids = new Vector(); // legacy required by BC. 
        Vector values = new Vector();
        oids.add(X509Extensions.SubjectAlternativeName);
        try {
        values.add(new X509Extension(false, new DEROctetString(subjectAltName)));
        } catch(IOException ex){
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            throw new IllegalStateException("Failed to make PKCS#10", ex);  
        }
        X509Extensions extensions = new X509Extensions(oids, values);
        Attribute attribute = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, new DERSet(extensions));*/
        try {
            if (TYPE.USER.equals(this.type)) {
                builder = new JcaPKCS10CertificationRequestBuilder(new X500Principal(attrDN), pubkey);
                subjectAltNames = new GeneralNames(new GeneralName(GeneralName.rfc822Name, email));
            } else {
                builder = new JcaPKCS10CertificationRequestBuilder(new X500Name(attrDN), pubkey);
                subjectAltNames = new GeneralNames(new GeneralName(GeneralName.rfc822Name, "DNS: " + attrCN));
            }
            ContentSigner contentSigner = new JcaContentSignerBuilder(sig_alg).build(privkey);

            ExtensionsGenerator extGen = new ExtensionsGenerator();

            extGen.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
            /*if(TYPE.USER.equals(this.type)){
                // X500Principal: The distinguished name must be specified using the 
                // grammar defined in RFC 1779 or RFC 2253 (either format is ok). e.g. 
                // "CN=Duke, OU=JavaSoft, O=Sun Microsystems, C=US"
                // 
                // When we run the following openssl command on the request.toString(), 
                // notice that the DN is in REVERSE (starts with C). 
                // This is needed to be consistent with OpenCA
                // which seems to prefer PKCS#10 requests to have that DN style, e.g. 
                //   $openssl req -in certwizCsr.pem -noout -subject
                //   subject=/C=UK/O=eScienceDev/OU=CLRC/L=DL/CN=david meredith test 
                // 
                // Think it must be the PKCS10CertificationRequest that reverses 
                // the DN to start with C. 
                request = new PKCS10CertificationRequest(sig_alg, new X500Principal(attrDN), pubkey, new DERSet(attribute), privkey);    
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
                
                // We specify true for a REVERSE DN (starts with C) to be consistent with OpenCA
                // which seems to prefer PKCS#10 requests to have that DN style, e.g. 
                //  $openssl req -in certwizCsr.pem -noout -subject
                //  subject=/C=UK/O=eScienceDev/OU=CLRC/L=DL/CN=some.valid.host
                request = new PKCS10CertificationRequest(sig_alg, new X509Name(true, attrDN), pubkey, new DERSet(attribute), privkey); 
            }*/

            request = builder.build(contentSigner);

            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWrite = new JcaPEMWriter(writer);
            pemWrite.writeObject(request);
            pemWrite.close();

            //System.out.println(""+request.getCertificationRequestInfo().getSubject().toString());
            //Vector theseOids = request.getCertificationRequestInfo().getSubject().getOIDs();
            //ASN1Set set = request.getCertificationRequestInfo().getAttributes();
            myLogger.debug("[CertificateCreator] createCertificateRequest: successful");
//            if(true){
//            System.out.println(writer.toString());
//            throw new RuntimeException("forced die dave"); 
//            }
            return writer.toString();
            /*} catch (NoSuchAlgorithmException ex) {
            // These exceptions are considered coding errors; because we control the 
            // security provider, algorithm and generate the private key so we 
            // don't expect any bad values. 
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            throw new IllegalStateException("Failed to make PKCS#10", ex);
        } catch (NoSuchProviderException ex) {
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            throw new IllegalStateException("Failed to make PKCS#10", ex);
        } catch (InvalidKeyException ex) {
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            throw new IllegalStateException("Failed to make PKCS#10", ex);
        } catch (SignatureException ex) {
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            throw new IllegalStateException("Failed to make PKCS#10", ex);*/
        } catch (IOException | OperatorCreationException ex) {
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            throw new IllegalStateException("Failed to make PKCS#10", ex);
        }
    }

    /**
     * Create a new instance. The <tt>email</tt> value is only used when type is
     * HOST for pre-pending the PKCS#10 DN with 'emailAddress=email@value'.
     *
     * @param type
     * @param cn
     * @param ou
     * @param l
     * @param emailAddress Only used when type is HOST.
     * @param includeEmailInDn
     * @throws IllegalArgumentException if any of the given values are empty.
     */
    /*public CertificateRequestCreator(TYPE type, String cn, String ou, String l, String emailAddress, boolean includeEmailInDn) {
        String c = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.c").trim();
        String o = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.o").trim();
        this.sig_alg = uk.ngs.ca.tools.property.SysProperty.getValue("ngsca.cert.signature.algorithm").trim();
        
        ou = ou.trim(); 
        if(l != null){
          l = l.trim(); 
        } else {
            l = null;
        }
        this.type = type; 
        this.email = emailAddress; 
        
        if (c.equals("")) {
            throw new IllegalArgumentException("Invalid C");
        }
        if (o.equals("")) {
            throw new IllegalArgumentException("Invalid O");
        }
        if (ou.equals("")) {
            throw new IllegalArgumentException("Invalid OU");
        }
        // Should L be made optional ? 
        //if (L.equals("")) {
        //      throw new IllegalArgumentException("L");
        //}
        this.attrCN = cn.trim(); 
        if (this.attrCN.equals("")) {
            throw new IllegalArgumentException("Invalid CN");
        }

        if (TYPE.HOST.equals(this.type)) {
            if (!EmailValidator.getInstance().isValid(this.email)) {
                throw new IllegalArgumentException("Invalid Email");
            }
        }

        if (TYPE.USER.equals(this.type)) { 
            // Should L be made optional ? 
            if (l==null || l.equals("")) {
                this.attrDN = ("CN=" + this.attrCN + ", OU=" + ou + ", O=" + o + ", C=" + c);
            } else {
                this.attrDN = ("CN=" + this.attrCN + ", L=" + l + ", OU=" + ou + ", O=" + o + ", C=" + c);
            }
        } else { //host certificate
            if (l==null || l.equals("")) {
                if (includeEmailInDn) {
                    this.attrDN = ("emailAddress=" + this.email + ", CN=" + this.attrCN + ", OU=" + ou + ", O=" + o + ", C=" + c);
                } else {
                    this.attrDN = ("CN=" + this.attrCN + ", OU=" + ou + ", O=" + o + ", C=" + c);
                }
            } else {
                if (includeEmailInDn) {
                    this.attrDN = ("emailAddress=" + this.email + ", CN=" + this.attrCN + ", L=" + l + ", OU=" + ou + ", O=" + o + ", C=" + c);
                } else {
                    this.attrDN = ("CN=" + this.attrCN + ", L=" + l + ", OU=" + ou + ", O=" + o + ", C=" + c);
                }
            }
        }
    }*/
}
