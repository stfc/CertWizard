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
           

            request = builder.build(contentSigner);

            StringWriter writer = new StringWriter();
            JcaPEMWriter pemWrite = new JcaPEMWriter(writer);
            pemWrite.writeObject(request);
            pemWrite.close();

            myLogger.debug("[CertificateCreator] createCertificateRequest: successful");
            return writer.toString();
        } catch (IOException | OperatorCreationException ex) {
            myLogger.error("[CertificateCreator] createCertificateRequest: failed. " + ex.toString());
            throw new IllegalStateException("Failed to make PKCS#10", ex);
        }
    }
}
