
import java.io.StringReader;
import java.security.interfaces.RSAPublicKey;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMParser;
import uk.ngs.ca.certificate.client.CSRCSR;
import uk.ngs.ca.tools.property.SysProperty;

/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.



 */

/**
 *
 * @author xw75
 */
public class Test {

    public static void main(String[] args ){
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        try {
            SysProperty.setupTrustStore(); // throws IllegalStateException if problem.
            String trustStoreFile = SysProperty.getValue("ngsca.truststore.file");
            String trustStorePath = System.getProperty("user.home");
            trustStorePath = trustStorePath + System.getProperty("file.separator") + ".ca";
            trustStorePath = trustStorePath + System.getProperty("file.separator") + trustStoreFile;

            String password = SysProperty.getValue("ngsca.cert.truststore.password");
            System.setProperty("javax.net.ssl.trustStore", trustStorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", password);
            // System.setProperty("javax.net.ssl.trustStoreType", "PKCS12");
        } catch(Exception ex) {
            javax.swing.JOptionPane.showMessageDialog(null,ex.getMessage(),"Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        CSRCSR csr = new CSRCSR( "773408" );
        String csrString = csr.getCSR();
        try {
            PEMParser pemReader = new PEMParser(new StringReader(csrString));
            Object obj = pemReader.readObject();
            PKCS10CertificationRequest request = (PKCS10CertificationRequest) obj;
            pemReader.close();
            //System.out.println("request = " + request);
            String keyalg = (((RSAPublicKey)request.getPublicKey()).getAlgorithm());
            String sigalg = (request.getSignatureAlgorithm().toString());
            String a = request.getPublicKey().getAlgorithm();
            a = "DSA".equals(a) ? "SHA1withDSA" : "MD5withRSA";

            //System.out.println("public key alg = " + keyalg);
            //System.out.println("signature alg = " + sigalg);
            //System.out.println("a = " + a);
            //  System.out.println(((RSAPublicKey)request.getPublicKey()).toString());
            //  this.modulus.setText(((RSAPublicKey)request.getPublicKey()).getModulus().bitLength());
        } catch (Exception ep) {
            ep.printStackTrace();
        }

    }

}
