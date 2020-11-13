/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import java.security.PublicKey;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.*;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75 Xiao Wang
 */
public class ResourcesPublicKey {

    /* 
     * Returned Document has the form:
     <resources>
       <resource>
        <publickey>+z8uM1DvrAKc3VRSFmY7M/Whr9OTbuqv0AInjw4s6aVm/QG1EPU3pFwIDAQAB...elided...</publickey>
        <CSRs>
        </CSRs>
            <certificates>
              <certificate>
                <id>3510</id>
                <X509Certificate>-----BEGIN CERTIFICATE-----...elided...-----END CERTIFICATE-----</X509Certificate>
                <status>VALID</status>
                <useremail>some.body@stfc.ac.uk</useremail>
                <role>RA Operator</role>
                <RA><OU>CLRC</OU><L>DL</L></RA>
                <owner>CN=some body,L=DL,OU=CLRC,O=eScienceDev,C=UK</owner>
                <startdate>23/04/2013</startdate>
                <enddate>20/10/2013</enddate>
                <lifedays>171</lifedays>
                <renew>20/10/2013</renew>
              </certificate>
            </certificates>
        <CCRs/>
        <CRRs>...</CRRs>
        </resource>
     </resources>
     */
    private Document document = null;
    private String encodedPublicKey = null;

    public ResourcesPublicKey(PublicKey publicKey) {
        this.encodedPublicKey = EncryptUtil.getEncodedPublicKey(publicKey);
    }

    public boolean isExist() {
        Document _document;
        boolean isExist = false;
        try {

            // call CA server and ask 'do you know about a certficate with this pub key'
            // url = /resources/resource/publickey/<base64encodedpubkey>
            String resourceURL = SysProperty.getValue("uk.ngs.ca.request.resource.publickey");
            resourceURL = resourceURL + "/" + this.encodedPublicKey;
            //System.out.println("publickeyresourceurl: "+resourceURL);
            Client c = RestletClient.getClient();

            Request request = new Request(Method.GET, new Reference(resourceURL));

            Series<Header> headers = request.getHeaders();
            headers.set("LocalHost", ClientHostName.getHostName());
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            if (response.getStatus().equals(Status.SUCCESS_OK)) {
                _document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();
                this.document = _document;
                isExist = true;
            } else {
                isExist = false;
            }

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return isExist;
        }
    }

    public Document getDocument() {
        return this.document;
    }

}
