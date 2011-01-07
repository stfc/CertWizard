/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.client;

import java.security.PublicKey;
import org.w3c.dom.Document;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Method;

import org.restlet.data.Status;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ResourcesPublicKey {

    private Document document = null;

    String encodedPublicKey = null;

    public ResourcesPublicKey( PublicKey publicKey ){
        this.encodedPublicKey = EncryptUtil.getEncodedPublicKey(publicKey);
    }
    public ResourcesPublicKey( String encodedPublicKey ){
        this.encodedPublicKey = encodedPublicKey;
    }

    public boolean isExist(){
        Document _document = null;
        boolean isExist = false;
        try {
            String resourceURL = SysProperty.getValue("uk.ngs.ca.request.resource.publickey");
            resourceURL = resourceURL + "/" + this.encodedPublicKey;
            Client c = new Client(Protocol.HTTPS);

            Request request = new Request(Method.GET, new Reference(resourceURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            if( response.getStatus().equals(Status.SUCCESS_OK)){
                _document = response.getEntityAsDom().getDocument();
                this.document = _document;
                isExist = true;
            }else{
                isExist = false;
            }

        } catch (Exception ep) {
            ep.printStackTrace();
        }finally{
            return isExist;
        }
    }

    public Document getDocument(){
        return this.document;
    }

}
