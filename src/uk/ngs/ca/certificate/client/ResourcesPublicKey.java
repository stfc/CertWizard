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
import org.w3c.dom.Document;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75 Xiao Wang
 */
public class ResourcesPublicKey {

    private Document document = null;
    private String encodedPublicKey = null;

    public ResourcesPublicKey( PublicKey publicKey ){
        this.encodedPublicKey = EncryptUtil.getEncodedPublicKey(publicKey);
    }
   
    public boolean isExist(){
        Document _document ;
        boolean isExist = false;
        try {

            // call CA server and ask 'do you know about a certficate with this pub key'
            // url = /resources/resource/publickey/<base64encodedpubkey>
            String resourceURL = SysProperty.getValue("uk.ngs.ca.request.resource.publickey");
            resourceURL = resourceURL + "/" + this.encodedPublicKey;
            Client c = new Client(Protocol.HTTPS);
            c.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 


            Request request = new Request(Method.GET, new Reference(resourceURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            if( response.getStatus().equals(Status.SUCCESS_OK)){
                _document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();
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
