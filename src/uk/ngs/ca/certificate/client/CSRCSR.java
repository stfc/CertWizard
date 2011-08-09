/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import org.w3c.dom.Document;
import java.io.StringReader;

import java.security.PublicKey;

import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.Response;
import org.restlet.Request;
import org.restlet.data.Method;
import org.restlet.ext.xml.DomRepresentation;

import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class CSRCSR {

    Document document = null;

    public CSRCSR(String reqID) {
        try {
            String csrURL = SysProperty.getValue("uk.ngs.ca.request.csr.reqid.url");
            csrURL = csrURL + "/" + reqID;
            Client c = new Client(Protocol.HTTPS);
            c.setConnectTimeout(SysProperty.getTimeoutMilliSecs());  // in milliseconds (8 secs). TODO: should be editable and stored in .properties file 

            Request request = new Request(Method.GET, new Reference(csrURL));

            Form form = new Form();
            form.add("LocalHost", ClientHostName.getHostName());
            request.getAttributes().put("org.restlet.http.headers", form);
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);

            document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
        }
    }

    public String getCSR() {
        String csr = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/request");

            csr = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return csr;
        }
    }

    public PublicKey getPublicKey() {
        PublicKey key = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/request[1]/text()");
            String csr = (String) expr.evaluate(document, XPathConstants.STRING);
            PEMReader pemReader = new PEMReader(new StringReader(csr));
            Object obj = pemReader.readObject();
            PKCS10CertificationRequest request = (PKCS10CertificationRequest) obj;
            pemReader.close();
            key = request.getPublicKey();
        } catch (Exception ep) {
            ep.printStackTrace();
        }finally{
            return key;
        }
    }

    public String getOwner(){
        String owner = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/owner");

            owner = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return owner;
        }
    }

    public String getRA(){
        String ra = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/DN/RA/OU");
            String _ou = (String) expr.evaluate(document, XPathConstants.STRING);

            expr = xpath.compile("/CSR/DN/RA/L");
            String _l = (String) expr.evaluate(document, XPathConstants.STRING);

            ra = _ou.trim() + " " + _l.trim();

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return ra;
        }
    }

    public String getCN(){
        String cn = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/DN/CN");

            cn = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return cn;
        }
    }

    public String getStatus(){
        String status = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/status");

            status = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return status;
        }
    }

    public String getPIN(){
        String pin = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/PIN");

            pin = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return pin;
        }
    }

    public String getUserEmail() {
        String email = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CSR/useremail");

            email = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return email;
        }
    }
    
}
