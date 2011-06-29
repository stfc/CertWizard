/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.io.InputStream;
import java.io.ByteArrayInputStream;

import org.w3c.dom.Document;

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
public class CertificateDownload {

    Document document = null;

    public CertificateDownload(String certID) {
        try {
            String certURL = SysProperty.getValue("uk.ngs.ca.request.certificate.url");
            certURL = certURL + "/" + certID;
            Client c = new Client(Protocol.HTTPS);
            Request request = new Request(Method.GET, new Reference(certURL));

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

    public X509Certificate getCertificate() {
        X509Certificate certificate = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/X509Certificate");

            String result = (String) expr.evaluate(document, XPathConstants.STRING);

            InputStream inputStream = new ByteArrayInputStream(result.getBytes());

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certificate = (X509Certificate) cf.generateCertificate(inputStream);
            inputStream.close();
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return certificate;
        }
    }

    public String getUserEmail() {
        String email = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/useremail");
            email = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return email;
        }
    }

    public String getRole() {
        String role = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/role");
            role = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return role;
        }
    }

    public String getRA() {
        String ra = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/RA");
            ra = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return ra;
        }
    }

    public String getStatus() {
        String status = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/status");
            status = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return status;
        }
    }

    public String getOwner() {
        String owner = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/owner");
            owner = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return owner;
        }
    }

    public String getSponsor() {
        String sponsor = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/sponsor");
            sponsor = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return sponsor;
        }
    }

    public String getPublicKey() {
        String key = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/publickey");
            key = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return key;
        }
    }

    public String getStartDate() {
        String date = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/startdate");
            date = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return date;
        }
    }

    public String getEndDate() {
        String date = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/enddate");
            date = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return date;
        }
    }

    public String getLifeDays() {
        String days = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/lifedays");
            days = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return days;
        }
    }

    public String getRenew() {
        String renew = null;
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/certificate/renew");
            renew = (String) expr.evaluate(document, XPathConstants.STRING);
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return renew;
        }
    }

    public String getCN() {
        String dn = getOwner();
        return _retrieveDataFromDN(dn, "CN=");
    }

    private String _retrieveDataFromDN(String dn, String data) {
        int index = dn.indexOf(data);
        index = index + data.length();
        String result = dn.substring(index);
        int _index = result.indexOf(",");
        if (_index != -1) {
            result = result.substring(0, _index);
        }
        result = result.trim();

        return result;
    }



    public boolean isCertificateExpired(){
        X509Certificate certificate = getCertificate();
        try{
            certificate.checkValidity();
            return false;
        }catch(Exception ep){
            return true;
        }
    }

}
