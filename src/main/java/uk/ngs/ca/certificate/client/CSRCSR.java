/*
 * CertWizard - UK eScience CA Certificate Management Client
 * Copyright (C) 2021 UKRI-STFC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package uk.ngs.ca.certificate.client;

import java.io.StringReader;
import java.security.PublicKey;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Header;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.RestletClient;
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
            Client c = RestletClient.getClient();

            Request request = new Request(Method.GET, new Reference(csrURL));

            Series<Header> headers = request.getHeaders();
            headers.set("LocalHost", ClientHostName.getHostName());
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
            PEMParser pemReader = new PEMParser(new StringReader(csr));
            Object obj = pemReader.readObject();
            PKCS10CertificationRequest r = (PKCS10CertificationRequest) obj;
            JcaPKCS10CertificationRequest request = new JcaPKCS10CertificationRequest(r);
            pemReader.close();
            key = request.getPublicKey();
        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return key;
        }
    }

    public String getOwner() {
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

    public String getRA() {
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

    public String getCN() {
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

    public String getStatus() {
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

    public String getPIN() {
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
