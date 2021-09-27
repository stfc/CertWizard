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

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author xw75
 */
public class CertificateDownload {

    Document document = null;

    public CertificateDownload(String certID) {
        try {
            String certURL = SysProperty.getValue("uk.ngs.ca.request.certificate.url");
            certURL = certURL + "/" + certID;
            Client c = RestletClient.getClient();

            Request request = new Request(Method.GET, new Reference(certURL));

            Series<Header> headers = request.getHeaders();
            headers.add("LocalHost", ClientHostName.getHostName());
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

}
