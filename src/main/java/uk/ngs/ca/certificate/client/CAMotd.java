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

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Header;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.data.Status;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.util.Series;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class CAMotd {

    public CAMotd() {
    }

    public String getText() {
        String text = null;
        try {
            String csrURL = SysProperty.getValue("uk.ngs.ca.request.ca.motd.text.url");
            Client c = RestletClient.getClient();

            Request request = new Request(Method.GET, new Reference(csrURL));

            Series<Header> headers = request.getHeaders();
            headers.set("LocalHost", ClientHostName.getHostName());
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            Document document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();

            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Motd/text");

            text = (String) expr.evaluate(document, XPathConstants.STRING);

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return text;
        }
    }

    /**
     * Get the latest version of CertWizard supported by the server.
     *
     * @return The latest CertWizard version or null if no version info can be
     * retrieved from the server.
     */
    public String getLatestVersion() {
        String latestVersion = "0.0.0";
        try {
            String csrURL = SysProperty.getValue("uk.ngs.ca.request.ca.url");
            Client c = RestletClient.getClient();
            Request request = new Request(Method.GET, new Reference(csrURL));

            Series<Header> headers = request.getHeaders();
            headers.set("LocalHost", ClientHostName.getHostName());
            org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
            info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
            request.setClientInfo(info);

            Response response = c.handle(request);
            //response.getStatus().
            if (!response.getStatus().equals(Status.SUCCESS_OK)) {
                return "0.0.0";
            }

            Document document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();
            // transform the Document into a String
            document.getDocumentElement().normalize();
            NodeList nodeLst = document.getElementsByTagName("certWizard");

            for (int s = 0; s < nodeLst.getLength(); s++) {

                Node fstNode = nodeLst.item(s);

                if (fstNode.getNodeType() == Node.ELEMENT_NODE) {

                    Element fstElmnt = (Element) fstNode;
                    NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("latestVersion");
                    Element fstNmElmnt = (Element) fstNmElmntLst.item(0);
                    NodeList fstNm = fstNmElmnt.getChildNodes();
                    latestVersion = fstNm.item(0).getNodeValue();
                }
            }

        } catch (Exception ep) {
            ep.printStackTrace();
        } finally {
            return latestVersion;
        }
    }
}
