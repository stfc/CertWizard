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
package uk.ngs.ca.certificate;

import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.ClientInfo;
import org.restlet.data.Header;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.data.Reference;
import org.restlet.ext.xml.DomRepresentation;
import org.restlet.representation.Representation;
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
 * @author xw75 (Xiao Wang)
 */
public class OnlineUserCertRequest {

    private String CSRURL = SysProperty.getValue("uk.ngs.ca.request.csr.url");
    private String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private String MESSAGE = "";
    private boolean isCSRRequestSuccess = false;

    public OnlineUserCertRequest(String csrString, String pin, String email) {
        Client c = RestletClient.getClient();
        Request request = new Request(Method.POST, new Reference(CSRURL), getRepresentation(csrString, pin, email));
        Series<Header> headers = request.getHeaders();
        headers.set("LocalHost", ClientHostName.getHostName());

        //by calling clientinfo to change standard header
        ClientInfo info = new ClientInfo();
        info.setAgent(USERAGENT);
        request.setClientInfo(info);

        Response response = c.handle(request);

        if (response.getStatus().equals(response.getStatus().SUCCESS_CREATED)) {
            MESSAGE = "Your CSR has been submitted to the CA server successfully. \nIt is waiting for the approval and signing by an RA and CA operator.";
            isCSRRequestSuccess = true;
        } else if (response.getStatus().equals(response.getStatus().SUCCESS_ACCEPTED)) {
            try {
                MESSAGE = _getFormattedMessage(response);
                isCSRRequestSuccess = false;
            } catch (Exception ep) {
                ep.printStackTrace();
            }
        } else {

            MESSAGE = "A problem occurred during the submission process. This could be due to a Server side problem.\n"
                    + "Please try again later. If the problem persists, please contact the helpdesk support at \n"
                    + "support@grid-support.ac.uk";
            isCSRRequestSuccess = false;
        }
    }

    private String _getFormattedMessage(Response response) {
        String message = "";

        try {
            Document document = new DomRepresentation(response.getEntity()).getDocument(); //response.getEntityAsDom().getDocument();
            document.getDocumentElement().normalize();
            NodeList nodeLst = document.getElementsByTagName("minor");

            for (int s = 0; s < nodeLst.getLength(); s++) {

                Node fstNode = nodeLst.item(s);

                if (fstNode.getNodeType() == Node.ELEMENT_NODE) {

                    Element fstElmnt = (Element) fstNode;
                    NodeList fstNmElmntLst = fstElmnt.getElementsByTagName("text");

                    Element fstNmElmnt = (Element) fstNmElmntLst.item(0);
                    NodeList fstNm = fstNmElmnt.getChildNodes();

                    message = (((Node) fstNm.item(0)).getNodeValue());
//                      System.out.println("SERVER VERSION NO === : "  + ((Node) fstNm.item(0)).getNodeValue());
                    //img = ((Node) fstNm.item(0)).getNodeValue();
                }
            }

            return message;
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }

    }

    public String getMessage() {
        return MESSAGE;
    }

    public boolean isCSRREquestSuccess() {
        return isCSRRequestSuccess;
    }

    private Representation getRepresentation(String csrString, String pin, String email) {
        DomRepresentation representation;
        try {
            representation = new DomRepresentation(MediaType.APPLICATION_XML);
            Document d = representation.getDocument();

            Element rootElement = d.createElement("CSR");
            d.appendChild(rootElement);

            Element eltName = d.createElement("Request");
            eltName.appendChild(d.createTextNode(csrString));
            rootElement.appendChild(eltName);

            eltName = d.createElement("PIN");
            eltName.appendChild(d.createTextNode(pin));
            rootElement.appendChild(eltName);

            eltName = d.createElement("Email");
            eltName.appendChild(d.createTextNode(email));
            rootElement.appendChild(eltName);

            String _version = SysProperty.getValue("ngsca.certwizard.version");
            eltName = d.createElement("Version");
            eltName.appendChild(d.createTextNode(_version));
            rootElement.appendChild(eltName);

            d.normalizeDocument();
        } catch (Exception ep) {
            ep.printStackTrace();
            return null;
        }
        return representation;
    }
}
