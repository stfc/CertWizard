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
package uk.ngs.ca.info;

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
import org.restlet.util.Series;
import org.w3c.dom.Document;
import uk.ngs.ca.common.RestletClient;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class ExpiredReKey {

    String CAURL = SysProperty.getValue("uk.ngs.ca.request.ca.maxexpiredrekey.url");
    private Document document;

    public ExpiredReKey() {
        init();
    }

    private void init() {
        Client c = RestletClient.getClient();
        Request request = new Request(Method.GET, new Reference(CAURL));

        Series<Header> headers = request.getHeaders();
        headers.set("PPPK", "this is pppk");
        headers.set("LocalHost", uk.ngs.ca.common.ClientHostName.getHostName());

        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();

        info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));

        request.setClientInfo(info);
        Response response = c.handle(request);

        try {
            String responseValue = response.getEntity().getText();
            javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder db = dbf.newDocumentBuilder();
            org.xml.sax.InputSource is = new org.xml.sax.InputSource();
            is.setCharacterStream(new java.io.StringReader(responseValue));

            document = db.parse(is);
        } catch (Exception ep) {
            ep.printStackTrace();

        }
    }

    public int getMaxReKeyTime() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Policy/MaxExpiredReKey[1]/text()");
            String result = (String) expr.evaluate(document, XPathConstants.STRING);
            return new Integer(result).intValue();
        } catch (Exception ep) {
            ep.printStackTrace();
            return -1;
        }

    }

}
