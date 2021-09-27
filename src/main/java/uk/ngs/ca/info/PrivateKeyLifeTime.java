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

import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.ClientInfo;
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
public class PrivateKeyLifeTime {

    String CAURL = SysProperty.getValue("uk.ngs.ca.request.ca.maxprivatekeylifetime.url");
    private Document document;

    private void init() {
        Client c = RestletClient.getClient();
        Request request = new Request(Method.GET, new Reference(CAURL));

        Series<Header> headers = request.getHeaders();
        headers.set("PPPK", "this is pppk");
        headers.set("LocalHost", uk.ngs.ca.common.ClientHostName.getHostName());

        //by calling clientinfo to change standard header
        ClientInfo info = new ClientInfo();

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

}
