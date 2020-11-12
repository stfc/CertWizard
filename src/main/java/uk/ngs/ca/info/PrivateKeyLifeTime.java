/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.info;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;
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

    public PrivateKeyLifeTime() {
        init();
    }

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

    public int getMaxLifeTime() {
        try {
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/Policy/MaxPrivateKeyLifeTime[1]/text()");
            String result = (String) expr.evaluate(document, XPathConstants.STRING);
            return new Integer(result).intValue();
        } catch (Exception ep) {
            ep.printStackTrace();
            return -1;
        }

    }

}
