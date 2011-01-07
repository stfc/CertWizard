/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.client;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Method;
import org.restlet.data.Status;
import org.restlet.data.Parameter;

import org.w3c.dom.NodeList;
import org.w3c.dom.Document;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.math.BigInteger;

import java.util.Date;

import uk.ngs.ca.certificate.management.RequestPendingInfo;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class CARARequestsPending {

    private long cert_id = -1;
    private String PENDINGURL = SysProperty.getValue("uk.ngs.ca.request.ca.ra.requests.pending.url");
    private String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");
    private PrivateKey privateKey;
    private Document document = null;

    public CARARequestsPending(PrivateKey privateKey, long cert_id) {
        this.privateKey = privateKey;
        this.cert_id = cert_id;
    }

    //original method
    public RequestPendingInfo[] _getRequestPendingInfos( ){
        RequestPendingInfo[] infos = null;
        try{
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/RA/requests/pending/CSR");
            Object result = expr.evaluate(document, XPathConstants.NODESET);
            NodeList nodes = (NodeList) result;
            int size = nodes.getLength();
            infos = new RequestPendingInfo[ size ];
            for( int i = 0; i < size; i ++ ){
                infos[ i ] = new RequestPendingInfo( );
                int _length = nodes.item(i).getChildNodes().getLength();

                for( int j = 0; j < _length; j++){   
                    String nodeName = nodes.item(i).getChildNodes().item(j).getNodeName();   
                    String nodeContent = nodes.item(i).getChildNodes().item(j).getTextContent();
                    if( nodeName.equals("id") ){       
                        infos[ i ].setSerialNumber(nodeContent);   
                    }else if( nodeName.equals("type") ){       
                        infos[ i ].setType(nodeContent);   
                    }else if( nodeName.contains("bulk") ){       
                        infos[ i ].setBulk(nodeContent);   
                    }else if( nodeName.equals("DN") ){       
                        infos[ i ].setEncodedDN(nodeContent);   
                    }else if( nodeName.equals("EPIN") ){       
                        infos[ i ].setPIN(nodeContent);   
                    }else if( nodeName.equals("date") ){       
                        infos[ i ].setStartDate(nodeContent);   
                    }else if( nodeName.equals("sponsor") ){       
                        infos[ i ].setSponsor(nodeContent);   
                    }else{       
                        infos[ i ].setDescription("unknown node");   
                    }
                }
                CSROwner csrOwner = new CSROwner( infos[ i ].getSerialNumber( ) );
                infos[ i ].setDN(csrOwner.getOwner());
                CSREmail csrEmail = new CSREmail( infos[ i ].getSerialNumber( ) );
                infos[ i ].setUserEmail(csrEmail.getEmail());
                CSRPublicKey csrPublicKey = new CSRPublicKey( infos[ i ].getSerialNumber( ) );
                infos[ i ].setPublicKey(csrPublicKey.getPublicKey());
                CSRRole csrRole = new CSRRole( infos[ i ].getSerialNumber() );
                infos[ i ].setRole( csrRole.getRole() );
                CSRDNCN csrDNCN = new CSRDNCN( infos[ i ].getSerialNumber() );
                infos[ i ].setCN(csrDNCN.getCN());
                String displayTitle = infos[ i ].getType() + ": " + infos[ i ].getDN();
                infos[ i ].setDisplayTitle(displayTitle);

            }
        }catch( Exception ep ){
            ep.printStackTrace();
        }finally{
            return infos;
        }


    }

    public RequestPendingInfo[] getRequestPendingInfos( ){
        RequestPendingInfo[] infos = null;
        try{
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/CA/RA/requests/pending/CSR");
            Object result = expr.evaluate(document, XPathConstants.NODESET);
            NodeList nodes = (NodeList) result;
            int size = nodes.getLength();

            expr = xpath.compile("/CA/RA/requests/pending/certificate");
            result = expr.evaluate(document, XPathConstants.NODESET);
            NodeList _nodes = (NodeList) result;
            int _size = _nodes.getLength();

            infos = new RequestPendingInfo[ size + _size ];
            for( int i = 0; i < size; i ++ ){
                infos[ i ] = new RequestPendingInfo( );
                int _length = nodes.item(i).getChildNodes().getLength();

                for( int j = 0; j < _length; j++){
                    String nodeName = nodes.item(i).getChildNodes().item(j).getNodeName();
                    String nodeContent = nodes.item(i).getChildNodes().item(j).getTextContent();
                    if( nodeName.equals("id") ){
                        infos[ i ].setSerialNumber(nodeContent);
                    }else if( nodeName.equals("type") ){
                        infos[ i ].setType(nodeContent);
                    }else if( nodeName.contains("bulk") ){
                        infos[ i ].setBulk(nodeContent);
                    }else if( nodeName.equals("DN") ){
                        infos[ i ].setEncodedDN(nodeContent);
                    }else if( nodeName.equals("EPIN") ){
                        infos[ i ].setPIN(nodeContent);
                    }else if( nodeName.equals("date") ){
                        infos[ i ].setStartDate(nodeContent);
                    }else if( nodeName.equals("sponsor") ){
                        infos[ i ].setSponsor(nodeContent);
                    }else{
                        infos[ i ].setDescription("unknown node");
                    }
                }
                CSRCSR csr = new CSRCSR( infos[ i ].getSerialNumber() );
                infos[ i ].setDN(csr.getOwner());
                infos[ i ].setUserEmail( csr.getUserEmail() );
                CSRPublicKey csrPublicKey = new CSRPublicKey( infos[ i ].getSerialNumber( ) );
                infos[ i ].setPublicKey(csrPublicKey.getPublicKey());
                CSRRole csrRole = new CSRRole( infos[ i ].getSerialNumber() );
                infos[ i ].setRole( csrRole.getRole() );

                infos[ i ].setCN(csr.getCN());
                String displayTitle = infos[ i ].getType() + ": " + infos[ i ].getDN();
                infos[ i ].setDisplayTitle(displayTitle);

            }
            for( int i = 0; i < _size; i ++ ){
                infos[ i + size ] = new RequestPendingInfo( );
                int _length = _nodes.item(i).getChildNodes().getLength();

                for( int j = 0; j < _length; j++){
                    String nodeName = _nodes.item(i).getChildNodes().item(j).getNodeName();
                    String nodeContent = _nodes.item(i).getChildNodes().item(j).getTextContent();
                    if( nodeName.equals("id") ){
                        infos[ i + size ].setSerialNumber(nodeContent);
                    }else if( nodeName.equals("type") ){
                        infos[ i + size ].setType(nodeContent);
                    }else if( nodeName.equals("DN") ){
                        infos[ i + size ].setEncodedDN(nodeContent);
                    }else if( nodeName.equals("EPIN") ){
                        infos[ i + size ].setPIN(nodeContent);
                    }else if( nodeName.equals("date") ){
                        infos[ i + size ].setStartDate(nodeContent);
                    }else if( nodeName.equals("sponsor") ){
                        infos[ i + size ].setSponsor(nodeContent);
                    }else{
                        infos[ i + size ].setDescription("unknown node");
                    }
                }
                CertificateDownload certDownload = new CertificateDownload( infos[ i + size ].getSerialNumber( ) );
                infos[ i + size ].setDN(certDownload.getOwner());
                infos[ i + size ].setUserEmail(certDownload.getUserEmail());
                infos[ i + size ].setPublicKey(certDownload.getPublicKey());
                infos[ i + size ].setRole( certDownload.getRole() );
                infos[ i + size ].setCN( certDownload.getCN());
                String displayTitle = infos[ i + size ].getType() + ": " + infos[ i + size ].getDN();
                infos[ i + size ].setDisplayTitle(displayTitle);
            }
        }catch( Exception ep ){
            ep.printStackTrace();
        }finally{
            return infos;
        }
    }

    public boolean doGet() {
        String pendingURL = this.PENDINGURL + "/" + this.cert_id + "/requests/pending";

        Client client = new Client(Protocol.HTTPS);
        Request request = new Request(Method.GET, new Reference(pendingURL));
        Form form = new Form();
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", ClientHostName.getHostName());
        request.getAttributes().put("org.restlet.http.headers", form);
//by calling clientinfo to change standard header
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(this.USERAGENT);
        request.setClientInfo(info);

        Response response = client.handle(request);

        Status _status = response.getStatus();
        //we will do second post
        if (_status.equals(Status.CLIENT_ERROR_UNAUTHORIZED)) {
            org.restlet.util.Series<org.restlet.data.Parameter> headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
            Parameter _realmP = headers.getFirst("realm");
            Parameter _nonceP = headers.getFirst("nonce");
            Parameter _keyidP = headers.getFirst("keyid");
            Parameter _opaqueP = headers.getFirst("opaque");

            //we will do the response action from here.
            if (_opaqueP == null) {

                String _keyid = _keyidP.getValue();
                int index = _keyid.indexOf(".");
                String m = _keyid.substring(0, index).toUpperCase();
                String q = getPrivateExponent(privateKey);

                String _nonce = _nonceP.getValue() + ":" + new Date().getTime();
                _nonce = _nonce.toLowerCase();
                String c = asciiToHex(_nonce);
                c = c.toUpperCase();

                BigInteger b_c = new BigInteger(c, 16);
                BigInteger b_q = new BigInteger(q, 16);
                BigInteger b_m = new BigInteger(m, 16);
                BigInteger b_response = b_c.modPow(b_q, b_m);
                String _response = b_response.toString(16);

                Form _form = new Form();
                _form.add("PPPK", "this is pppk");
                _form.add("LocalHost", ClientHostName.getHostName());
                _form.add("keyid", _keyid);
                _form.add("realm", _realmP.getValue());
                _form.add("response", _response);
                client = new Client(Protocol.HTTPS);
                request = new Request(Method.GET, new Reference(pendingURL));
                request.getAttributes().put("org.restlet.http.headers", _form);
                org.restlet.data.ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

            } else {
                //we will do cookie thing from here
                Form _form = new Form();
                _form.add("PPPK", "this is pppk");
                _form.add("LocalHost", ClientHostName.getHostName());
                _form.add("opaque", _opaqueP.getValue());
                /* */
                client = new Client(Protocol.HTTPS);
//please note you have to call getRepresentation() again, otherwise it will be null. Why???
                request = new Request(Method.GET, new Reference(pendingURL));
                request.getAttributes().put("org.restlet.http.headers", _form);
                org.restlet.data.ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(this.USERAGENT);
                request.setClientInfo(_info);
                response = client.handle(request);

                org.restlet.util.Series<org.restlet.data.Parameter> _headers = (org.restlet.util.Series) response.getAttributes().get("org.restlet.http.headers");
            }

            if (response.getStatus().equals(Status.SUCCESS_OK)) {
                //200
                try {
                    document = response.getEntityAsDom().getDocument();
                } catch (Exception ep) {
                    ep.printStackTrace();
                    return false;
                }
                return true;

            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    private String getPrivateExponent(PrivateKey _privateKey) {
        int index = _privateKey.toString().indexOf("private exponent:");
        index = index + 17;
        String subString = _privateKey.toString().substring(index);
        index = subString.indexOf("\n");
        subString = subString.substring(0, index);
        subString = subString.trim();
        return subString;
    }

    private String asciiToHex(String ascii) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < ascii.length(); i++) {
            hex.append(Integer.toHexString(ascii.charAt(i)));
        }
        return hex.toString();
    }

}
