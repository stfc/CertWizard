/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.client;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.w3c.dom.Document;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;

import org.restlet.Client;
import org.restlet.data.Protocol;
import org.restlet.data.Reference;
import org.restlet.data.Form;
import org.restlet.data.Response;
import org.restlet.data.Request;
import org.restlet.data.Method;

import org.bouncycastle.util.encoders.Base64;

import org.restlet.data.Parameter;
import org.restlet.data.Status;
import org.w3c.dom.NodeList;
import uk.ngs.ca.certificate.management.RASearchInfo;
import uk.ngs.ca.common.ClientHostName;
import uk.ngs.ca.common.EncryptUtil;
import uk.ngs.ca.tools.property.SysProperty;

/**
 *
 * @author xw75
 */
public class RASearch {

    private PrivateKey privateKey = null;

    private String name = null;
    private String ra = null;
    private String useremail = null;
    private String status = null;
    private String role = null;
    private String encodedPublicKey = null;

    private Document document = null;

    private String SEARCHURL = SysProperty.getValue("uk.ngs.ca.ra.search.url");
    private String USERAGENT = SysProperty.getValue("uk.ngs.ca.request.useragent");

    public RASearch( PrivateKey privateKey, String encodedPublicKeyString, String name, String ra, String useremail, String status, String role ){
        this.privateKey = privateKey;
        this.encodedPublicKey = encodedPublicKeyString;
        this.name = name;
        this.useremail = useremail;
        this.ra = ra;
        this.status = status;
        this.role = role;
    }
    
    public boolean doGet(){

        String keyid = EncryptUtil.getKeyid( this.encodedPublicKey );

        String parameters = "";
        if( this.name != null ){
            parameters = parameters + "name=" + this.name + ",";
        }
        if( this.useremail != null ){         
            parameters = parameters + "useremail=" + this.useremail + ",";
        }            
        if( this.ra != null ){         
            parameters = parameters + "ra=" + this.ra + ",";
        }            
        if( this.status != null ){        
            parameters = parameters + "status=" + this.status + ",";
        }            
        if( this.role != null ){        
            parameters = parameters + "role=" + this.role + ",";
        }
        String searchURL = this.SEARCHURL + "/" + parameters;

        Client client = new Client(Protocol.HTTPS);
        Request request = new Request(Method.GET, new Reference(searchURL));

        Form form = new Form();
        form.add("PPPK", "this is pppk");
        form.add("LocalHost", ClientHostName.getHostName());
        form.add("keyid", keyid);
        request.getAttributes().put("org.restlet.http.headers", form);
        org.restlet.data.ClientInfo info = new org.restlet.data.ClientInfo();
        info.setAgent(SysProperty.getValue("uk.ngs.ca.request.useragent"));
        request.setClientInfo(info);
        Response response = client.handle(request);
        Status _status = response.getStatus();

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
                request = new Request(Method.GET, new Reference(searchURL));
                request.getAttributes().put("org.restlet.http.headers", _form);
                org.restlet.data.ClientInfo _info = new org.restlet.data.ClientInfo();
                _info.setAgent(this.USERAGENT);
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
                request = new Request(Method.GET, new Reference(searchURL));
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
                    this.document = response.getEntityAsDom().getDocument();
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

    public RASearchInfo[] getRASearchInfos( ){
        RASearchInfo[] infos = null;
        try{
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression expr = xpath.compile("/resources/resource/certificates/certificate");
            Object result = expr.evaluate(this.document, XPathConstants.NODESET);
            NodeList nodes = (NodeList) result;
            int size = nodes.getLength();
            infos = new RASearchInfo[ size ];
            for( int i = 0; i < size; i ++ ){
                infos[ i ] = new RASearchInfo( );
                int _length = nodes.item(i).getChildNodes().getLength();
                for( int j = 0; j < _length; j++){
                    String nodeName = nodes.item(i).getChildNodes().item(j).getNodeName();
                    String nodeContent = nodes.item(i).getChildNodes().item(j).getTextContent();
                    if( nodeName.equals("id") ){
                        infos[ i ].setSerialNumber(nodeContent);
                    }else if( nodeName.equals("status") ){
                        infos[ i ].setStatus(nodeContent);
                    }else if( nodeName.contains("useremail") ){
                        infos[ i ].setUserEmail(nodeContent);
                    }else if( nodeName.equals("role") ){
                        infos[ i ].setRole(nodeContent);
                    }else if( nodeName.equals("owner") ){
                        infos[ i ].setOwner(nodeContent);
                    }else if( nodeName.equals("startdate") ){
                        infos[ i ].setStartDate(nodeContent);
                    }else if( nodeName.equals("enddate") ){
                        infos[ i ].setEndDate(nodeContent);
                    }else if( nodeName.equals("lifedays") ){
                        infos[ i ].setLifeDays(nodeContent);
                    }else if( nodeName.equals("renew") ){
                        infos[ i ].setRenew(nodeContent);
                    }else if( nodeName.equals("CN") ){
                        infos[ i ].setCN(nodeContent);
                    }else if( nodeName.equals("RA") ){
                        NodeList _nodes = nodes.item(i).getChildNodes().item(j).getChildNodes();
                        int _size = _nodes.getLength();
                        for( int k = 0; k < _size; k++ ){
                            String _nodeName = _nodes.item(k).getNodeName();
                            String _nodeContent = _nodes.item(k).getTextContent();
                            if( _nodeName.equals("OU") ){
                                infos[ i ].setOU(_nodeContent);
                            }else if( _nodeName.equals("L") ){
                                infos[ i ].setL(_nodeContent);
                            }
                        }
                    }
                }
            }
        }catch( Exception ep ){
            ep.printStackTrace();
        }finally{
            return infos;
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
/*
    public static void main( String[] args ){
       java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        String message = SysProperty.setupTrustStore();
        if (message == null) {
            String trustStoreFile = SysProperty.getValue("ngsca.truststore.file");
            String trustStorePath = System.getProperty("user.home");
            trustStorePath = trustStorePath + System.getProperty("file.separator") + ".ca";
            trustStorePath = trustStorePath + System.getProperty("file.separator") + trustStoreFile;

            String password = SysProperty.getValue("ngsca.cert.truststore.password");
            System.setProperty("javax.net.ssl.trustStore", trustStorePath);
            System.setProperty("javax.net.ssl.trustStorePassword", password);
        } else {
            javax.swing.JOptionPane.showMessageDialog(null,message,"Error", javax.swing.JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        String pswd = "mypassword";
        try {
//        uk.ngs.ca.common.ClientKeyStore k = new uk.ngs.ca.common.ClientKeyStore(pswd.toCharArray());
//        java.security.KeyStore store = k.getKeyStore();
//        java.util.Enumeration<String> aliases = store.aliases();

            uk.ngs.ca.common.ClientCertKeyStore k = new uk.ngs.ca.common.ClientCertKeyStore(pswd.toCharArray());
            java.security.KeyStore store = k.getCertKeyStore();
            java.util.Enumeration<String> aliases = store.aliases();

            while( aliases.hasMoreElements()){
            String alias = aliases.nextElement();
            System.out.println("alias = " + alias);

            //            PrivateKey prikey = k.getPrivateKey(alias);
            //            PublicKey pubkey = k.getPublicKey(alias);
            X509Certificate cert = (X509Certificate) store.getCertificate(alias);
            String dn = cert.getSubjectDN().getName();
            System.out.println("dn = " + dn);
            }

            PrivateKey prikey = (PrivateKey) store.getKey("1288799149896", pswd.toCharArray());
            X509Certificate cert = (X509Certificate) store.getCertificate("1288799149896");
            PublicKey pubkey = cert.getPublicKey();
            String encodedPubKeyString = EncryptUtil.getEncodedPublicKey(pubkey);

//            RASearch s = new RASearch( prikey, encodedPubKeyString, "xiao wang", "CLRC DL", "xiao.wang@stfc.ac.uk","REVOKED", "CA Operator" );
            RASearch s = new RASearch( prikey, encodedPubKeyString, null, "ALL", null, "ALL", null );

            boolean b = s.doGet();
            System.out.println( "GET result = " + b);
            RASearchInfo[] infos = s.getRASearchInfos();
            System.out.println("size = " + infos.length);

            for( int i = 0; i < infos.length; i++){
                String owner = infos[ i ].getOwner();
                String serial = infos[ i ].getSerialNumber();
                String status = infos[i].getStatus();
                String role = infos[ i ].getRole();
                System.out.println("[" + i + "], owner = " + owner + ", serial = " + serial + ", status = " + status + ", role = " + role);
            }
        } catch (Exception ep) {
            ep.printStackTrace();
        }
//        DNRole d = new DNRole( "CN=xiao wang,L=DL,OU=CLRC,O=eScienceDev,C=UK" );
//        System.out.println("role = " + d.getRole());
    }
*/
    
}
