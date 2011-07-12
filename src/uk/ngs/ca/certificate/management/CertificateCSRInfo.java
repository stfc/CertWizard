/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathConstants;


import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.w3c.dom.Node;
import org.w3c.dom.Element;


import uk.ngs.ca.certificate.client.CertificateDownload;
import uk.ngs.ca.certificate.client.ResourcesPublicKey;
import uk.ngs.ca.common.ClientCertKeyStore;
import uk.ngs.ca.common.ClientKeyStore;
import uk.ngs.ca.common.EncryptUtil;

/**
 *
 * @author xw75
 */
public class CertificateCSRInfo {

    private String owner = null;
    private String role = null;
    private String status = null;
    private String useremail = null;
    private String id = null;
    private String startdate = null;
    private String enddate = null;
    private String lifedays = null;
    private String renew = null;
    private String description = null;
    private boolean isCSR = false;
    private String publickey = null;

    public CertificateCSRInfo() {
    }

    public CertificateCSRInfo(PublicKey _publicKey) {
        this.publickey = EncryptUtil.getEncodedPublicKey(_publicKey);
        init();
    }

    public void setPublickey(String publickey) {
        this.publickey = publickey;
    }

    public void setIsCSR(boolean isCSR) {
        this.isCSR = isCSR;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public void setRole( String role ){
        this.role = role;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public void setUserEmail(String useremail) {
        this.useremail = useremail;
    }

    public void setId(String id) {
        this.id = id;
    }

    public void setStartDate(String startdate) {
        this.startdate = startdate;
    }

    public void setEndDate(String enddate) {
        this.enddate = enddate;
    }

    public void setLifeDays(String lifedays) {
        this.lifedays = lifedays;
    }

    public void setRenew(String renew) {
        this.renew = renew;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getPublickey() {
        return this.publickey;
    }

    public boolean getIsCSR() {
        return this.isCSR;
    }

    public String getOwner() {
        return this.owner;
    }

    public String getRole(){
        return this.role;
    }

    public String getStatus() {
        return this.status;
    }

    public String getUserEmail() {
        return this.useremail;
    }

    public String getId() {
        return this.id;
    }

    public String getStartDate() {
        return this.startdate;
    }

    public String getEndDate() {
        return this.enddate;
    }

    public String getLifeDays() {
        return this.lifedays;
    }

    public String getRenew() {
        return this.renew;
    }

    public String getDescription() {
        return this.description;
    }

    /**
     * Contact the server using this.publicKey as the identifier, and update
     * the state of this CertificateCSRInfo instance (either cert or csr).
     * Called from one of the constructors
     */
    private void init() {
        try {           
            // we assume that one publickey only map one certificate and done CSR.
            ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey(this.publickey);
            resourcesPublicKey.isExist();
            Document doc = resourcesPublicKey.getDocument();
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression getCertificateExpr = xpath.compile("/resources/resource/certificates/certificate");
            Object result = getCertificateExpr.evaluate(doc, XPathConstants.NODESET);
            NodeList certificateNodes = (NodeList) result;
            if (certificateNodes.getLength() == 0) {
                XPath _xpath = XPathFactory.newInstance().newXPath();
                XPathExpression getCSRsExpr = _xpath.compile("/resources/resource/CSRs/CSR");
                Object _result = getCSRsExpr.evaluate(doc, XPathConstants.NODESET);
                NodeList csrNodes = (NodeList) _result;
                if ((csrNodes.getLength() != 0)) {
                    // iterate csr nodes and update this.state accordingly
                    for (int i = 0; i < csrNodes.getLength(); i++) {
                        Node _csrNode = csrNodes.item(i);
                        if (_csrNode.getNodeType() == Node.ELEMENT_NODE) {
                            Element _csrElement = (Element) _csrNode;

                            NodeList _statusList = _csrElement.getElementsByTagName("status");
                            Element _statusElement = (Element) _statusList.item(0);
                            String _status = _statusElement.getChildNodes().item(0).getTextContent();
                            if ((!_status.equals("ARCHIVED")) || (!_status.equals("DELETED"))) {
                                //if (!_status.equals(this.getStatus())) {
                                    NodeList _idList = _csrElement.getElementsByTagName("id");
                                    Element _idElement = (Element) _idList.item(0);
                                    String _id = _idElement.getChildNodes().item(0).getTextContent();

                                    NodeList _ownerList = _csrElement.getElementsByTagName("owner");
                                    Element _ownerElement = (Element) _ownerList.item(0);
                                    String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                                    NodeList _roleList = _csrElement.getElementsByTagName("role");
                                    Element _roleElement = (Element) _roleList.item(0);
                                    String _role = _roleElement.getChildNodes().item(0).getTextContent();

                                    NodeList _useremailList = _csrElement.getElementsByTagName("useremail");
                                    Element _useremailElement = (Element) _useremailList.item(0);
                                    String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                                    this.setIsCSR(true);
                                    this.setOwner(_owner);
                                    this.setRole(_role);
                                    this.setUserEmail(_useremail);
                                    this.setId(_id);
                                    this.setStatus(_status);

                                    if (_status.equals("NEW")) {
                                        String _description = "Your certificate has been submitted and is waiting for the approve.";
                                        this.setDescription(_description);
                                    }
                                    if (_status.equals("RENEW")) {
                                        String _description = "Your renewal certificate has been submitted and is waiting for the approve.";
                                        this.setDescription(_description);
                                    }
                                    if (_status.equals("APPROVED")) {
                                        String _description = "Your certificate has been approved and is waiting for CA operator to sign.";
                                        this.setDescription(_description);
                                    }
                                //}
                            }
                        }
                    }
                }
            } else {
                // iterate certificate nodes and update this.state accordingly
                for (int i = 0; i < certificateNodes.getLength(); i++) {
                    Node _certNode = certificateNodes.item(i);
                    if (_certNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element _certElement = (Element) _certNode;

                        NodeList _idList = _certElement.getElementsByTagName("id");
                        Element _idElement = (Element) _idList.item(0);
                        String _id = _idElement.getChildNodes().item(0).getTextContent();

                        NodeList _statusList = _certElement.getElementsByTagName("status");
                        Element _statusElement = (Element) _statusList.item(0);
                        String _status = _statusElement.getChildNodes().item(0).getTextContent();

                        NodeList _ownerList = _certElement.getElementsByTagName("owner");
                        Element _ownerElement = (Element) _ownerList.item(0);
                        String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                        NodeList _roleList = _certElement.getElementsByTagName("role");
                        Element _roleElement = (Element) _roleList.item(0);
                        String _role = _roleElement.getChildNodes().item(0).getTextContent();

                        NodeList _useremailList = _certElement.getElementsByTagName("useremail");
                        Element _useremailElement = (Element) _useremailList.item(0);
                        String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                        NodeList _startdateList = _certElement.getElementsByTagName("startdate");
                        Element _startdateElement = (Element) _startdateList.item(0);
                        String _startdate = _startdateElement.getChildNodes().item(0).getTextContent();

                        NodeList _enddateList = _certElement.getElementsByTagName("enddate");
                        Element _enddateElement = (Element) _enddateList.item(0);
                        String _enddate = _enddateElement.getChildNodes().item(0).getTextContent();

                        NodeList _lifedaysList = _certElement.getElementsByTagName("lifedays");
                        Element _lifedaysElement = (Element) _lifedaysList.item(0);
                        String _lifedays = _lifedaysElement.getChildNodes().item(0).getTextContent();

                        NodeList _renewList = _certElement.getElementsByTagName("renew");
                        Element _renewElement = (Element) _renewList.item(0);
                        String _renew = _renewElement.getChildNodes().item(0).getTextContent();

                        this.setIsCSR(false);
                        this.setOwner(_owner);
                        this.setRole(_role);
                        this.setStatus(_status);
                        this.setUserEmail(_useremail);
                        this.setId(_id);
                        this.setStartDate(_startdate);
                        this.setEndDate(_enddate);
                        this.setLifeDays(_lifedays);
                        this.setRenew(_renew);
                    }
                }
            }
        } catch (Exception ep) {
            ep.printStackTrace();
        }

    }

    /*
     * Contact the server using this.publicKey as the identifier, and update
     * the state of this CertificateCSRInfo instance if the status of the cert or csr 
     * has changed. For certificates, if the status has newly changed to 'VALID', then
     * save the downloaded certificate and the corresponding private key from cakeystore.pkcs12
     * as a new entry in cacertkeystore.pkcs12 (only if they don't
     * already exist in cacertkeystore).
     * This method is called from MainWindowPanel when selecting jcombobox.
     */
    public boolean update(char[] passphrase) {
        if (this.publickey == null) {
            return false;
        }
        try {   
            // we assume that one publickey only map one certificate and done CSR.
            // bad bad code - repeated in init?
            System.out.println("update yes dave.......................");

            // get the latest state of the the cert with this.publickey from the
            // server.
            ResourcesPublicKey resourcesPublicKey = new ResourcesPublicKey(this.publickey);
            // need to force invokation of isExist() even if the result is not checked.
            resourcesPublicKey.isExist();

            Document doc = resourcesPublicKey.getDocument();
            XPath xpath = XPathFactory.newInstance().newXPath();
            XPathExpression getCertificateExpr = xpath.compile("/resources/resource/certificates/certificate");
            Object result = getCertificateExpr.evaluate(doc, XPathConstants.NODESET);
            NodeList certNodeList = (NodeList) result;

            // if no cert nodes, then look at CSRs instead
            if (certNodeList.getLength() == 0) {
                XPath _xpath = XPathFactory.newInstance().newXPath();
                XPathExpression getCsrExpr = _xpath.compile("/resources/resource/CSRs/CSR");
                Object _result = getCsrExpr.evaluate(doc, XPathConstants.NODESET);
                NodeList _nodeList = (NodeList) _result;
                if ((_nodeList.getLength() != 0)) {
                    for (int i = 0; i < _nodeList.getLength(); i++) {
                        Node _csrNode = _nodeList.item(i);
                        if (_csrNode.getNodeType() == Node.ELEMENT_NODE) {
                            Element _csrElement = (Element) _csrNode;

                            NodeList _statusList = _csrElement.getElementsByTagName("status");
                            Element _statusElement = (Element) _statusList.item(0);
                            String _status = _statusElement.getChildNodes().item(0).getTextContent();
                            if ((!_status.equals("ARCHIVED")) || (!_status.equals("DELETED"))) {
                                if (!_status.equals(this.getStatus())) {  // ****different to above block
                                    NodeList _idList = _csrElement.getElementsByTagName("id");
                                    Element _idElement = (Element) _idList.item(0);
                                    String _id = _idElement.getChildNodes().item(0).getTextContent();

                                    NodeList _ownerList = _csrElement.getElementsByTagName("owner");
                                    Element _ownerElement = (Element) _ownerList.item(0);
                                    String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                                    NodeList _roleList = _csrElement.getElementsByTagName("role");
                                    Element _roleElement = (Element) _roleList.item(0);
                                    String _role = _roleElement.getChildNodes().item(0).getTextContent();

                                    NodeList _useremailList = _csrElement.getElementsByTagName("useremail");
                                    Element _useremailElement = (Element) _useremailList.item(0);
                                    String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                                    this.setIsCSR(true);
                                    this.setOwner(_owner);
                                    this.setRole(_role);
                                    this.setUserEmail(_useremail);
                                    this.setId(_id);
                                    this.setStatus(_status);

                                    if (_status.equals("NEW")) {
                                        String _description = "Your certificate has been submitted and is waiting for approval.";
                                        this.setDescription(_description);
                                    }
                                    if (_status.equals("RENEW")) {
                                        String _description = "Your renewal certificate has been submitted and is waiting for approval.";
                                        this.setDescription(_description);
                                    }
                                    if (_status.equals("APPROVED")) {
                                        String _description = "Your certificate has been approved and is waiting for CA operator signature.";
                                        this.setDescription(_description);
                                    }
                                }// ****different to above block
                            }
                        }
                    }
                }
            } else {
                // Iterate all the <certificate/> nodes and update the state of this
                // CertificateCSRInfo instance if the certificate status has
                // changed. If the status has newly changed to 'VALID', then
                // save the downloaded certificate and the cakeystore.pkcs12 keyStore file's private key
                // as a new entry in cacertkeystore.pkcs12 (only if they don't
                // already exist in cacertkeystore).
                for (int i = 0; i < certNodeList.getLength(); i++) {
                    Node _certNode = certNodeList.item(i);
                    if (_certNode.getNodeType() == Node.ELEMENT_NODE) {
                        Element _certElement = (Element) _certNode;

                        NodeList _idList = _certElement.getElementsByTagName("id");
                        Element _idElement = (Element) _idList.item(0);
                        String _id = _idElement.getChildNodes().item(0).getTextContent();

                        NodeList _statusList = _certElement.getElementsByTagName("status");
                        Element _statusElement = (Element) _statusList.item(0);
                        String _status = _statusElement.getChildNodes().item(0).getTextContent();

                        // update this.state only if the status has changed
                        if (!(_status.equals(this.getStatus()))) {
                            if (_status.equals("VALID")) {
                                // Restore this certificate in cacertkeystore.pkcs12
                                ClientKeyStore clientKeyStore = ClientKeyStore.getClientkeyStore(passphrase);
                                PublicKey publicKey = EncryptUtil.getPublicKey(this.getPublickey());
                                PrivateKey keyStorePrivateKey = clientKeyStore.getPrivateKey(publicKey);
                                CertificateDownload certDownload = new CertificateDownload(_id);
                                X509Certificate downloadedCert = certDownload.getCertificate();
                                // update/write cacertkeystore.pkcs12
                                ClientCertKeyStore.getClientCertKeyStore(passphrase).addNewKey(keyStorePrivateKey, downloadedCert);
                            }

                            NodeList _ownerList = _certElement.getElementsByTagName("owner");
                            Element _ownerElement = (Element) _ownerList.item(0);
                            String _owner = _ownerElement.getChildNodes().item(0).getTextContent();

                            NodeList _roleList = _certElement.getElementsByTagName("role");
                            Element _roleElement = (Element) _roleList.item(0);
                            String _role = _roleElement.getChildNodes().item(0).getTextContent();

                            NodeList _useremailList = _certElement.getElementsByTagName("useremail");
                            Element _useremailElement = (Element) _useremailList.item(0);
                            String _useremail = _useremailElement.getChildNodes().item(0).getTextContent();

                            NodeList _startdateList = _certElement.getElementsByTagName("startdate");
                            Element _startdateElement = (Element) _startdateList.item(0);
                            String _startdate = _startdateElement.getChildNodes().item(0).getTextContent();

                            NodeList _enddateList = _certElement.getElementsByTagName("enddate");
                            Element _enddateElement = (Element) _enddateList.item(0);
                            String _enddate = _enddateElement.getChildNodes().item(0).getTextContent();

                            NodeList _lifedaysList = _certElement.getElementsByTagName("lifedays");
                            Element _lifedaysElement = (Element) _lifedaysList.item(0);
                            String _lifedays = _lifedaysElement.getChildNodes().item(0).getTextContent();

                            NodeList _renewList = _certElement.getElementsByTagName("renew");
                            Element _renewElement = (Element) _renewList.item(0);
                            String _renew = _renewElement.getChildNodes().item(0).getTextContent();

                            this.setIsCSR(false);
                            this.setOwner(_owner);
                            this.setRole( _role );
                            this.setStatus(_status);
                            this.setUserEmail(_useremail);
                            this.setId(_id);
                            this.setStartDate(_startdate);
                            this.setEndDate(_enddate);
                            this.setLifeDays(_lifedays);
                            this.setRenew(_renew);
                        }
                    }
                }
            }
            return true;
        } catch (Exception ep) {
            ep.printStackTrace();
            return false;
        }

    }
}
