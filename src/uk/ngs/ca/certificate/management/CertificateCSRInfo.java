/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

/**
 *
 * @author xw75 (Xiao Wang)
 */
public class CertificateCSRInfo {

    private volatile String owner = null;
    private volatile String role = null;
    
    // The status returned by the server. TODO: 
    private volatile String status = null;
    private volatile String useremail = null;
    private volatile String id = null;
    private volatile String startdate = null;
    private volatile String enddate = null;
    private volatile String lifedays = null;
    private volatile String renew = null;
    private volatile String description = null;
    private volatile boolean isCSR = false;
    private volatile String publickey = null;

    public CertificateCSRInfo() {
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
}
