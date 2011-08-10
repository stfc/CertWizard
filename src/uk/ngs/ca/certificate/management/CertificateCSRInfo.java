/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.certificate.management;

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
