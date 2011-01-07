/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.management;

/**
 *
 * @author xw75
 */
public class RequestPendingInfo {
    
    private String dn = null;
    private String serialnumber = null;
    private String cn = null;
    private String useremail = null;
    private String role = null;
    private String startdate = null;
    private String description = null;
    private String publickey = null;
    private String pin = null;
    private String type = null;
    private String sponsor = null;
    private String encodeddn = null;
    private String bulk = null;
    private String displaytitle = null;

    private String revokeobject = null;
    private String revokecode = null;
    private String revoketext = null;

    public String NEW = "NEW";
    public String REKEY = "REKEY";
    public String REVOKED = "REVOKED";

    private boolean isApproved = false;

    public RequestPendingInfo(){
        
    }

    public void setDN( String dn ){
        this.dn = dn;
    }

    public void setSerialNumber( String serialnumber ){
        this.serialnumber = serialnumber;
    }

    public void setCN( String cn ){
        this.cn = cn;
    }

    public void setUserEmail( String useremail ){
        this.useremail = useremail;
    }

    public void setRole( String role ){
        this.role = role;
    }

    public void setStartDate( String startdate ){
        this.startdate = startdate;
    }

    public void setDescription( String description ){
        this.description = description;
    }

    public void setPublicKey( String publickey ){
        this.publickey = publickey;
    }

    public void setPIN( String pin ){
        this.pin = pin;
    }

    public void setType( String type ){
        this.type = type;
    }

    public void setSponsor( String sponsor ){
        this.sponsor = sponsor;
    }

    public void setEncodedDN( String encodeddn ){
        this.encodeddn = encodeddn;
    }

    public void setBulk( String bulk ){
        this.bulk = bulk;
    }

    public void setRevokeObject( String revokeobject ){
        this.revokeobject = revokeobject;
    }

    public void setRevokeCode( String revokecode ){
        this.revokecode = revokecode;
    }

    public void setRevokeText( String revoketext ){
        this.revoketext = revoketext;
    }

    public void setDisplayTitle( String displaytitle ){
        this.displaytitle = displaytitle;
    }

    public String getDN( ){
        return this.dn;
    }

    public String getSerialNumber( ){
        return this.serialnumber;
    }

    public String getCN( ){
        return this.cn;
    }

    public String getUserEmail( ){
        return this.useremail;
    }

    public String getRole( ){
        return this.role;
    }

    public String getStartDate( ){
        return this.startdate;
    }

    public String getDescription( ){
        return this.description;
    }

    public String getPublicKey( ){
        return this.publickey;
    }

    public String getPIN( ){
        return this.pin;
    }

    public String getType( ){
        return this.type;
    }

    public String getSponsor( ){
        return this.sponsor;
    }

    public String getEncodedDN( ){
        return this.encodeddn;
    }

    public String getBulk( ){
        return this.bulk;
    }

    public String getRevokeObject( ){
        return this.revokeobject;
    }

    public String getRevokeCode( ){
        return this.revokecode;
    }

    public String getRevokeText( ){
        return this.revoketext;
    }

    public String getDisplayTitle( ){
        return this.displaytitle;
    }
    
}
