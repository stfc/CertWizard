/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.ca.certificate.management;

/**
 *
 * @author xw75
 */
public class RASearchInfo {

    private String serialNumber = null;
    private String cn = null;
    private String ou = null;
    private String l = null;
    private String status = null;
    private String role = null;
    private String startdate = null;
    private String enddate = null;
    private String useremail = null;
    private String owner = null;
    private String lifedays = null;
    private String renew = null;

    public RASearchInfo(){

    }

    public void setSerialNumber( String serialNumber ){
        this.serialNumber = serialNumber;
    }

    public void setCN( String cn ){
        this.cn = cn;
    }

    public void setOU( String ou ){
        this.ou = ou;
    }

    public void setL( String l ){
        this.l = l;
    }

    public void setStatus( String status ){
        this.status = status;
    }

    public void setRole( String role ){
        this.role = role;
    }

    public void setStartDate( String startdate ){
        this.startdate = startdate;
    }

    public void setEndDate( String enddate ){
        this.enddate = enddate;
    }

    public void setUserEmail( String useremail ){
        this.useremail = useremail;
    }

    public void setOwner( String owner ){
        this.owner = owner;
    }

    public void setLifeDays( String lifedays ){
        this.lifedays = lifedays;
    }

    public void setRenew( String renew ){
        this.renew = renew;
    }

    public String getSerialNumber( ){
        return this.serialNumber;
    }

    public String getCN( ){
        return this.cn;
    }

    public String getOU( ){
        return this.ou;
    }

    public String getL( ){
        return this.l;
    }

    public String getStatus( ){
        return this.status;
    }

    public String getRole( ){
        return this.role;
    }

    public String getStartDate( ){
        return this.startdate;
    }

    public String getEndDate( ){
        return this.enddate;
    }

    public String getUserEmail( ){
        return this.useremail;
    }

    public String getOwner( ){
        return this.owner;
    }

    public String getLifeDays( ){
        return this.lifedays;
    }

    public String getRenew( ){
        return this.renew;
    }

}
