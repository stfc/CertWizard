/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package uk.ngs.certwizard.gui;

/**
 *
 * @author hyz38924
 */
public class Certificate {
    private String dn;
    private String vFrom;
    private String vTo;
    private String status;
    private String dRemaining;
    private String renDue;
    private String email;
    
       
    public void setDN(String dn){
       this.dn = dn;
    }
    
    public void setVFrom(String vFrom){
        this.vFrom = vFrom;
    }
    
    public void setVTo(String vTo){
        this.vTo = vTo;
    }
    
    public void setStatus(String status){
        this.status = status;
    }
    
    public void setDRemaining(String dRemaining){
        this.dRemaining = dRemaining;
    }
    
    public void setRenDue(String renDue){
        this.renDue = renDue;
    }
    
    public void setEmail(String email){
        this.email = email;
    }
    
    public String getDN(){
       return this.dn;
    }
    
    public String getVFrom(){
        return this.vFrom;
    }
    
    public String getVTo(){
        return this.vTo;
    }
    
    public String getStatus(){
        return this.status;
    }
    
    public String getDRemaining(){
        return this.dRemaining;
    }
    
    public String getRenDue(){
        return this.renDue;
    }
    
    public String getEmail(){
        return this.email;
    }
    
    public String getCN(){
        int index = dn.indexOf("/CN");
        String cn = dn.substring(index);
        return cn;
        
    }
}
