/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package uk.ngs.ca.common;

/**
 * Utility class for certificate related functions. Stateless and thread safe. 
 * 
 * @author Xiao Wang
 * @author David Meredith (modifications, javadoc)
 */
public class CertUtil {
    
    public static enum DNAttributeType {
        CN, L, OU, O, C, E 
    };
   
    /**
     * Get the value of the specified DN attribute. 
     * @param dn
     * @param attribute
     * @return The value of the attribute, null if the attribute does not exist 
     *  or has an empty string value. 
     */
    public static String extractDnAttribute(String dn, DNAttributeType attType) {
        //dn = dn.replace('/', ','); // consider host requests where CN=globusservice/host.dl.ac.uk
        String attribute = attType.name()+"="; 
        
        int index = dn.indexOf(attribute); 
        if(index == -1) return null; 
        
        index = index + attribute.length();
        String result = dn.substring(index);
        int _index = result.indexOf(",");
        if (_index != -1) {
            result = result.substring(0, _index);
        }
        result = result.trim();
        if("".equals(result)) return null; 
        return result;
    }
    
    
    /**
     * Reverse the given DN and use the / char as the attribute separator. 
     * The given DN must use the comma ',' as the attribute separator char. 
     * For example, given: "CN=david meredith ral,L=RAL,OU=CLRC,O=eScienceDev,C=UK"
     * the returned DN is:  "/C=UK/O=eScienceDev/OU=CLRC/L=RAL/CN=david meredith ral" 
     * 
     * @param dnrfc2253 DN that uses comma chars as the attribute separator. 
     * @return Formatted DN string. 
     */
    public static String getReverseSlashSeparatedDN(String dnrfc2253){
        StringBuilder buff = new StringBuilder("/"); 
        String[] oids = dnrfc2253.split(",");
        for(int i=oids.length-1; i>=0; --i){
            buff.append(oids[i].trim()).append("/");  
        }
        buff.delete(buff.length()-1, buff.length());  //remove trailing / 
        return buff.toString(); 
    }
}
