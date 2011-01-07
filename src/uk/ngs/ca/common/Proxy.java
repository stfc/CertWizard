/*
 * This file is part of NGS CA project.
 */

package uk.ngs.ca.common;

/**
 * This class setup the proxy configuration.
 * @author xw75
 */
public class Proxy {
    /*
     * to initiate proxy if necessary.
     * the proxyhost and proxyport should be required from configure file.
     */
    public static void init(){
         java.util.Properties systemSetting = System.getProperties();
         systemSetting.put( "http.proxyHost", "wwwcache.dl.ac.uk" );
         systemSetting.put( "http.proxyPort", "8080" );
    }
}
