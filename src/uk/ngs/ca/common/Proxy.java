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
/*
 * Command Line JVM Settings

The proxy settings are given to the JVM via command line arguments:

$ java -Dhttp.proxyHost=proxyhostURL
-Dhttp.proxyPort=proxyPortNumber
-Dhttp.proxyUser=someUserName
-Dhttp.proxyPassword=somePassword javaClassToRun

Setting System Properties in Code:

System.getProperties().put("http.proxyHost", "someProxyURL");
System.getProperties().put("http.proxyPort", "someProxyPort");
System.getProperties().put("http.proxyUser", "someUserName");
System.getProperties().put("http.proxyPassword", "somePassword");
 *
 * http://download.oracle.com/javase/1.5.0/docs/guide/deployment/deployment-guide/jcp.html
 */