
Running:
===========
cd into the dist dir and run:  "java -jar Certwizard.jar"

(You may need to specify your Web Proxy, how to described below)



Specify Connection Details on Command Line
==========================================

If the tool reports that it cannot connect to the CA Server (shown as a red 
message at the base of the tool), you probably need to configure the Web Proxy 
and other connection details.

You can specify the Web proxy host, port, username (if any) and password 
(if any) on the command line when running the tool:

$ java -Dhttp.proxyHost=proxyhost 
-Dhttp.proxyPort=proxyPortNumber
-Dhttp.proxyUser=someUserName
-Dhttp.proxyPassword=somePassword
-jar Certwizard.jar

    e.g. 

$ java -Dhttp.proxyHost=wwwcache.dl.ac.uk -Dhttp.proxyPort=8080 -jar Certwizard.jar


Specify Connection Details on Java Control Panel
================================================
Alternatively, specify the connection details for ALL your Java applications using 
the Java Control Panel (needed for the Java WebStart version of CertWizard):

    * Win: Start | Control Panel | Java  (1.)
    * Linux/Unix: type 'jcontrol &'
    * MAC: Applications | Utilities | Java Preferences

Then, on the 'General' tab click the 'Network Settings' button where you can 
specify the Web proxy details.

