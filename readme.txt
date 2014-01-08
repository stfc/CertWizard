README
David Meredith 
Disclaimer - Much of the code needs refactoring (many parts are poorly written 
with 3rd party legacy). 

Requirements
===============
Java JDK 1.6 +
Apache Ant 1.8+
netbeans 7.1+ (you don't need netbeans to build/compile this project
  since netbeans uses 100% apache ant to build netbeans projects, but it is 
  very useful for building the GUI).


CertWizard is a java client tool to access and manage user/host certificates. 
The voms enabled MyProxyUploader is a sub-project that is included in Certwizard. 
Therefore, all the dependencies of the MyProxyUploader are also required in this 
project. 


It is developed based on Restlet APIs. This is the client tool for the corresponding
CA-Server. See: http://www.restlet.org/ 


CertWizard supports the following functions:

1. MyProxy Uploader functions.
2. Working under online and offline.
3. Apply user certificate.
4. Import user certificate from pkcs12 file.
5. Export user certificate to pkcs12 file.
6. Renew user certificate.
7. Revoke user certificate.
8. Remove user certificate from CertWizard.
9. Create user cer/key pem files.


Configuration:
===============

1) Copy 'uk/ngs/ca/tool/property/template.configure.properties' 
         to:
        'uk/ngs/ca/tool/property/configure.properties' (and modify as required) 
    
   (for ukca, use one of the provided configure files): 
       'uk/ngs/ca/tool/property/configure.cwiz-live.ca.ngs.ac.uk.properties, (production CA)
       'uk/ngs/ca/tool/property/configure.cwiz.ca.ngs.ac.uk.properties, (development CA)


2) Modify the copied properties file as required.  
    If you want to access different CA server, just overwrite configure.properties by
    using the above template files.

3) For new CA servers, either add the host cert pem of the CA-Server host you 
need to interact with OR the CA cert chain that signed the CA-Server's hosts cert to 
'uk/ngs/ca/tool/property/hostcert.pem' XML file (certs need to be in pem format).   

This file is configured with the UK eSci CA chain (CA cert and root) so it can
be used against cwiz-live and cwiz.ca without modification.
 
This file is actually an XML file (not a pem encoded cert) and can store 
multiple public certs for convenience. Note, when
adding the base64 encoded pem file, do not have any spaces after <hostcert>
and before </hostcert> 
To export a pem from a p12 use openssl with (-clcerts = only out client certs, -nokeys don't export key): 
openssl pkcs12 -clcerts -nokeys -in somepkcs12file.p12 -out hostcert.pem


Build / Compile
====================
Use netbeans or in the project directory run the following:
    ant clean
    ant jar
(although this is a netbeans project, netbeans uses 100% ant to build so you
don't actually need netbeans to build/compile the project)

Running:
===========
cd into the dist dir and run: 
java -jar Certwizard.jar

note, although not common, you can also cd into the build dir and run:
java uk.ngs.certwizard.gui.CertWizardMain


Crytpo BC/JCE unlimited strength provider notes
================================================
CWiz requires an unlimited strength jce security provider to allow big password 
access to a PKCS12 keystore without policy restrictions on pw length. This is provided 
with the following custom class that is provided as part of the 'MyProxyUploader2.jar' 
dependency (a sub-project): 'org.bouncycastle.jce.provider.unlimited.PKCS12KeyStoreUnlimited;' 

To remove the dependency on MyProxyUploader2.jar, this class would need to be 
copied into the src tree of this project under the same package. This class 
also requires a particular build of the BC crypto provider (bcprov-jdk15-145.jar). 

This class is provided by NIKHEF, see: http://wiki.nikhef.nl/grid/PKCS12KeyStoreUnlimited 
and is also copied into the 'resources/pkcs12KeyStoreUnlimited' dir for archive. 

 
Code Signing for deployment via Java WebStart as a RIA (Rich Internet App)
===========================================================================
To deploy Cwiz via Java WebStart, you need to sign all the dist/**/*.jar files. To do this, 
you can use either:
a) the 'SignDistJars' ant target in the build.xml file. This target requires 
the 'env.properties' file (use the provided 'sample.env.properties' as a template).  
In this file, specify your code-signing certificate and the corresponding details, 
you can then run this ant target to sign all the dist/**/*.jar files. 

b) use jarsigner directly on the command line: 
e.g.  
for i in dist/**/*.jar; do jarsigner.exe -keystore ./mykeystore.p12 -storepass somepassword -storetype pkcs12 $i "cert_alias" ; done


Signing Notes: 
---------------
+) Permissions attribute in jar manifest: 
We need to deploy via WebStart using a single .jnlp file (see myproxy.jnlp) rather 
than using multiple jnlp files linked using jnlp <extensions/>. In doing this, 
all the jars must be signed using the same code-sign signature. 
In addition, deploying using a single .jnlp file means the 'Permissions' manifest 
file attribute defined in the *main* jar file will also apply to all the other jars. 
The Permissions mf attribute is now mandatory as of JDK 1.7u51 (January 2014).  
If another jar is loaded as a jnlp <extension/>, it appears that the Permissions 
attribute needs to be added to the jar using:  
  'jar ufm manifestUpdates.txt some.jar' 
(where manifestUpdates.txt file defines the manifest updates, e.g. adding the 
Permissions mf attribute followed by a newline) e.g: 
Permissions: permissions-all 

See: http://docs.oracle.com/javase/tutorial/deployment/jar/modman.html

Updating digitally signed jars is problematic - you must first remove the jar's 
existing signature (can remove jar signatures using a zip utility), update the jar's mf 
file as described above, and then re-sign the jar.  

+) It is important that all the jars in a jnlp are signed using the same signature 
algorithm. If you do not, you may encounter the following error:
 'java.io.IOException: invalid SHA1 signature file digest for org/bouncycastle/asn1/ocsp/ResponderID.class' 

This exception occurred because the BC jar was signed using SHA1, whilst all the other jars 
were signed using SHA256 (the JDK1.7 default is to sign using SHA256, whilst JDK1.6 uses SHA1). 
You have been warned - see: http://www.captaincasademo.com/forum/posts/list/1831.page 


JCE/JCA code signing for cryptography extensions
=================================================
This application deploys Java crytpo libraries - the 'bcprov-jdk15-145.jar' from 
Bouncy Castle. This library needs to be signed by a special JCA/JCE certificate that
can be requested free from Oracle (you can't use your normal code-sign cert, it has
to be a special JCE code-sign cert as described at the link below). Note, this jar  
has already been signed by BC's JCE code-sign cert but you can replace the 
BC JCE signature with your own signature (remove the BC signature using a zip util and 
re-sign as normal using jarsigner and your JCE code-sign cert).   
 
Getting a JCE code sign cert: 
http://www.oracle.com/technetwork/java/javase/tech/getcodesigningcertificate-361306.html

Note, If you are deploying via webstart, this lib must therefore be signed twice:  
  a) the BC JCE signature (or another signature from a JCA signing cert) 
     verifying this jar is a valid JCA provider  
  b) the normal code-sign signature for Webstart/RIA deployment. 

  (code signing for Webstart deployment and signing a jar as a valid JCE/JCA provider are two 
  separate things !)   

   http://www.oracle.com/technetwork/java/javase/tech/getcodesigningcertificate-361306.html
   http://docs.oracle.com/javase/7/docs/technotes/guides/jweb/no_redeploy.html#permissions


TODOs:
======
There are lots of to do items. Much of the code needs refactoring (many parts 
are poorly written with 3rd party legacy): 

- Address following bug: System property "user.home" does not correspond to "USERPROFILE" (win)
   http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4787931
- Export multiple certificates into a PKCS12 file (currently, can only export one at a time)  
- When exporting certs, need to change the perms on *nix box much like 
  when installing the pem files (think this may be done - check).  
- Edit/choose Colours 
- Apply needs fixing for the regex pattern to prevent accented chars. 


Deprecated todos:
=================
- Remove "Authority CLRC" from RA list and update the RA list in the DB. 
  OpenCA gets the list of RAs from /usr/local/OpenCA/etc/**/*.conf 
  (there is probably a ra.conf, a ca.conf, and a server.conf and something to that effect, which contains a line with a list of RAs in alphabetical order). 
  For CertWizard, we should try to ensure that the deprecated RAs - like Authority CLRC and CLRC External - are not displayed.  One way of doing this is to have a "deprecated" flag in the database - I assume they're coming from raoplist? - and maybe even a view which hides the deprecated ones.
