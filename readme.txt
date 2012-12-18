README

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
    OR 
   Copy one of the provided configure files, located at: 
       'uk/ngs/ca/tool/property/configure.cwiz-live.ca.ngs.ac.uk.properties, (production CA)
       'uk/ngs/ca/tool/property/configure.cwiz.ca.ngs.ac.uk.properties, (development CA)
        to: 
       'uk/ngs/ca/tool/property/configure.properties'


2) Modify the copied properties file as required.  
    If you want to access different CA server, just overwrite configure.properties by
    using the above template files.

3) For new CA servers, add the public host cert (in pem format) of the CA-Server you need to interact with
 to the 'uk/ngs/ca/tool/property/hostcert.pem' XML file (this file already includes certs 
 for cwiz-live and cwiz.ca). 
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

cd into the build dir and run:
java uk.ngs.certwizard.gui.CertWizardMain


TODOs:
======
There are lots of to do items. Much of the code needs refactoring (many parts 
are poorly written with 3rd party legacy). 

- Show location of keyStore file (currently is just shown on password panel). 
- Export multiple certificates into a PKCS12 file (currently, can only export one at a time)  
- When exporting certs, need to change the perms on *nix box much like 
  when installing the pem files (think this may be done - check).  
- Edit/choose Colours 
- Apply needs fixing for the regex pattern to prevent accented chars. 

