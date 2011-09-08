README

Requirements
===============
Java JDK 1.5 +
Apache Ant 1.8+
netbeans 6.8+ (optional - you don't need netbeans to build/compile this project
    since netbeans uses 100% apache ant to build netbeans projects).


CertWizard is a java client tool to access and manage user certificates. 
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

1) Copy 'uk/ngs/ca/tool/property/template.configure.properties' to
        'uk/ngs/ca/tool/property/configure.properties'

2) Modify the copied properties file as required.
    Several example template configure files are located at
       uk/ngs/ca/tool/property/configure.cwiz-live.ca.ngs.ac.uk.properties, (production CA)
       uk/ngs/ca/tool/property/configure.cwiz.ca.ngs.ac.uk.properties, (development CA)

    If you want to access different CA server, just overwrite configure.properties by
    using the above template files.

3) Add the public key (in pem format) of the CA-Server you need to interact with
 to the 'uk/ngs/ca/tool/property/hostcert.pem' file. This file is actually an
 xml file and can store multiple public certs for convenience. Note, when
adding the base64 encoded pem file, do not have any spaces after <hostcert>
and before </hostcert> 


Build / Compile
====================
In the project directory run the following:
    ant clean
    ant jar
(although this is a netbeans project, netbeans uses 100% ant to build so you
dont' actually need netbeans to build/compile the project)

Running:
===========

cd into the dist dir and run: 
java -jar Certwizard.jar

cd into the build dir and run:
java uk.ngs.certwizard.gui.CertWizardMain




