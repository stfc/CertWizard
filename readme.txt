README

Requirements
===============
Java JDK 1.5 +
Apache Ant 1.8+
netbeans 6.8 (optional - you don't need netbeans to build/compile this project
    since netbeans uses 100% apache ant to build netbeans projects).


CertWizard is a java client tool to access and manage user certificates.
It is developed based on Restlet APIs. This is the client tool for the corresponding
CA-Server. 

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
10. Support RA Operation functions which insists of deleting CSR pending request,
    approving CSR pending request, displaying full information of the pending request
    and searching functions.

Configuration:
===============

1) Copy 'uk/ngs/ca/tool/property/template.configure.properties' to
        'uk/ngs/ca/tool/property/configure.properties'

2) Modify the copied config file as required.
    Several example template configure files are located at
       uk/ngs/ca/tool/property/configure.cwiz-live.ca.ngs.ac.uk.properties, (production CA)
       uk/ngs/ca/tool/property/configure.cwiz.ca.ngs.ac.uk.properties, (development CA)
       uk/ngs/ca/tool/property/configure.escvig14.dl.ac.uk.properties. (Xiaodong's development server)

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
java -jar Latest-Certwizard.jar

cd into the build dir and run:
java uk.ngs.certwizard.gui.CertWizardMain




