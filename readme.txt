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


TODOs:
======
There are lots of to do items. Much of the code needs refactoring (many parts 
are rather poorly written and involves much legacy). 


- When exporting certs, need to change the perms on *nix box much like 
  when installing the pem files.
- Default the keysize from 1024 to 2048. 
- OnLineUserCertificateReKey.java and CSRRequest.java both test for HTTP 202 
  return codes (when doing a renew or new csr). This is wrong! (the server is 
  also wrong). We should NOT be using 202 to return error codes ! certwiz and 
  the server both need updating in-synch to fix this.  

- When doing host certs, stop adding the Email address field for host certs (or even removing it when renewing?) 
  because CERN don't like it (special actions need to be taken as Email field can be 
  email, Email, emailadress etc...) - need to tell JJ. 
- Following string is too long "SUSPENDED (Your certificate revocation request is waiting to be processed)"
- Edit Colours 
- typo on dialog that pops up informing that the user appears to have no certs, either import or apply 
- Remove oxford myproxy server
- Add gridpp myproxy server (lcgrbp01.gridpp.rl.ac.uk:7512)
- New server cert for voms (check) 
