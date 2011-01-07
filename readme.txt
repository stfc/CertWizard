README

CertWizard is a java client tool to access and manage user certificates.
It is developed based on Restlet APIs.

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

The configuration file can be found from uk/ngs/ca/tool/property/configure.properties.

Several template configure files are located at
   uk/ngs/ca/tool/property/configure.cwiz-live.ca.ngs.ac.uk.properties, (production CA)
   uk/ngs/ca/tool/property/configure.cwiz.ca.ngs.ac.uk.properties, (development CA)
   uk/ngs/ca/tool/property/configure.escvig14.dl.ac.uk.properties. (Xiaodong's development server)

if you want to access different CA server, just overwrite configure.properties by
using the above template files.

Running

java uk.ngs.certwizard.gui.CertWizardMain



