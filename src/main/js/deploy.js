//    Copyright 2018 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

print("Loading CertUtils");
var CertUtils = Java.type("com.tremolosecurity.kubernetes.artifacts.util.CertUtils");

print("Creating openunison keystore");

ksPassword = inProp['unisonKeystorePassword'];
ouKs = Java.type("java.security.KeyStore").getInstance("PKCS12");
ouKs.load(null,ksPassword.toCharArray());

use_k8s_cm = inProp['USE_K8S_CM'] == "true";


inProp['K8S_DB_SECRET'] = java.util.UUID.randomUUID().toString();


print("Generating openunison tls certificate");
certInfo = {
    "serverName":"openunison.openunison.svc.cluster.local",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

var x509data = CertUtils.createCertificate(certInfo);

if (use_k8s_cm) {
  print("Creating CSR for API server");



  csrReq = {
      "apiVersion": "certificates.k8s.io/v1beta1",
      "kind": "CertificateSigningRequest",
      "metadata": {
        "name": "openunison.openunison.svc.cluster.local",
      },
      "spec": {
        "request": java.util.Base64.getEncoder().encodeToString(CertUtils.generateCSR(x509data).getBytes("utf-8")),
        "usages": [
          "digital signature",
          "key encipherment",
          "server auth"
        ]
      }
    };

  print("Requesting certificate");
  apiResp = k8s.postWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests',JSON.stringify(csrReq));

  if (apiResp.code == 409) {
    print("CertManager is not enabled on this cluster.  Change USE_K8S_CM=false in your input.props");
    exit(1);
  }

  print("Approving certificate");
  approveReq = JSON.parse(apiResp.data);
  approveReq.status.conditions = [
      {
          "type":"Approved",
          "reason":"OpenUnison Deployment",
          "message":"This CSR was approved by the OpenUnison artifact deployment job"
      }
  ];

  apiResp = k8s.putWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/openunison.openunison.svc.cluster.local/approval',JSON.stringify(approveReq));
  print("Retrieving certificate from API server");
  apiResp = k8s.callWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/openunison.openunison.svc.cluster.local');
  print(apiResp.data);
  certResp = JSON.parse(apiResp.data);
  b64cert = certResp.status.certificate;

  if (b64cert == null || b64cert === "") {
    print("CertManager is not enabled on this cluster.  Change USE_K8S_CM=false in your input.props");
    exit(1);
  }

  CertUtils.importSignedCert(x509data,b64cert);
}

print("Saving certificate to keystore");
CertUtils.saveX509ToKeystore(ouKs,ksPassword,"unison-tls",x509data);
CertUtils.createKey(ouKs,"session-unison",ksPassword);
CertUtils.createKey(ouKs,"lastmile-oidc",ksPassword);

print("Generating OIDC Certificate");

certInfo = {
    "serverName":"unison-saml2-rp-sig",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

x509data = CertUtils.createCertificate(certInfo);
CertUtils.saveX509ToKeystore(ouKs,ksPassword,"unison-saml2-rp-sig",x509data);

rp_sig_cert_bytes = x509data.getCertificate();

print("Storing k8s cert");
ouKs.setCertificateEntry('k8s-master',k8s.getCertificate('k8s-master'));


//import metadata

fXmlFile = new java.io.File("/etc/extracerts/saml2-metadata.xml");
dbFactory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
dBuilder = dbFactory.newDocumentBuilder();
doc = dBuilder.parse(fXmlFile);

//get entity id
entityId = doc.getElementsByTagName("EntityDescriptor").item(0).getAttribute("entityID");

idp = doc.getElementsByTagName("IDPSSODescriptor").item(0);

singleLogoutURL = "";
ssoGetURL = "";
ssoPostURL = "";
sig_certs = [];
sig_cert_to_use = ""

current_cert_choice = null;


//single logout
slos = idp.getElementsByTagName("SingleLogoutService");

for (i = 0;i<slos.getLength();i++) {
    slo = slos.item(i);
    if (slo.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
        singleLogoutURL = slo.getAttribute("Location");
    }
}

//single sign on
ssos = idp.getElementsByTagName("SingleSignOnService");

for (i = 0;i<ssos.getLength();i++) {
    sso = ssos.item(i);
    if (sso.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")) {
        ssoGetURL = sso.getAttribute("Location");
    } else if (sso.getAttribute("Binding").equalsIgnoreCase("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")) {
        ssoPostURL = sso.getAttribute("Location");
    }
}

keys = idp.getElementsByTagName("KeyDescriptor");

for (i=0;i<keys.getLength();i++) {
    key = keys.item(i);

    if (key.getAttribute("use").equalsIgnoreCase("signing")) {
        sig_cert = key.getElementsByTagName("KeyInfo").item(0).getElementsByTagName("X509Data").item(0).getElementsByTagName("X509Certificate").item(0).getTextContent();
        sig_certs.push(sig_cert);
    }
}

if (sig_certs.length == 1) {
    current_cert_choice = com.tremolosecurity.kubernetes.artifacts.util.CertUtils.string2cert(sig_certs[0]);
} else {
    for (i=0;i<sig_certs.length;i++) {
        current_cert = com.tremolosecurity.kubernetes.artifacts.util.CertUtils.string2cert(sig_certs[i]);
        if (current_cert_choice == null) {
            current_cert_choice = current_cert;
        } else {
            if (current_cert_choice.getNotAfter().compareTo(current_cert.getNotAfter())  < 0  ) {
                current_cert_choice = current_cert;
            }
        }
    }
    
}


inProp['IDP_ENTITY_ID'] = entityId;
inProp['IDP_POST'] = ssoPostURL;
inProp['IDP_REDIR'] = ssoGetURL;
inProp['IDP_LOGOUT'] = singleLogoutURL;


ouKs.setCertificateEntry('idp-saml2-sig',current_cert_choice);



print("Generate Ingress Certificate");

ingressCertInfo = {
    "serverName": inProp["OU_HOST"],
    "ou":inProp["OU_CERT_OU"],
    "o":inProp["OU_CERT_O"],
    "l":inProp["OU_CERT_L"],
    "st":inProp["OU_CERT_ST"],
    "c":inProp["OU_CERT_C"],
    "caCert":true,
    "subjectAlternativeNames":[
        inProp["K8S_DASHBOARD_HOST"]
    ]
}

ingressX509data = CertUtils.createCertificate(ingressCertInfo);

print("Import OpenUnison certificate into keystore");
ouKs.setCertificateEntry('unison-ca',ingressX509data.getCertificate());

print("Importing the dashboard");

 res = k8s.callWS('/api/v1/namespaces/kube-system/pods');
pods = JSON.parse(res.data);

 k8s_db_uri = null;

 for (i=0;i<pods.items.length;i++) {
  pod = pods.items[i];
  if (pod.metadata.name.startsWith("kubernetes-dashboard")) {
    k8s_db_uri = pod.metadata.selfLink;
  }
}


 if (k8s_db_uri == null) {
  print("Dashboard not present, deploying");
  k8s.kubectlCreateFromURL("https://raw.githubusercontent.com/kubernetes/dashboard/v1.10.1/src/deploy/recommended/kubernetes-dashboard.yaml");

   res = k8s.callWS('/api/v1/namespaces/kube-system/pods');
  pods = JSON.parse(res.data);


   for (i=0;i<pods.items.length;i++) {
    pod = pods.items[i];
    if (pod.metadata.name.startsWith("kubernetes-dashboard")) {
      k8s_db_uri = pod.metadata.selfLink;
    }
  }
} else {
  print("Skipping import of dashboard");
}



print("Generating dashboard tls certificate");
dbCertInfo = {
    "serverName":"kubernetes-dashboard.kube-system.svc.cluster.local",
    "ou":"kubernetes",
    "o":"tremolo",
    "l":"cloud",
    "st":"cncf",
    "c":"ea",
    "caCert":false
}

dbX509data = CertUtils.createCertificate(dbCertInfo);

if (use_k8s_cm) {
  print("Creating CSR for API server");



  csrReq = {
      "apiVersion": "certificates.k8s.io/v1beta1",
      "kind": "CertificateSigningRequest",
      "metadata": {
        "name": "kubernetes-dashboard.kube-system.svc.cluster.local",
      },
      "spec": {
        "request": java.util.Base64.getEncoder().encodeToString(CertUtils.generateCSR(dbX509data).getBytes("utf-8")),
        "usages": [
          "digital signature",
          "key encipherment",
          "server auth"
        ]
      }
    };

  print("Requesting certificate");
  apiResp = k8s.postWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests',JSON.stringify(csrReq));
  print("Approving certificate");
  approveReq = JSON.parse(apiResp.data);
  approveReq.status.conditions = [
      {
          "type":"Approved",
          "reason":"OpenUnison Deployment",
          "message":"This CSR was approved by the OpenUnison artifact deployment job"
      }
  ];

  apiResp = k8s.putWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/kubernetes-dashboard.kube-system.svc.cluster.local/approval',JSON.stringify(approveReq));
  print("Retrieving certificate from API server");
  apiResp = k8s.callWS('/apis/certificates.k8s.io/v1beta1/certificatesigningrequests/kubernetes-dashboard.kube-system.svc.cluster.local','java.util.Base64.getDecoder().decode(JSON.parse(ws_response_json).status.certificate);check_ws_response=true;',10);
  print(apiResp.data);
  certResp = JSON.parse(apiResp.data);
  b64cert = certResp.status.certificate;
  CertUtils.importSignedCert(dbX509data,b64cert);
} else {
  //not using k8s cm, so just import the dashboard cert into the openunison keystore
  ouKs.setCertificateEntry("trusted-k8s-dasboard",dbX509data.getCertificate());
}
print("Creating dashboard secret");

dbsecret = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"kubernetes-dashboard-certs",
        "namespace":"kube-system"
    },
    "data":{
        "dashboard.crt": java.util.Base64.getEncoder().encodeToString(CertUtils.exportCert(dbX509data.getCertificate()).getBytes("UTF-8")),
        "dashboard.key": java.util.Base64.getEncoder().encodeToString(CertUtils.exportKey(dbX509data.getKeyData().getPrivate()).getBytes("UTF-8"))
    }
};

res = k8s.postWS('/api/v1/namespaces/kube-system/secrets',JSON.stringify(dbsecret));

if (res["code"] == 409) {
    print("Secret alread exists, lets delete then recreate");
    k8s.deleteWS('/api/v1/namespaces/kube-system/secrets/kubernetes-dashboard-certs');

    print("re-creating");
    k8s.postWS('/api/v1/namespaces/kube-system/secrets',JSON.stringify(dbsecret));
}

print("restarting the dashboard")

 print("Deleting " + k8s_db_uri);
k8s.deleteWS(k8s_db_uri);

print("Create the openunison namespace");

ouNS = {
    "apiVersion":"v1",
    "kind":"Namespace",
    "metadata":{
        "creationTimestamp":null,
        "name":"openunison"
    },
    "spec":{},
    "status":{}
};

k8s.postWS('/api/v1/namespaces',JSON.stringify(ouNS));

print("Create openunison service account");

k8s.postWS('/api/v1/namespaces/openunison/serviceaccounts',JSON.stringify({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"creationTimestamp":null,"name":"openunison"}}));




print("Create Ingress TLS Secret");

ingressSecret = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"kubernetes.io/tls",
    "metadata": {
        "name":"ou-tls-certificate",
        "namespace":"openunison"
    },
    "data":{
        "tls.crt": java.util.Base64.getEncoder().encodeToString(CertUtils.exportCert(ingressX509data.getCertificate()).getBytes("UTF-8")),
        "tls.key": java.util.Base64.getEncoder().encodeToString(CertUtils.exportKey(ingressX509data.getKeyData().getPrivate()).getBytes("UTF-8"))
    }
};

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(ingressSecret));


print("Create OpenUnison Secret");


ouSecrets = {
    "apiVersion":"v1",
    "kind":"Secret",
    "type":"Opaque",
    "metadata": {
        "name":"openunison-secrets",
        "namespace":"openunison"
    },
    "data":{
      "openunison.yaml":"LS0tCm9wZW5fcG9ydDogODA4MApvcGVuX2V4dGVybmFsX3BvcnQ6IDgwCnNlY3VyZV9wb3J0OiA4NDQzCnNlY3VyZV9leHRlcm5hbF9wb3J0OiA0NDMKc2VjdXJlX2tleV9hbGlhczogInVuaXNvbi10bHMiCmZvcmNlX3RvX3NlY3VyZTogdHJ1ZQphY3RpdmVtcV9kaXI6ICIvdG1wL2FtcSIKcXVhcnR6X2RpcjogIi90bXAvcXVhcnR6IgpjbGllbnRfYXV0aDogbm9uZQphbGxvd2VkX2NsaWVudF9uYW1lczogW10KY2lwaGVyczoKLSBUTFNfUlNBX1dJVEhfUkM0XzEyOF9TSEEKLSBUTFNfUlNBX1dJVEhfQUVTXzEyOF9DQkNfU0hBCi0gVExTX1JTQV9XSVRIX0FFU18yNTZfQ0JDX1NIQQotIFRMU19SU0FfV0lUSF8zREVTX0VERV9DQkNfU0hBCi0gVExTX1JTQV9XSVRIX0FFU18xMjhfQ0JDX1NIQTI1NgotIFRMU19SU0FfV0lUSF9BRVNfMjU2X0NCQ19TSEEyNTYKcGF0aF90b19kZXBsb3ltZW50OiAiL3Vzci9sb2NhbC9vcGVudW5pc29uL3dvcmsiCnBhdGhfdG9fZW52X2ZpbGU6ICIvZXRjL29wZW51bmlzb24vb3UuZW52IgoK",
      "ou.env":k8s.encodeMap(inProp),
      "unisonKeyStore.p12":CertUtils.encodeKeyStore(ouKs,ksPassword)
    }
}

k8s.postWS('/api/v1/namespaces/openunison/secrets',JSON.stringify(ouSecrets));

print("Creating post deployment configmap");

oidcFlags = "--oidc-issuer-url=https://" + inProp["OU_HOST"] + "/auth/idp/k8sIdp\n" +
            "--oidc-client-id=kubernetes\n" +
            "--oidc-username-claim=sub\n" + 
            "--oidc-groups-claim=groups\n" +
            "--oidc-ca-file=/etc/kubernetes/pki/ou-ca.pem";

canonicalOidcFlags =  "oidc-issuer-url=https://" + inProp["OU_HOST"] + "/auth/idp/k8sIdp " +
                      "oidc-client-id=kubernetes " +
                      "oidc-username-claim=sub " + 
                      "oidc-groups-claim=groups " +
                      "oidc-ca-file=/root/cdk/ou-ca.pem";

print("Runing kubectl create");
k8s.kubectlCreate(k8s.processTemplate(deploymentTemplate,inProp));
print("kubectl complete");

xmlMetaData =  '<EntityDescriptor ID="_10685acd-7df4-427e-b61e-68e4f6407c24" entityID="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">\n';
xmlMetaData += '  <SPSSODescriptor WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n';
xmlMetaData += '      <KeyDescriptor use="signing">\n';
xmlMetaData += '        <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">\n';
xmlMetaData += '              <X509Data>\n';
xmlMetaData += '                  <X509Certificate>\n' + new org.apache.commons.codec.binary.Base64(64).encodeToString(rp_sig_cert_bytes.getEncoded()) + '</X509Certificate>\n';
xmlMetaData += '              </X509Data>\n';
xmlMetaData += '          </KeyInfo>\n';
xmlMetaData += '      </KeyDescriptor>\n';
xmlMetaData += '      <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth"/>\n';
xmlMetaData += '      <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>\n';
xmlMetaData += '      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" index="0" isDefault="true"/>\n';
xmlMetaData += '      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://' + inProp['OU_HOST'] + '/auth/SAML2Auth" index="1"/>\n';
xmlMetaData += '  </SPSSODescriptor>\n';
xmlMetaData += '</EntityDescriptor>';


cfgMap = {
    "apiVersion":"v1",
    "kind":"ConfigMap",
    "metadata":{
        "name":"api-server-config",
        "namespace":"openunison"
    },
    "data":{
      "oidc-api-server-flags":oidcFlags,
      "ou-ca.pem-base64-encoded":CertUtils.exportCert(ingressX509data.getCertificate()),
      "canonical-cdk-flags":canonicalOidcFlags,
      "oidc-issuer-url":"https://" + inProp["OU_HOST"] + "/auth/idp/k8sIdp",
      "oidc-client-id":"kubernetes",
      "oidc-username-claim":"sub",
      "oidc-groups-claim":"groups",
      "oidc-ca-file":"/etc/kubernetes/pki/ou-ca.pem",
      "saml2-rp-metadata":xmlMetaData
    }
};

k8s.postWS('/api/v1/namespaces/openunison/configmaps',JSON.stringify(cfgMap));

print("Deleting cluster role binding");
k8s.deleteWS('/apis/rbac.authorization.k8s.io/v1/clusterrolebindings/artifact-deployment');

print("Artifacts Created, to configure the API server run 'kubectl describe configmap api-server-config -n openunison'");