const vc = require('vc-js');
const jsigs = require('jsonld-signatures');
const {Ed25519KeyPair}  = require('crypto-ld');
const {documentLoaders} = require('jsonld');
const {Ed25519Signature2018}  = jsigs.suites;
const documentLoader = documentLoaders.node();

const subject = {
  '@context': [
   "https://w3id.org/security/v2",
  ],
  id:'did:example:credential-subject',
  publicKey: [{
      type: 'Ed25519VerificationKey2018',
      id: 'did:example:credential-subject#key0',
      controller: 'did:example:credential-subject',
      publicKeyBase58: '9RSUMjw9BL4edKrS8ugTfaartEdjhk4kDoZPDEPHvQKP'
  }],
};

const issuer = {
  '@context': [
   "https://w3id.org/security/v2",
   subject
  ],
  id:'did:example:credential-issuer',
  publicKey: [{
      type: 'Ed25519VerificationKey2018',
      id: 'did:example:credential-issuer#key0',
      controller: 'did:example:credential-issuer',
      publicKeyBase58: 'GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza'
  }],
  assertionMethod:[
    'did:example:credential-issuer#key0'
  ],
  authentication:[
    'did:example:credential-subject#key0'
  ]
};

const issuer_suite = new Ed25519Signature2018({
  key: new Ed25519KeyPair(
      {
      id: issuer.publicKey[0].id,
      privateKeyBase58: "3cEzNVGdLoujfhWXqrbo1FgYy9GHA5GXYvB4KixHVuQoRbWbHTJP7XTkj6LqXeiFhw79v85E4wjPQc8WcdyzntcA",
      publicKeyBase58: issuer.publicKey[0].publicKeyBase58
      })
});

const subject_suite = new Ed25519Signature2018({
  key: new Ed25519KeyPair(
      {
      id: subject.publicKey[0].id,
      privateKeyBase58: "ZxCUJSxY8xKPwGoXDm2VHGQfvHdzwYySgXFuMgvhfFKBRs1pG39uwWgaymnwG7rFDDg23dXmyKKxGUa3bNeG8wo",
      publicKeyBase58: subject.publicKey[0].publicKeyBase58
      })
});

const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
  ],
  id: 'did:example:credential:1872',
  type: ['VerifiableCredential'],
  issuer: 'did:example:credential-issuer',
  issuanceDate: '2010-01-01T19:23:24Z',
  credentialSubject: {
    id: 'did:example:credential-subject',
  }
};

(async ()=>{
  const signedVC = await vc.issue({credential, suite:issuer_suite});
  console.log(JSON.stringify(signedVC, null, 2));
  result = await vc.verifyCredential({credential:signedVC, documentLoader, suite:issuer_suite, controller:issuer});
  console.log(JSON.stringify(result, null, 2))
  const verifiableCredential = [signedVC];
  const presentation = vc.createPresentation({verifiableCredential});
  console.log(JSON.stringify(presentation, null, 2));
  challenge = "12ec21";
  const vp = await vc.signPresentation({presentation, suite:subject_suite, challenge});
  console.log(JSON.stringify(vp, null, 2))
  result = await vc.verify({presentation:vp, documentLoader, challenge, suite:[issuer_suite, subject_suite], controller:issuer});
  console.log(JSON.stringify(result, null, 2)) 
})();

