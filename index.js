const vc = require('vc-js');
const jsigs = require('jsonld-signatures');
const {Ed25519KeyPair}  = require('crypto-ld');
const {documentLoaders} = require('jsonld');


const {Ed25519Signature2018}  = jsigs.suites;
const {AssertionProofPurpose} = jsigs.purposes;
const publicKeyBase58         = "GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza";
const privateKeyBase58        = "3cEzNVGdLoujfhWXqrbo1FgYy9GHA5GXYvB4KixHVuQoRbWbHTJP7XTkj6LqXeiFhw79v85E4wjPQc8WcdyzntcA";

//const documentLoader = testLoader.documentLoader.bind(testLoader);
const documentLoader = documentLoaders.node();

const doc = {
    '@context': [
     "https://w3id.org/security/v2",
    ],
    id:'did:example:fotiou',
    publicKey: [{
        type: 'Ed25519VerificationKey2018',
        id: 'did:example:fotiou#issuer',
        controller: 'did:example:fotiou',
        publicKeyBase58: 'GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza'
    },
    {
        type: 'Ed25519VerificationKey2018',
        id: 'did:example:fotiou#subject',
        controller: 'did:example:fotiou',
        publicKeyBase58: 'GKKcpmPU3sanTBkoDZq9fwwysu4x7VaUTquosPchSBza'
      }
    ],
    assertionMethod:[
      'did:example:fotiou#issuer'
    ],
    authentication:[
        'did:example:fotiou#subject'
      ]
};
const issuer_suite = new Ed25519Signature2018({
    verificationMethod: "did:example:fotiou#issuer",
    key: new Ed25519KeyPair(
        {
        id: 'did:example:fotiou#issuer',
        privateKeyBase58: privateKeyBase58,
        publicKeyBase58: publicKeyBase58
        })
});

const subject_suite = new Ed25519Signature2018({
    verificationMethod: "did:example:fotiou#subject",
    key: new Ed25519KeyPair(
        {
        id: 'did:example:fotiou#subject',
        privateKeyBase58: privateKeyBase58,
        publicKeyBase58: publicKeyBase58
        })
});

const credential = {
    '@context': [
      'https://www.w3.org/2018/credentials/v1',
    ],
    id: 'did:example:fotiou:1872',
    type: ['VerifiableCredential'],
    issuer: 'did:example:fotiou',
    issuanceDate: '2010-01-01T19:23:24Z',
    credentialSubject: {
      id: 'did:example:fotiou',
    }
  };

(async ()=>{
    const signedVC = await vc.issue({credential, suite:issuer_suite});
    //console.log(JSON.stringify(signedVC, null, 2));
    //const result = await vc.verifyCredential({credential:signedVC, documentLoader, suite:[issuer_suite, subject_suite], controller:doc});
    //console.log(JSON.stringify(result, null, 2))
    
    const verifiableCredential = [signedVC];
    const presentation = vc.createPresentation({verifiableCredential});
    //console.log(JSON.stringify(presentation, null, 2));
    challenge = "12ec21";
    const vp = await vc.signPresentation({presentation, suite:subject_suite, challenge});
    //console.log(JSON.stringify(vp, null, 2))
    const result = await vc.verify({presentation:vp, documentLoader, challenge, suite:[issuer_suite, subject_suite], controller:doc});
    console.log(result)

    

})();
