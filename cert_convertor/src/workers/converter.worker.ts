import forge from 'node-forge';

const ctx: Worker = self as any;

ctx.addEventListener('message', async (event) => {
  const { buffer, password, action } = event.data;

  if (action === 'CONVERT_PFX') {
    try {
      // Create a forge buffer from the ArrayBuffer
      const p12Der = forge.util.createBuffer(new Uint8Array(buffer));
      const p12Asn1 = forge.asn1.fromDer(p12Der);
      
      // Attempt to load the PKCS#12 bundle
      const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

      let pem = '';
      // Iterate through bags to extract Private Keys and Certificates
      for (const t of Object.keys(p12.bags)) {
        const bags = p12.bags[t];
        for (const bag of bags) {
          if (bag.key) pem += forge.pki.privateKeyToPem(bag.key);
          if (bag.cert) pem += forge.pki.certificateToPem(bag.cert);
        }
      }

      ctx.postMessage({ status: 'success', data: pem });
    } catch (error) {
      ctx.postMessage({ 
        status: 'error', 
        message: 'Decryption failed. Please verify the password.' 
      });
    }
  }
});