import * as crypto from "crypto";

export function getSigningAlgorithm(shortName?: string): string {
  switch (shortName) {
    case "rsa-sha256-MGF1":
      return "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
    case "sha256":
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    case "sha512":
      return "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
    case "sha1":
    default:
      return "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  }
}

export function getDigestAlgorithm(shortName?: string): string {
  switch (shortName) {
    case "sha256":
      return "http://www.w3.org/2001/04/xmlenc#sha256";
    case "sha512":
      return "http://www.w3.org/2001/04/xmlenc#sha512";
    case "sha1":
    default:
      return "http://www.w3.org/2000/09/xmldsig#sha1";
  }
}

export function getSigner(shortName?: string) {
  // The return type of `crypto.createSign` is `crypto.Sign`, but in Node@14, it fails compilation if specified; it is correct inferred if not specified
  switch (shortName) {
    case "rsa-sha256-MGF1":
    case "sha256":
      return crypto.createSign("RSA-SHA256");
    case "sha512":
      return crypto.createSign("RSA-SHA512");
    case "sha1":
    default:
      return crypto.createSign("RSA-SHA1");
  }
}

/**
 * Returns the key input to pass to `Sign.sign()`. RSASSA-PSS (MGF1) needs the padding and salt
 * length passed alongside the key; the other algorithms use PKCS#1 v1.5 and take the key as-is.
 */
export function getSigningKey(
  shortName: string | undefined,
  privateKey: string
): string | crypto.SignPrivateKeyInput {
  if (shortName === "rsa-sha256-MGF1") {
    return {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
    };
  }
  return privateKey;
}

/**
 * xml-crypto signature algorithm for http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1
 * (RSASSA-PSS, RFC 6931 section 2.3.10), which xml-crypto does not provide itself.
 */
export class RsaSha256Mgf1SignatureAlgorithm {
  getSignature(signedInfo: string, signingKey: string | Buffer): string {
    return crypto
      .sign("sha256", Buffer.from(signedInfo), {
        key: signingKey,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        // RFC 6931 default: salt length equals the digest length
        saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST,
      })
      .toString("base64");
  }

  verifySignature(str: string, key: string | Buffer, signatureValue: string): boolean {
    return crypto.verify(
      "sha256",
      Buffer.from(str),
      {
        key,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        // Accept any salt length the signer chose; xml-crypto does not expose RSAPSSParams
        saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
      },
      Buffer.from(signatureValue, "base64")
    );
  }

  getAlgorithmName(): string {
    return "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
  }
}
