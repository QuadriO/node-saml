import * as crypto from "crypto";
import * as fs from "fs";
import * as querystring from "querystring";
import { expect } from "chai";
import { SAML } from "../src/saml";
import { signSamlPost } from "../src/saml-post-signing";
import { parseDomFromString, validateSignature } from "../src/xml";
import * as algorithms from "../src/algorithms";

const MGF1_URI = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
const signingKey = fs.readFileSync(__dirname + "/static/key.pem");
const signingCert = fs.readFileSync(__dirname + "/static/cert.pem", "utf-8");

const verifyPss = (data: string, cert: string, signature: string): boolean =>
  crypto.verify(
    "sha256",
    Buffer.from(data),
    {
      key: cert,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
      saltLength: crypto.constants.RSA_PSS_SALTLEN_AUTO,
    },
    Buffer.from(signature, "base64")
  );

describe("rsa-sha256-MGF1 (RSASSA-PSS) signing", function () {
  it("maps the rsa-sha256-MGF1 option to the MGF1 algorithm URI", function () {
    expect(algorithms.getSigningAlgorithm("rsa-sha256-MGF1")).to.equal(MGF1_URI);
  });

  it("signs redirect binding requests with RSASSA-PSS", async function () {
    const samlObj = new SAML({
      entryPoint: "https://idp.example.com/sso",
      issuer: "onelogin_saml",
      callbackUrl: "https://sp.example.com/callback",
      privateKey: fs.readFileSync(__dirname + "/static/acme_tools_com.key", "utf-8"),
      signatureAlgorithm: "rsa-sha256-MGF1",
      cert: signingCert,
    });
    const authorizeUrl = await samlObj.getAuthorizeUrlAsync("", "", {});
    const qry = querystring.parse(new URL(authorizeUrl).search.substring(1));
    expect(qry.SigAlg).to.equal(MGF1_URI);

    const signedData = querystring.stringify({ SAMLRequest: qry.SAMLRequest, SigAlg: qry.SigAlg });
    const cert = fs.readFileSync(__dirname + "/static/acme_tools_com.cert", "utf-8");
    expect(verifyPss(signedData, cert, qry.Signature as string)).to.be.true;
  });

  it("signs POST binding XML with RSASSA-PSS and validates it", async function () {
    const xml =
      '<SAMLRequest ID="_abc123"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></SAMLRequest>';
    const signed = signSamlPost(xml, "/SAMLRequest", {
      privateKey: signingKey,
      signatureAlgorithm: "rsa-sha256-MGF1",
      digestAlgorithm: "sha256",
    });
    expect(signed).to.contain(`<SignatureMethod Algorithm="${MGF1_URI}"/>`);

    const dom = await parseDomFromString(signed);
    expect(validateSignature(signed, dom.documentElement, [signingCert])).to.be.true;
  });

  it("rejects a tampered RSASSA-PSS signed XML document", async function () {
    const xml =
      '<SAMLRequest ID="_abc123"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://example.com</saml2:Issuer></SAMLRequest>';
    const signed = signSamlPost(xml, "/SAMLRequest", {
      privateKey: signingKey,
      signatureAlgorithm: "rsa-sha256-MGF1",
      digestAlgorithm: "sha256",
    });
    const tampered = signed.replace("http://example.com", "http://evil.example.com");

    const dom = await parseDomFromString(tampered);
    expect(validateSignature(tampered, dom.documentElement, [signingCert])).to.be.false;
  });
});
