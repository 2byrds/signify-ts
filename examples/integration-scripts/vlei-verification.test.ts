import { strict as assert } from 'assert';
import { getOrCreateClients } from './utils/test-setup';
import { Cigar, SignifyClient, b } from 'signify-ts';

const ECR_SCHEMA_SAID = 'EEy9PkikFcANV1l7EHukCeXqrzT1hNZjGlUk7wuMO5jw';

// This test assumes you have run a vlei test that sets up the glief, qvi, le, and
// role identifiers and Credentials.
test('vlei-verification', async function run() {
    // these come from a previous test (ex. singlesig-vlei-issuance.test.ts)
    const bran = 'CixJAl2XWVjNhj5cZu96U'; //taken from SIGNIFY_SECRETS
    const aidName = 'role';
    const [roleClient] = await getOrCreateClients(1, [bran]);
    try {
        // let resp = await roleClient.signedFetch(aidName,
        //     'http://127.0.0.1:7676',
        //     '/health',
        //     {method: 'GET',
        //     body: null,}
        // );
        // assert.equal(200,resp.status)

        let ecrCreds = await roleClient.credentials().list();
        let ecrCred = ecrCreds.find(
            (cred: any) => cred.sad.s === ECR_SCHEMA_SAID
        );
        let ecrCredHolder = await getGrantedCredential(
            roleClient,
            ecrCred.sad.d
        );
        assert(ecrCred !== undefined);
        assert.equal(ecrCredHolder.sad.d, ecrCred.sad.d);
        assert.equal(ecrCredHolder.sad.s, ECR_SCHEMA_SAID);
        assert.equal(ecrCredHolder.status.s, '0');
        assert(ecrCredHolder.atc !== undefined);
        let ecrCredCesr = await roleClient
            .credentials()
            .get(ecrCred.sad.d, true);

        let heads = new Headers();
        heads.set('Content-Type', 'application/json+cesr');
        let reqInit = { headers: heads, method: 'PUT', body: ecrCredCesr };
        // resp = await roleClient.signedFetch(
        //     aidName,
        //     'http://localhost:7676',
        //     `/presentations/${ecrCred.sad.d}`,
        //     reqInit
        // );
        // assert.equal(202, resp.status);

        let data = "\"@method\": null\n\"@path\": /request/verify/EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x\n\"signify-resource\": EP4kdoVrDh4Mpzh2QbocUYIv4IjLZLDU367UO0b40f6x\n\"signify-timestamp\": 2024-05-03T19:21:16.745000+00:00\n\"@signature-params: (@method @path signify-resource signify-timestamp);created=1714764449;keyid=BPoZo2b3r--lPBpURvEDyjyDkS65xBEpmpQhHQvrwlBE;alg=ed25519\"";
        // let raw = new TextEncoder().encode(data)
        let sig = "0BCQvbyYRY3sy_6XRWTVBNb4Ecyeuj3L6gW5xAgAIq4G6s1hO6B6LERdstaaTHCT2ZZn1ghvq-XReS0hLNFdn_sG"
        // let cig = new Cigar({ qb64: sig as string })
        let ecrAid = await roleClient.identifiers().get(aidName);
        // const keeper = this.manager!.get(ecrAid);
        // const signed_headers = authenticator.sign(
        //     new Headers(headers),
        //     headers.get('method')!,
        //     path.split('?')[0]
        // );

        // const authenticator = new Authenticater(
        //     keeper.signers[0],
        //     keeper.signers[0].verfer
        // );
        let params = new URLSearchParams({
            data: data,
            sig: sig
        }).toString();
        heads = new Headers();
        heads.set("method", "POST");
        reqInit = { headers: heads, method: "POST", body: null };
        let resp = await roleClient.signedFetch(aidName,
            'http://localhost:7676',
            `/request/verify/${ecrAid.prefix}?${params}`,
            reqInit
        );
        assert.equal(202,resp.status)

        heads.set('Content-Type', 'application/json');
        reqInit = { headers: heads, method: 'GET', body: null };
        resp = await roleClient.signedFetch(
            aidName,
            'http://localhost:7676',
            `/authorizations/${ecrAid.prefix}`,
            reqInit
        );
        assert.equal(200, resp.status);
        let body = await resp.json();
        assert.equal(body['aid'], `${ecrAid.prefix}`);
        assert.equal(body['said'], `${ecrCred.sad.d}`);

        //     heads.set("Content-Type", "application/json");
        //     reqInit = {headers: heads, method: 'POST', body: null};
        //     let data = 'this is the raw data'
        //     let raw = new TextEncoder().encode(data)
        //     let cig = hab.sign(ser=raw, indexed=False)[0]
        // assert cig.qb64 == '0BChOKVR4b5t6-cXKa3u3hpl60X1HKlSw4z1Rjjh1Q56K1WxYX9SMPqjn-rhC4VYhUcIebs3yqFv_uu0Ou2JslQL'
        //     resp = await roleClient.signedFetch(aidName, 'http://localhost:7676', `/request/verify${ecrAid.prefix}?data=data, 'sig': sig`, reqInit);
        //     assert.equal(202,resp.status)
    } catch (e) {
        console.log(e);
        fail(e);
    }
});

export async function getGrantedCredential(
    client: SignifyClient,
    credId: string
): Promise<any> {
    const credentialList = await client.credentials().list({
        filter: { '-d': credId },
    });
    let credential: any;
    if (credentialList.length > 0) {
        assert.equal(credentialList.length, 1);
        credential = credentialList[0];
    }
    return credential;
}
