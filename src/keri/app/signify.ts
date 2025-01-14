import { Controller, Agent } from "./controller"
import { Tier } from "../core/salter"
import { Authenticater } from "../core/authing"
import { KeyManager } from "../core/keeping"
import { Algos } from '../core/manager'
import { incept, rotate, interact, reply, messagize } from "../core/eventing"
import { b, Serials, Versionage, Ilks, versify, Ident} from "../core/core"
import { Tholder } from "../core/tholder"
import { MtrDex } from "../core/matter"
import { Saider } from "../core/saider"
import { Serder } from "../core/serder"
import { Siger } from "../core/siger"
import { Prefixer } from "../core/prefixer"
import { Salter } from "../core/salter"
import { randomNonce } from "./apping"

const DEFAULT_BOOT_URL = "http://localhost:3903"

export class CredentialTypes {
    static issued = "issued"
    static received = "received"
}

class State {
    agent: any | null
    controller: any | null
    ridx: number
    pidx: number

    constructor() {
        this.agent = null
        this.controller = null
        this.pidx = 0
        this.ridx = 0
    }
}

export class SignifyClient {
    public controller: Controller
    public url: string
    public bran: string
    public pidx: number
    public agent: Agent | null
    public authn: Authenticater | null
    public manager: KeyManager | null
    public tier: Tier
    public bootUrl: string

    constructor(url: string, bran: string, tier: Tier = Tier.low, bootUrl: string = DEFAULT_BOOT_URL) {
        this.url = url
        if (bran.length < 21) {
            throw Error("bran must be 21 characters")
        }
        this.bran = bran
        this.pidx = 0
        this.controller = new Controller(bran, tier)
        this.authn = null
        this.agent = null
        this.manager = null
        this.tier = tier
        this.bootUrl = bootUrl
    }

    get data() {
        return [this.url, this.bran, this.pidx, this.authn]
    }

    async boot() {
        const [evt, sign] = this.controller?.event ?? [];
        const data = {
            icp: evt.ked,
            sig: sign.qb64,
            stem: this.controller?.stem,
            pidx: 1,
            tier: this.controller?.tier
        };
        const res = await fetch(this.bootUrl + "/boot", {
            method: "POST",
            body: JSON.stringify(data),
            headers: {
                "Content-Type": "application/json"
            }
        });

        return res;
    }

    async state(): Promise<State> {
        const caid = this.controller?.pre
        let res = await fetch(this.url + `/agent/${caid}`);
        if (res.status == 404) {
            throw new Error(`agent does not exist for controller ${caid}`);
        }
        const data = await res.json();
        let state = new State();
        state.agent = data.agent ?? {};
        state.controller = data.controller ?? {};
        state.ridx = data.ridx ?? 0;
        state.pidx = data.pidx ?? 0;
        return state;
    }

    async connect() {
        const state = await this.state()
        this.pidx = state.pidx
        //Create controller representing the local client AID
        this.controller = new Controller(this.bran, this.tier, 0, state.controller)
        this.controller.ridx = state.ridx !== undefined ? state.ridx : 0
        // Create agent representing the AID of KERIA cloud agent
        this.agent = new Agent(state.agent)
        if (this.agent.anchor != this.controller.pre) {
            throw Error("commitment to controller AID missing in agent inception event")
        }
        if (this.controller.serder.ked.s == 0) {
            await this.approveDelegation()
        }
        this.manager = new KeyManager(this.controller.salter, null)
        this.authn = new Authenticater(this.controller.signer, this.agent.verfer!)
    }

    async fetch(path: string, method: string, data: any, extraHeaders?: Headers) {
        let headers = new Headers()
        let signed_headers = new Headers()
        let final_headers = new Headers()

        headers.set('Signify-Resource', this.controller.pre)
        headers.set('Signify-Timestamp', new Date().toISOString().replace('Z', '000+00:00'))
        headers.set('Content-Type', 'application/json')

        let _body = method == 'GET' ? null : JSON.stringify(data)
        if (_body !== null) {
            headers.set('Content-Length', String(_body.length))
        }
        if (this.authn) {
            signed_headers = this.authn.sign(headers, method, path.split('?')[0])
        } else {
            throw new Error('client need to call connect first')
        }
        
        signed_headers.forEach((value, key) => {
            final_headers.set(key, value)
        })
        if (extraHeaders !== undefined) {
            extraHeaders.forEach((value, key) => {
                final_headers.set(key, value)
            })
        }

        let res = await fetch(this.url + path, {
            method: method,
            body: _body,
            headers: final_headers
        });

        if (!(res.status == 200 || res.status == 202)) {
            throw new Error('response status is not 200');
        }
        const isSameAgent = this.agent?.pre === res.headers.get('signify-resource');
        if (!isSameAgent) {
            throw new Error('message from a different remote agent');
        }

        const verification = this.authn.verify(res.headers, method, path.split('?')[0]);
        if (verification) {
            return res;
        } else {
            throw new Error('response verification failed');
        }
    }

    async signedFetch(url: string, path: string, method: string, data: any, aidName: string) {
        const hab = await this.identifiers().get(aidName)
        const keeper = this.manager!.get(hab)

        const authenticator = new Authenticater(keeper.signers[0], keeper.signers[0].verfer)

        let headers = new Headers()
        headers.set('Signify-Resource', hab.prefix)
        headers.set('Signify-Timestamp', new Date().toISOString().replace('Z', '000+00:00'))
        headers.set('Content-Type', 'application/json')

        if (data !== null) {
            headers.set('Content-Length', data.length)
        }
        else {
            headers.set('Content-Length', '0')
        }
        let signed_headers = authenticator.sign(headers, method, path.split('?')[0])
        let _body = method == 'GET' ? null : JSON.stringify(data)

        return await fetch(url + path, {
            method: method,
            body: _body,
            headers: signed_headers
        });

    }

    async approveDelegation() {
        let sigs = this.controller.approveDelegation(this.agent!)

        let data = {
            ixn: this.controller.serder.ked,
            sigs: sigs
        }

        await fetch(this.url + "/agent/" + this.controller.pre + "?type=ixn", {
            method: "PUT",
            body: JSON.stringify(data),
            headers: {
                "Content-Type": "application/json"
            }
        })
    }

    async saveOldSalt(salt:string) {
        const caid = this.controller?.pre;
        const body = { salt: salt };
        return await fetch(this.url + "/salt/" + caid, {
            method: "PUT",
            body: JSON.stringify(body),
            headers: {
                "Content-Type": "application/json"
            }
        })
    }

    async deleteldSalt() {
        const caid = this.controller?.pre;
        return await fetch(this.url + "/salt/" + caid, {
            method: "DELETE",
            headers: {
                "Content-Type": "application/json"
            }
        })
    }

    identifiers() {
        return new Identifier(this)
    }

    oobis() {
        return new Oobis(this)
    }

    operations() {
        return new Operations(this)
    }

    keyEvents() {
        return new KeyEvents(this)
    }

    keyStates() {
        return new KeyStates(this)
    }

    credentials() {
        return new Credentials(this)
    }

    registries() {
        return new Registries(this)
    }

    schemas() {
        return new Schemas(this)
    }

    challenges() {
        return new Challenges(this)
    }

    contacts() {
        return new Contacts(this)
    }

    notifications() {
        return new Notifications(this)
    }
}

class Identifier {
    public client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async list() {
        let path = `/identifiers`
        let data = null
        let method = 'GET'
        let res = await this.client.fetch(path, method, data)
        return await res.json()
    }

    async get(name: string) {
        let path = `/identifiers/${name}`
        let data = null
        let method = 'GET'
        let res = await this.client.fetch(path, method, data)
        return await res.json()
    }

    async create(name: string,
        kargs: {
            transferable?: boolean,
            isith?: string | number,
            nsith?: string | number,
            wits?: string[],
            toad?: number,
            proxy?: string,
            delpre?: string,
            dcode?: string,
            data?: any,
            algo?: Algos,
            pre?: string,
            states?: any[],
            rstates?: any[]
            prxs?: any[],
            nxts?: any[],
            mhab?: any,
            keys?: any[],
            ndigs?: any[],
            bran?: string,
            count?: number,
            ncount?: number,
            tier?: Tier
        }={}) {

        const algo = kargs.algo == undefined ? Algos.salty : kargs.algo


        let transferable = kargs.transferable ?? true
        let isith = kargs.isith ?? "1"
        let nsith = kargs.nsith ?? "1"
        let wits = kargs.wits ?? []
        let toad = kargs.toad ?? 0
        let dcode = kargs.dcode ?? MtrDex.Blake3_256
        let proxy = kargs.proxy
        let delpre = kargs.delpre
        let data = kargs.data != undefined ? [kargs.data] : []
        let pre = kargs.pre
        let states = kargs.states
        let rstates = kargs.rstates
        let prxs = kargs.prxs
        let nxts = kargs.nxts
        let mhab = kargs.mhab
        let _keys = kargs.keys
        let _ndigs = kargs.ndigs
        let bran = kargs.bran
        let count = kargs.count
        let ncount = kargs.ncount
        let tier = kargs.tier

        let xargs = {
            transferable: transferable,
            isith: isith,
            nsith: nsith,
            wits: wits,
            toad: toad,
            proxy: proxy,
            delpre: delpre,
            dcode: dcode,
            data: data,
            algo: algo,
            pre: pre,
            prxs: prxs,
            nxts: nxts,
            mhab: mhab,
            states: states,
            rstates: rstates,
            keys: _keys,
            ndigs: _ndigs,
            bran: bran,
            count: count,
            ncount: ncount,
            tier: tier
        }

        let keeper = this.client.manager!.new(algo, this.client.pidx, xargs)
        let [keys, ndigs] = keeper!.incept(transferable)
        wits = wits !== undefined ? wits : []
        if (delpre == undefined) {
            var serder = incept({
                keys: keys!,
                isith: isith,
                ndigs: ndigs,
                nsith: nsith,
                toad: toad,
                wits: wits,
                cnfg: [],
                data: data,
                version: Versionage,
                kind: Serials.JSON,
                code: dcode,
                intive: false
            })

        } else {
            var serder = incept({
                keys: keys!,
                isith: isith,
                ndigs: ndigs,
                nsith: nsith,
                toad: toad,
                wits: wits,
                cnfg: [],
                data: data,
                version: Versionage,
                kind: Serials.JSON,
                code: dcode,
                intive: false,
                delpre: delpre
            })
        }

        let sigs = keeper!.sign(b(serder.raw))
        var jsondata: any = {
            name: name,
            icp: serder.ked,
            sigs: sigs,
            proxy: proxy,
            smids: states != undefined ? states.map(state => state.i) : undefined,
            rmids: rstates != undefined ? rstates.map(state => state.i) : undefined
        }
        jsondata[algo] = keeper.params(),

            this.client.pidx = this.client.pidx + 1
        let res = await this.client.fetch("/identifiers", "POST", jsondata)
        return res.json()
    }

    async interact(name: string, data?: any) {

        let hab = await this.get(name)
        let pre: string = hab.prefix

        let state = hab.state
        let sn = Number(state.s)
        let dig = state.d

        data = Array.isArray(data) ? data : [data]

        let serder = interact({ pre: pre, sn: sn + 1, data: data, dig: dig, version: undefined, kind: undefined })
        let keeper = this.client!.manager!.get(hab)
        let sigs = keeper.sign(b(serder.raw))

        let jsondata: any = {
            ixn: serder.ked,
            sigs: sigs,
        }
        jsondata[keeper.algo] = keeper.params()

        let res = await this.client.fetch("/identifiers/" + name + "?type=ixn", "PUT", jsondata)
        return res.json()

    }

    async rotate(
        name: string,
        kargs: {
            transferable?: boolean,
            nsith?: string | number,
            toad?: number,
            cuts?: string[],
            adds?: string[],
            data?: Array<object>,
            ncode?: string,
            ncount?: number,
            ncodes?: string[],
            states?: any[],
            rstates?: any[]
        }={}) {

        let transferable = kargs.transferable ?? true
        let ncode = kargs.ncode ?? MtrDex.Ed25519_Seed
        let ncount = kargs.ncount ?? 1


        let hab = await this.get(name)
        let pre = hab.prefix

        let state = hab.state
        let count = state.k.length
        let dig = state.d
        let ridx = (Number(state.s) + 1)
        let wits = state.b
        let isith = state.kt

        let nsith = kargs.nsith ?? isith


        // if isith is None:  # compute default from newly rotated verfers above
        if (isith == undefined) isith = `${Math.max(1, Math.ceil(count / 2)).toString(16)}`

        // if nsith is None:  # compute default from newly rotated digers above
        if (nsith == undefined) nsith = `${Math.max(1, Math.ceil(ncount / 2)).toString(16)}`

        let cst = new Tholder({sith: isith}).sith  // current signing threshold
        let nst = new Tholder({sith: nsith}).sith  // next signing threshold

        // Regenerate next keys to sign rotation event
        let keeper = this.client.manager!.get(hab)
        // Create new keys for next digests
        let ncodes = kargs.ncodes ?? new Array(ncount).fill(ncode)

        let states = kargs.states == undefined? [] : kargs.states
        let rstates = kargs.rstates == undefined? [] : kargs.rstates
        let [keys, ndigs] = keeper!.rotate(ncodes, transferable, states, rstates)

        let cuts = kargs.cuts ?? []
        let adds = kargs.adds ?? []
        let data = kargs.data != undefined ? [kargs.data] : []
        let toad = kargs.toad
        let serder = rotate({
            pre: pre,
            keys: keys,
            dig: dig,
            sn: ridx,
            isith: cst,
            nsith: nst,
            ndigs: ndigs,
            toad: toad,
            wits: wits,
            cuts: cuts,
            adds: adds,
            data: data
        })

        let sigs = keeper.sign(b(serder.raw))

        var jsondata: any = {
            rot: serder.ked,
            sigs: sigs,
            smids: states != undefined ? states.map(state => state.i) : undefined,
            rmids: rstates != undefined ? rstates.map(state => state.i) : undefined
        }
        jsondata[keeper.algo] = keeper.params()

        let res = await this.client.fetch("/identifiers/" + name, "PUT", jsondata)
        return res.json()
    }
    async addEndRole(name: string, role: string, eid?: string) {
        const hab = await this.get(name)
        const pre = hab.prefix

        const rpy = this.makeEndRole(pre, role, eid)
        const keeper = this.client.manager!.get(hab)
        const sigs = keeper.sign(b(rpy.raw))

        const jsondata = {
            rpy: rpy.ked,
            sigs: sigs
        }

        let res = await this.client.fetch("/identifiers/" + name + "/endroles", "POST", jsondata)
        return res.json()

    }
    makeEndRole(pre: string, role: string, eid?: string) {
        const data: any = {
            cid: pre,
            role: role
        }
        if (eid != undefined) {
            data.eid = eid
        }
        const route = "/end/role/add"
        return reply(route, data, undefined, undefined, Serials.JSON)
    }
}

class Oobis {
    public client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async get(name: string, role: string = 'agent') {
        let path = `/identifiers/${name}/oobis?role=${role}`
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()

    }

    async resolve(oobi: string, alias?: string) {
        let path = `/oobis`
        let data: any = {
            url: oobi
        }
        if (alias !== undefined) {
            data.oobialias = alias
        }
        let method = 'POST'
        let res = await this.client.fetch(path, method, data)
        return await res.json()

    }
}

class Operations {
    public client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async get(name: string) {
        let path = `/operations/${name}`
        let data = null
        let method = 'GET'
        let res = await this.client.fetch(path, method, data)
        return await res.json()

    }
}

class KeyEvents {
    public client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async get(pre: string) {
        let path = `/events?pre=${pre}`
        let data = null
        let method = 'GET'
        let res = await this.client.fetch(path, method, data)
        return await res.json()

    }
}

class KeyStates {
    public client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async get(pre: string) {
        let path = `/states?pre=${pre}`
        let data = null
        let method = 'GET'
        let res = await this.client.fetch(path, method, data)
        return await res.json()

    }

    async list(pres: [string]) {
        let path = `/states?${pres.map(pre => `pre=${pre}`).join('&')}`
        let data = null
        let method = 'GET'
        let res = await this.client.fetch(path, method, data)
        return await res.json()

    }

    async query(pre: string, sn?: number, anchor?: string) {
        let path = `/queries`
        let data: any = {
            pre: pre
        }
        if (sn !== undefined) {
            data.sn = sn
        }
        if (anchor !== undefined) {
            data.anchor = anchor
        }

        let method = 'POST'
        let res = await this.client.fetch(path, method, data)
        return await res.json()

    }
}

class Credentials {
    public client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }
    async list(name: string, kargs: {filter?: object, sort?: object[], skip?: number, limit?: number}={}) {
        let path = `/identifiers/${name}/credentials/query`
        let filtr = kargs.filter === undefined ? {} : kargs.filter;
        let sort = kargs.sort === undefined ? [] : kargs.sort;
        let limit = kargs.limit === undefined ? 25 : kargs.limit;
        let skip = kargs.skip === undefined ? 0 : kargs.skip;

        let data = {
            filter: filtr,
            sort: sort,
            skip: skip,
            limt: limit
        }
        let method = 'POST'

        let res = await this.client.fetch(path, method, data, undefined)
        return await res.json()
    }

    async get(name: string, said: string, includeCESR: boolean = false) {
        let path = `/identifiers/${name}/credentials/${said}`
        let method = 'GET'
        let headers = includeCESR? new Headers({'Accept': 'application/json+cesr'}) : new Headers({'Accept': 'application/json'})
        let res = await this.client.fetch(path, method, null, headers)

        return includeCESR? await res.text() : await res.json()
    }

    async issue(name: string, registy: string, schema: string, recipient?: string, credentialData?: any, rules?: any, source?: any, priv: boolean=false) {
        
        // Create Credential
        let hab = await this.client.identifiers().get(name)
        let pre: string = hab.prefix
        const dt = new Date().toISOString().replace('Z', '000+00:00')

        const vsacdc = versify(Ident.ACDC, undefined, Serials.JSON, 0)
        const vs = versify(Ident.KERI, undefined, Serials.JSON, 0)

        let cred: any = {
            v: vsacdc,
            d: ""
        }
        let subject: any = {
            d: "",
        }
        if (priv) {
            cred.u = new Salter({})
            subject.u = new Salter({})
        }
        if (recipient != undefined) {
            subject.i = recipient
        }
        subject.dt = dt
        subject = {...subject, ...credentialData}

        const [, a] = Saider.saidify(subject,undefined,undefined,"d")

        cred = {...cred, i:pre}
        cred.ri = registy
        cred = {...cred,...{s: schema}, ...{a: a}}

        if (source !== undefined ) {
            cred.e = source
        }
        if (rules !== undefined) {
            cred.r = rules
        }
        const [, vc] = Saider.saidify(cred)

        // Create iss
        let _iss = {
            v: vs,
            t: Ilks.iss,
            d: "",
            i: vc.d,
            s: "0",
            ri: registy,
            dt: dt

        }

        let [, iss] = Saider.saidify(_iss)

        // Create paths and sign
        let cpath = '6AABAAA-'
        let keeper = this.client!.manager!.get(hab)
        let csigs = keeper.sign(b(JSON.stringify(vc)))

        // Create ixn
        let ixn = {}
        let sigs = []

        let state = hab.state
        if (state.c !== undefined && state.c.includes("EO")) {
            var estOnly = true
        }
        else {
            var estOnly = false
        }
        let sn = Number(state.s)
        let dig = state.d

        let data:any = [{
            i: iss.i,
            s: iss.s,
            d: iss.d
        }]

        if (estOnly) {
            // TODO implement rotation event
            throw new Error("Establishment only not implemented")

        } else {
            let serder = interact({ pre: pre, sn: sn + 1, data: data, dig: dig, version: undefined, kind: undefined })
            sigs = keeper.sign(b(serder.raw))
            ixn = serder.ked
        }

        let body = {
            cred: vc,
            csigs: csigs,
            path: cpath,
            iss: iss,
            ixn: ixn,
            sigs: sigs
        }

        let path = `/identifiers/${name}/credentials`
        let method = 'POST'
        let headers = new Headers({
            'Accept': 'application/json+cesr'

        })
        let res = await this.client.fetch(path, method, body, headers)
        return await res.json()

    }

    async revoke(name: string, said: string) {
        let hab = await this.client.identifiers().get(name)
        let pre: string = hab.prefix

        const vs = versify(Ident.KERI, undefined, Serials.JSON, 0)
        const dt = new Date().toISOString().replace('Z', '000+00:00')

        let cred = await this.get(name, said)

        // Create rev
        let _rev = {
            v: vs,
            t: Ilks.rev,
            d: "",
            i: said,
            s: "1",
            p: cred.status.d,
            ri: cred.sad.ri,
            dt: dt
        }

        let [, rev] = Saider.saidify(_rev)

        // create ixn
        let ixn = {}
        let sigs = []

        let state = hab.state
        if (state.c !== undefined && state.c.includes("EO")) {
            var estOnly = true
        }
        else {
            var estOnly = false
        }

        let sn = Number(state.s)
        let dig = state.d

        let data:any = [{
            i: rev.i,
            s: rev.s,
            d: rev.d
        }]
        if (estOnly) {
            // TODO implement rotation event
            throw new Error("Establishment only not implemented")

        } else {
            let serder = interact({ pre: pre, sn: sn + 1, data: data, dig: dig, version: undefined, kind: undefined })
            let keeper = this.client!.manager!.get(hab)
            sigs = keeper.sign(b(serder.raw))
            ixn = serder.ked
        }

        let body = {
            rev: rev,
            ixn: ixn,
            sigs: sigs
        }

        let path = `/identifiers/${name}/credentials/${said}`
        let method = 'DELETE'
        let headers = new Headers({
            'Accept': 'application/json+cesr'

        })
        let res = await this.client.fetch(path, method, body, headers)
        return await res.text()

    }


    async present(name: string, said: string, recipient: string, include: boolean=true) {

        let hab = await this.client.identifiers().get(name)
        let pre: string = hab.prefix

        let cred = await this.get(name, said)
        let data = {
            i: cred.sad.i,
            s: cred.sad.s,
            n: said
        }

        const vs = versify(Ident.KERI, undefined, Serials.JSON, 0)

        const _sad = {
            v: vs,
            t: Ilks.exn,
            d: "",
            dt: new Date().toISOString().replace("Z","000+00:00"),
            r: "/presentation",
            q: {},
            a: data
        }
        const [, sad] = Saider.saidify(_sad)
        const exn = new Serder(sad)

        let keeper = this.client!.manager!.get(hab)

        let sig = keeper.sign(b(exn.raw),true)

        let siger = new Siger({qb64:sig[0]})
        let seal = ["SealLast" , {i:pre}]
        let ims = messagize(exn,[siger],seal, undefined, undefined, true)
        ims = ims.slice(JSON.stringify(exn.ked).length)


        let body = {
            exn: exn.ked,
            sig: new TextDecoder().decode(ims),
            recipient: recipient,
            include: include
        }

        let path = `/identifiers/${name}/credentials/${said}/presentations`
        let method = 'POST'
        let headers = new Headers({
            'Accept': 'application/json+cesr'

        })
        let res = await this.client.fetch(path, method, body, headers)
        return await res.text()

    }

    async request(name: string, recipient: string, schema: string, issuer: string) {

        let hab = await this.client.identifiers().get(name)
        let pre: string = hab.prefix

        let data = {
            i: issuer,
            s: schema
        }

        const vs = versify(Ident.KERI, undefined, Serials.JSON, 0)

        const _sad = {
            v: vs,
            t: Ilks.exn,
            d: "",
            dt: new Date().toISOString().replace("Z","000+00:00"),
            r: "/presentation/request",
            q: {},
            a: data
        }
        const [, sad] = Saider.saidify(_sad)
        const exn = new Serder(sad)

        let keeper = this.client!.manager!.get(hab)

        let sig = keeper.sign(b(exn.raw),true)

        let siger = new Siger({qb64:sig[0]})
        let seal = ["SealLast" , {i:pre}]
        let ims = messagize(exn,[siger],seal, undefined, undefined, true)
        ims = ims.slice(JSON.stringify(exn.ked).length)


        let body = {
            exn: exn.ked,
            sig: new TextDecoder().decode(ims),
            recipient: recipient,
        }

        let path = `/identifiers/${name}/requests`
        let method = 'POST'
        let headers = new Headers({
            'Accept': 'application/json+cesr'

        })
        let res = await this.client.fetch(path, method, body, headers)
        return await res.text()

    }
}

class Registries {
    public client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async list(name:string) {
        let path = `/identifiers/${name}/registries`
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()

    }
    async create(name: string, registryName: string, nonce?:string) {
        // TODO add backers option
        // TODO get estOnly from get_identifier ?

        let hab = await this.client.identifiers().get(name)
        let pre: string = hab.prefix

        nonce = nonce !== undefined? nonce : randomNonce()

        const vs = versify(Ident.KERI, undefined, Serials.JSON, 0)
        let vcp = {
            v: vs,
            t: Ilks.vcp,
            d: "",
            i: "",
            ii: pre,
            s: "0",
            c: ['NB'],
            bt: "0",
            b: [],
            n: nonce
        }

        let prefixer = new Prefixer({code: MtrDex.Blake3_256}, vcp)
        vcp.i = prefixer.qb64
        vcp.d = prefixer.qb64

        let ixn = {}
        let sigs = []

        let state = hab.state
        if (state.c !== undefined && state.c.includes("EO")) {
            var estOnly = true
        }
        else {
            var estOnly = false
        }
        if (estOnly) {
            // TODO implement rotation event
            throw new Error("establishment only not implemented")

        } else {
            let state = hab.state
            let sn = Number(state.s)
            let dig = state.d

            let data:any = [{
                i: prefixer.qb64,
                s: "0",
                d: prefixer.qb64
            }]

            let serder = interact({ pre: pre, sn: sn + 1, data: data, dig: dig, version: undefined, kind: undefined })
            let keeper = this.client!.manager!.get(hab)
            sigs = keeper.sign(b(serder.raw))
            ixn = serder.ked
        }

        let path = `/identifiers/${name}/registries`
        let method = 'POST'
        let data = {
            name: registryName,
            vcp: vcp,
            ixn: ixn!,
            sigs: sigs
        }
        let res = await this.client.fetch(path, method, data)
        return await res.json()
    }

}

class Schemas {
    client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async get(said: string) {
        let path = `/schema/${said}`
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()
    }

    async list() {
        let path = `/schema`
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()
    }
}

class Challenges {
    client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async generate(strength: number = 128) {
        let path = `/challenges?strength=${strength.toString()}`
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()
    }

    async respond(name: string, recipient: string, words: string[]) {
        let path = `/challenges/${name}`
        let method = 'POST'

        let hab = await this.client.identifiers().get(name)
        let pre: string = hab.prefix
        let data = {
            i: pre,
            words: words
        }

        const vs = versify(Ident.KERI, undefined, Serials.JSON, 0)

        const _sad = {
            v: vs,
            t: Ilks.exn,
            d: "",
            dt: new Date().toISOString().replace("Z","000+00:00"),
            r: "/challenge/response",
            q: {},
            a: data
        }
        const [, sad] = Saider.saidify(_sad)
        const exn = new Serder(sad)

        let keeper = this.client!.manager!.get(hab)

        let sig = keeper.sign(b(exn.raw),true)

        let siger = new Siger({qb64:sig[0]})
        let seal = ["SealLast" , {i:pre}]
        let ims = messagize(exn,[siger],seal, undefined, undefined, true)
        ims = ims.slice(JSON.stringify(exn.ked).length)

        let jsondata = {
            recipient: recipient,
            words: words,
            exn: exn.ked,
            sig: new TextDecoder().decode(ims)
        }

        let resp = await this.client.fetch(path, method, jsondata)
        if (resp.status === 202) {
            return exn.ked.d
        }
        else {
            return resp
        }
    }
    //ChallengeResourceEnd
    async accept(name: string, pre: string, said: string) {
        let path = `/challenges/${name}`
        let method = 'PUT'
        let data = {
            aid: pre,
            said: said
        }
        let res = await this.client.fetch(path, method, data)

        return res
    }
}

class Contacts {
    client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async list(group?:string, filterField?:string, filterValue?:string) {
        let params = new URLSearchParams()
        if (group !== undefined) {params.append('group', group)}
        if (filterField !== undefined && filterValue !== undefined) {params.append(filterField, filterValue)}

        let path = `/contacts`+ '?' + params.toString()
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()

    }

    async get(pre:string) {

        let path = `/contacts/`+ pre
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()

    }

    async add(pre: string, info: any) {
        let path = `/contacts/`+ pre
        let method = 'POST'

        let res = await this.client.fetch(path, method, info)
        return await res.json()
    }

    async delete(pre: string) {
        let path = `/contacts/`+ pre
        let method = 'DELETE'

        let res = await this.client.fetch(path, method, null)
        return await res.json()
    }

    async update(pre: string, info: any) {
        let path = `/contacts/` + pre
        let method = 'PUT'

        let res = await this.client.fetch(path, method, info)
        return await res.json()
    }

}

class Notifications {
    client: SignifyClient
    constructor(client: SignifyClient) {
        this.client = client
    }

    async list(last?:string, limit?:number) {
        let params = new URLSearchParams()
        if (last !== undefined) {params.append('last', last)}
        if (limit !== undefined) {params.append('limit', limit.toString())}

        let path = `/notifications` + '?' + params.toString()
        let method = 'GET'
        let res = await this.client.fetch(path, method, null)
        return await res.json()
    }

    async mark(said:string) {

        let path = `/notifications/`+ said
        let method = 'PUT'
        let res = await this.client.fetch(path, method, null)
        return await res.json()
    }

    async delete(said:string) {

        let path = `/notifications/`+ said
        let method = 'DELETE'
        let res = await this.client.fetch(path, method, null)
        return await res.json()
    }

}

