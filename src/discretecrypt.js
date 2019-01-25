const scrypt = require('scrypt-async')
const bigInt = require('bn.js')
const aesjs = require('aes-js')
const jsSHA = require('jssha')

// Applied in Password-Based cases.
const DEFAULT_SCRYPT_CONFIG = {
    N: 1 << 14,
    r: 10,
    p: 3,
    len: 64
}

// Should be applied for performance reasons when the author is willing to accept 
// slightly reduced security for performance reasons. 
// This can securely be applied in situations where password input is reasonably decent.
const TUNED_SCRYPT_CONFIG = {
    N: 1 << 14, 
    r: 11, 
    p: 1,
    len: 48
}

// This should be applied in cases where the key doesn't need much stretching. 
// Usually due to ephemeral keys
const EPHEMERAL_SCRYPT_CONFIG = {
    N: 1 << 10, 
    r: 4, 
    p: 1,
    len: 32
}

// Funnily enough, it seems the default params can have their pohlig found in 7.    
const DEFAULT_PARAMS = {
    prime: '1236027852723267358067496240415081192016632901798652377386974104662393263762300791015297301419782476103015366958792837873764932552461292791165884073898812814414137342163134112441573878695866548152604326906481241134560091096795607547486746060322717834549300353793656273878542405925895784382400028374603183267116520399667622873636417533621785188753096887486165751218947390793886174932206305484313257628695734926449809428884085464402485504798782585345665225579018127843073619788513405272670558284073983759985451287742892999484270521626583252756445695489268987027078838378407733148367649564107237496006094048593708959670063677802988307113944522310326616125731276572628521088574537964296697257866765026848588469121515995674723869067535040253689232576404893685613618463095967906841853447414047313021676108205138971649482561844148237707440562831931089544088821151806962538015278155763187487878945694840272084274212918033049841007502061',
    gen: '2'
}

/**
 * This assumes that this is a Nearly Safe Prime, with factors under 4096 (default). 
 * @private
 * @param {BigInt|bigInt|string} prime
 * @param {Number=} range The largest allowed prime factor (aside from the pohlig itself)
 */
function pohlig(prime, range)
{
    // checks the range
    if(typeof range !== "undefined" && typeof range !== "number")
    {
        throw "Only number types are allowed for the range parameter."
    }

    /* istanbul ignore if */
    if (typeof BigInt !== "undefined")
    {
        /*
         * This assumes that this is a Nearly Safe Prime, with factors under 4096 (default). 
         * @param {BigInt|bigInt|string} prime
         * @param {Number=} range The largest allowed prime factor (aside from the pohlig itself)
         */
        function native_pohlig(prime, range)
        {
            if (typeof prime === "string") prime = BigInt(prime)
            else if (typeof prime !== "bigint") prime = BigInt(prime.toString())

            prime -= BigInt(1)
            let factors = BigInt(1)

            let max = BigInt((range || (1 << 12)) + 1)

            /* istanbul ignore next */
            for (let i = BigInt(2); i < max; i++)
            {
                while (!(prime % i))
                {
                    prime /= i
                    factors *= i
                }
            }

            return [prime.toString(), factors.toString()]
        }

        return native_pohlig(prime, range)
    }

    if (!(prime instanceof bigInt)) prime = new bigInt(prime)

    prime.isubn(1)
    let factors = new bigInt(1)
    let max = (range || (1 << 12)) + 1
    for (let i = 2; i < max; i++)
    {
        while (!prime.modn(i))
        {
            prime.idivn(i)
            factors.imuln(i)
        }
    }

    return [prime.toString(), factors.toString()]
}



/**
 * @private
 * @param {Number|String|bigInt} a base
 * @param {Number|String|bigInt} b exponent
 * @param {Number|String|bigInt} c modulus
 * @returns {bigInt} result
 */
function modPow(a, b, c)
{
    if (!(a instanceof bigInt)) a = new bigInt(a)
    if (!(b instanceof bigInt)) b = new bigInt(b)
    if (!(c instanceof bigInt)) c = new bigInt(c)

    /* istanbul ignore if */
    if (typeof BigInt !== "undefined")
    {
        function pow(a, b, c)
        {
            let one = BigInt(1)
            let res = BigInt(1)
            a = a % c;

            while (b > 0)
            {
                if (b & one)
                    res = (res * a) % c

                b = b >> one
                a = (a * a) % c
            }

            return res
        }

        a = BigInt(a.toString())
        b = BigInt(b.toString())
        c = BigInt(c.toString())

        return new bigInt(pow(a, b, c).toString())
    }
    else
    {
        let red = bigInt.red(c)
        return a.toRed(red).redPow(b).fromRed()
    }
}



/* istanbul ignore next: Browser specific code */
if(typeof window !== "undefined")
{
    if(window.crypto)
    {    
        exports.randomBytes = function(n)
        {
            let arr = new Uint8Array(n)
            window.crypto.getRandomValues(arr)
            return arr
        }
    }
    else
    {
        let warning = false
        exports.randomBytes = function(n)
        {
            if (!warning)
            {
                console.warn('Window.crypto not detected. This might be insecure, please override the exports.randomBytes function with a secure one.')
                warning = true
            }
    
            let arr = new Uint8Array(n)
            for (var i = 0; i < arr.length; i++)
            {
                arr[i] = (Math.random() * 256) | 0
            }
            return arr
        }
    }

    global.jsSHA = jsSHA
    global.bigInt = bigInt
    global.aesjs = aesjs
}



/**
 * Converts a byte array to a hex string
 * @private
 * @param {Array|Buffer|ArrayBuffer|Uint8Array} byteArray 
 */
function toHexString(byteArray)
{
    var s = '';
    byteArray.forEach(byte =>
    {
        s += ('0' + (byte & 0xFF).toString(16)).slice(-2);
    })
    return s;
}

/**
 * Gets the scrypt value.
 * @private
 * @param {String|Buffer|Array} key 
 * @param {String|Buffer|Array} salt 
 * @param {Number=} N 
 * @param {Number=} r 
 * @param {Number=} p 
 * @param {Number=} len 
 * @returns {Promise.<Uint8Array|Buffer>} derived key
 */
function scryptPromise(key, salt, N, r, p, len)
{
    if (typeof key === "string")
    {
        key = Buffer.from(key.normalize('NFKC'))
    } 
    
    if (typeof salt === "string") salt = Buffer.from(salt, 'hex')

    N = N || DEFAULT_SCRYPT_CONFIG.N
    r = r || DEFAULT_SCRYPT_CONFIG.r
    p = p || DEFAULT_SCRYPT_CONFIG.p
    len = len || DEFAULT_SCRYPT_CONFIG.len

    if(!Number.isInteger(len)) 
        return Promise.reject('Length is not a number.')    

    return new Promise((resolve, reject) =>
    {
        scrypt(key, salt,
        {
            N: N,
            r: r,
            p: p,
            dkLen: len,
            interruptStep: exports.SCRYPT_PAUSE,
            encoding: 'binary'
        }, (key) =>
        {
            resolve(key)
        })
    })
}

const PROMISE_TRICK = function()
{
    let arg = arguments
    return Contact._modifyPromise(this[0].then(contact =>
    {
        return contact[this[1]].apply(contact, arg)
    }))
}

/**
 * A stub class that doesn't actually get used, but helps with autocompletion. Allows you to use Contacts asynchronously.
 */
/*export   */class ContactPromise
{
    /**
     * 
     * @param {Function} data
     * @returns {ContactPromise}
     */
    then /* istanbul ignore next */ (data)
    {
    }

    /**
     * 
     * @param {Function} err
     * @returns {ContactPromise}      
     */
    catch /* istanbul ignore next */ (err)
    {
    }
    
    /**
     * Signs data using the Contact, using the Schnorr Signature algorithm.    
     * This is not how DiscreteCrypt  (C++) does it,
     * but it will be modified to match this approach.
     * @param {*} data 
     * @param {Boolean} bundle
     * @returns {ContactPromise}
     */
    sign /* istanbul ignore next */ (data, bundle)
    {

    }

    /**
     * Sends the data to the recipient, encrypted.
     * @param {Contact} recipient 
     * @param {*} data 
     * @returns {Promise.<Object>}
     * 
     */
    open /* istanbul ignore next */ (data)
    {

    }


    /**
     * Sends the data to the recipient, encrypted.
     * @param {Contact} recipient 
     * @param {*} data 
     * @returns {Promise.<Object>}
     */
    send /* istanbul ignore next */ (recipient, data)
    {

    }

    /**
     * Used to export the (safe) JSON for the Contact
     * @param {Object} extra 
     * @returns {ContactPromise}
     * 
     */
    export /* istanbul ignore next */ (extra)
    {

    }


    /**
     * Verifies the signed data.

     * @param {Object|Promise.<Object>=} data      
     * @param {Object|Promise.<Object>=} source      
     * @returns {ContactPromise}
     */
    verify /* istanbul ignore next */ (data, source)
    {

    }

     /**
      * Returns the public key
     * @returns {ContactPromise.<bigInt>}
     */
    publicKey /* istanbul ignore next */ ()
    {

    }

     /**
      * Returns the private key
     * @returns {ContactPromise.<bigInt>}
     */
    privateKey /* istanbul ignore next */ ()
    {

    }

    
    /**
     * Computes the private key for a contact from an input key.
     * @param {String|Buffer|Array} key 
     * @returns {ContactPromise}
     */
    compute /* istanbul ignore next */ (key)
    {

    }

    
    /**
     * 
     * @param {*} extra 
     * @returns {ContactPromise}
     * 
     */
    clean /* istanbul ignore next */ (extra)
    {

    }

}

/**
 * A contact that can be used to send or receive secure messages. Essentially an abstraction of a public/private key.
 */
/*export   */class Contact
{
    /**
     * Returns the public key
     * @returns {bigInt} public key
     */
    publicKey()
    {
        if (!this.public)
        {
            throw "Public key not set."
        }

        return new bigInt(this.public)
    }

    /**
     * Returns the private key
     * @returns {bigInt} private key
     */
    privateKey()
    {
        if (!this.private)
        {
            throw "Private key not set."
        }

        return new bigInt(this.private)
    }

    /**
     * 
     * @param {*} params 
     * @protected
     * @returns {Contact} Contact
     */
    setParams(params)
    {
        this.params = {
            prime: params.prime.toString(),
            gen: params.gen.toString()
        }
        return this
    }

    /**
     * 
     * @param {*} scryptConfig
     * @protected
     * @returns {Contact} Contact
     */
    setScrypt(scryptConfig)
    {
        this.scryptConfig = scryptConfig
        return this
    }

    /**
     * Alias for fromJSON
     * @see fromJSON
     * @param {String|Object} json
     * @returns {ContactPromise|Contact} 
     */
    static
    import(json, sync)
    {
        return this.fromJSON(json, sync)
    }

    /**
     * Imports the asynchronous version of a DiscreteCrypt Contact
     * @private
     * @param {String|Object|Promise} json 
     */
    static _fromJSONAsync(json)
    {
        if (!(json instanceof Promise))
        {
            json = Promise.resolve(json)
        }

        let contact = json.then(json =>
        {
            return Contact._fromJSONSync(json)
        })

        return this._modifyPromise(contact)
    }

    /**
     * Imports the synchronous version of a DiscreteCrypt Contact
     * @private
     * @param {String|Object} json 
     */
    static _fromJSONSync(json)
    {
        if (typeof json === "string")
        {
            json = JSON.parse(json)
        }

        let contact = new Contact()
        for (var prop in json)
        {
            contact[prop] = json[prop]
        }

        return contact
    }

    /**
     * Processes a JSON string or object, and converts it into a Contact class. 
     * 
     * @param {String|Object|Promise} json
     * @param {Boolean=} sync Determines whether this returns a synchronous contact or asynchronous.
     * If true, the input must be synchronous.
     *  @returns {ContactPromise} 
     */
    static fromJSON(json, sync)
    {
        if (sync)
        {
            return Contact._fromJSONSync(json)
        }

        return Contact._fromJSONAsync(json)
    }

    /**
     * Used to export the (safe) JSON for the Contact for sharing.
     * @param {Object} extra 
     * @returns {Object} An object that is safe to share with others
     */
    export (extra)
    {
        let res = Object.assign(
        {}, this)

        delete res.private

        if (extra)
        {
            if (extra.params || extra.all)
            {
                delete res.params
            }

            if (extra.scryptConfig || extra.all || extra.scrypt)
            {
                delete res.scryptConfig
            }
        }

        return JSON.stringify(res)
    }

    /**
     * Sends the data to the recipient, encrypted.
     * @param {Contact|ContactPromise} recipient 
     * @param {*} data
     * @returns {Promise.<Object>} Encrypted data
     */
    send(recipient, data)
    {
        return exchange(this, recipient, data)
    }

    /**
     * Opens an encrypted payload for the contact.
     * @param {*} data 
     * @returns {Promise.<Object>} Decrypted data
     */
    open(data)
    {
        return open(this, data)
    }

    /**
     * Signs data using the Contact, using the Schnorr Signature algorithm.
     * 
     * This is not how DiscreteCrypt (C++) currently handles signatures,
     * but that will be changed.
     * 
     * @param {*} data 
     * @param {Object|Promise.<Object>} data 
     * @param {Boolean} bundle allows you to specify whether the source data should be bundled in or not.
     * @returns {Promise.<Object>} Signature
     */
    sign(data, bundle)
    {
        // Performs the Schnorr Signature Algorithm

        // constants for the Scrypt step of the signature. 
        // this computes K deterministically, (similar to what is recommended in DSA)
        // in such a way that protects the upper bits of the private key.
        // I would've used an HMAC, but I didn't want any information to leak about the private key (by dividing out the hash).
        // These values can likely be tweaked quite freely.
        const N = 1 << 5
        const r = 4
        const p = 1

        // gets the private key 
        let priv = this.privateKey()

        /*
         * the following line will need to be altered based on the hash algorithm.
         * please do not forget this. it's the length of the output in bytes.
         * ensuring K > (private.length + hash.length) prevents an attacker from learning information about the private key.
         */
        const HASH_LENGTH = 32
        const len = Math.round((priv.bitLength() / 8) + HASH_LENGTH + 1)

        // Allows asynchronous input
        if (!(data instanceof Promise))
        {
            data = Promise.resolve(data)
        }
        
        // computes the signature
        return data.then(data =>
        {
            let d = Buffer.from(JSON.stringify(data))
            
            // scrypt is used to create the K value deterministically
            return exports.utils.scryptPromise(d, Buffer.from(priv.toString(16), 'hex'), N, r, p, len).then(k_derived =>
            {
                let K = new bigInt(toHexString(k_derived), 16)       
                
                // K is used to generate R
                let R = Buffer.from(modPow(this.params.gen, K, this.params.prime).toString(16), 'hex')
    
                // compute a public hash
                let hash = new jsSHA('SHA-256', 'ARRAYBUFFER')
                hash.update(R)
                hash.update(d)
                hash = hash.getHash('HEX')
                
                // computes the signature values
                let e = new bigInt(hash, 16)
                let s = K.sub(priv.mul(e))

                let result = { s: s.toString(16), e: e.toString(16) }
                
                if(bundle) result.data = data

                return result
            })
        })
    }

    /**
     * Verifies the signed data.
     * @param {Object|Promise.<Object>} data
     * @param {Object|Promise.<Object>=} source      
     * @returns {Promise.<Boolean>} 
     */
    verify(data, source)
    {
        if (!(data instanceof Promise))
        {
            data = Promise.resolve(data)
        }

        if (!(source instanceof Promise))
        {
            source = Promise.resolve(source)
        }

        return Promise.all([data, source]).then(([data, source]) =>
        {
            if (!data.s || !data.e) return Promise.reject('Signature Not Verified')
            
            let d = Buffer.from(JSON.stringify(source || data.data))
            
            // Gets the e & s bignums
            let s = new bigInt(data.s, 16)
            let e = new bigInt(data.e, 16)

            // computes the values
            let gs = modPow(this.params.gen, s, this.params.prime)
            let ye = modPow(this.publicKey(), e, this.params.prime)
            
            // multiplies them together to get R (for the hash) 
            let R = Buffer.from(gs.mul(ye).mod(new bigInt(this.params.prime)).toString(16), 'hex')

            // compute the hash
            let hash = new jsSHA('SHA-256', 'ARRAYBUFFER')
            hash.update(R)
            hash.update(d)
            hash = hash.getHash('HEX')

            // get it as a bigint
            let ev = new bigInt(hash, 16)

            if(ev.eq(e)) return source || data.data

            return Promise.reject('Signature Not Verified')
        })
    }

    /**
     * 
     * @param {*} extra 
     * @returns {Contact}
     */
    clean(extra)
    {
        delete this.private

        /* istanbul ignore else */
        if (extra)
        {
            if (extra.params || extra.all)
            {
                delete this.params
            }

            if (extra.scryptConfig || extra.scrypt || extra.all)
            {
                delete this.scryptConfig
            }
        }

        return this
    }

    /**
     * Converts the object to the fully asynchronous Contact
     * @returns {ContactPromise}
     */
    async ()
    {
        return Contact._modifyPromise(Promise.resolve(this))
    }

    static _modifyPromise(prom)
    {
        [
            'sign',
            'open',
            'send',
            'export',
            'verify',
            'publicKey',
            'privateKey',
            'compute',
            'clean'
        ].forEach(func =>
        {
            prom[func] = PROMISE_TRICK.bind([prom, func])
        })

        prom['async'] = () => prom

        return prom
    }

    /**
     * Computes the private key for a contact from an input key.
     * @param {String|Buffer|Array} key 
     * @returns {ContactPromise}
     */
    compute(key)
    {
        let salt = Buffer.from(this.salt, 'hex')

        /* istanbul ignore else : I'm trusting the user input on this one. scrypt will throw an error otherwise */
        if (typeof key === "string")
        {
            key = Buffer.from(key.normalize('NFKC'))
        }

        let scryptProm = exports.utils.scryptPromise(key, salt, this.scryptConfig.N, this.scryptConfig.r, this.scryptConfig.p, this.scryptConfig.len).then(key =>
        {
            this.private = new bigInt(toHexString(key), 16).mod(new bigInt(this.params.prime)).toString()

            let publicTest = modPow(this.params.gen, this.privateKey(), this.params.prime).toString()

            if (this.public !== publicTest) return Promise.reject("Incorrect Key")

            return this
        })

        return Contact._modifyPromise(scryptProm)
    }

    /**
     * Creates a contact from the given key / salt. 
     * 
     * @param {String|Buffer|Uint8Array|Array=} key Key, can be passed in as a string or Buffer-like object.
     * @param {String|Buffer|Uint8Array|Array=} salt Salt, can be passed in as a hex string or Buffer-like object.
     * @param {Object=} scryptConfig Configuration for Scrypt
     * @param {Object=} params Discrete Log Parameters
     * @returns {ContactPromise}
     */
    static create(key, salt, scryptConfig, params)
    {
        let contact = new Contact()

        // if there is no defined scrypt config, and no key, automatically switch to ephemeral scrypt settings.
        if(!key && typeof scryptConfig === "undefined") scryptConfig = EPHEMERAL_SCRYPT_CONFIG

        scryptConfig = scryptConfig || DEFAULT_SCRYPT_CONFIG
        params = params || DEFAULT_PARAMS

        function getKeyPair(key, salt)
        {
            // numbers get converted to a string
            if(typeof key === "number")
            {
                key = key.toString()
            }

            // strings get converted to buffers (after normalization)
            if (typeof key === "string")
            {
                key = Buffer.from(key.normalize('NFKC'))
            }
            
            // empty key or no key get one randomly generated
            if (!key || !key.length)
            {
                key = exports.randomBytes(32)
            } 

            /* istanbul ignore else: not necessary. I'm trusting that it is an array like object. */
            if (typeof salt === "string")
                salt = Buffer.from(salt, 'hex')

            return exports.utils.scryptPromise(key, salt, scryptConfig.N, scryptConfig.r, scryptConfig.p, scryptConfig.len).then(key =>
            {
                key = new bigInt(toHexString(key), 16)
                let pub = modPow(params.gen, key, params.prime)
                return [key, pub]
            })
        }

        if (salt)
        {
            contact.salt = salt
        }
        else
        {
            contact.salt = toHexString(exports.randomBytes(16))
        }

        contact.setScrypt(scryptConfig).setParams(params)

        let keyPairPromise = getKeyPair(key, contact.salt).then(([priv, pub]) =>
        {
            contact.private = priv.toString()
            contact.public = pub.toString()
            return contact
        })

        return Contact._modifyPromise(keyPairPromise)
    }
}

let remember = {}

function truncate(x, len)
{
    if (x.length > len)
    {
        return x.substring(0, len)
    }
    return x
}

// Todo: add some sort of cache cleaner for remember, to prevent memory bloat

/**
 * Opens an encrypted payload
 * @param {Contact|ContactPromise} receiver 
 * @param {*} data 
 */
/*export   */function open(receiver, data)
{
    if (!(receiver instanceof Promise))
    {
        receiver = Promise.resolve(receiver)
    }

    if (!(data instanceof Promise))
    {
        data = Promise.resolve(data)
    }

    return Promise.all([receiver, data]).then(([receiver, data]) =>
    {
        if (!remember[data.public + ',' + receiver.public])
        {
            remember[data.public + ',' + receiver.public] = modPow(new bigInt(data.public, 16), receiver.privateKey(), receiver.params.prime).toString(16)
        }

        let dhexchange = remember[data.public + ',' + receiver.public]

        return exports.utils.scryptPromise(Buffer.from(dhexchange, 'hex'), data.hmac, receiver.scryptConfig.N, receiver.scryptConfig.r, receiver.scryptConfig.p, 32).then(dhkey =>
        {
            let ctr = new aesjs.ModeOfOperation.ctr(dhkey, Buffer.from(truncate(data.hmac, 32), 'hex'))

            let ekey = ctr.decrypt(aesjs.utils.hex.toBytes(data.key))

            let ctr2 = new aesjs.ModeOfOperation.ctr(ekey, Buffer.from(truncate(data.hmac, 32), 'hex'))

            let payload = ctr2.decrypt(aesjs.utils.hex.toBytes(data.payload))

            let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
            hmac.setHMACKey(ekey, 'ARRAYBUFFER')
            hmac.update(payload)

            hmac = hmac.getHMAC('HEX')

            if (hmac === data.hmac)
            {
                payload = aesjs.utils.utf8.fromBytes(payload)
                return JSON.parse(payload)
            }
            else
            {
                return Promise.reject('Decryption failed.')
            }
        })
    })
}

/**
 * Creates an encrypted payload from the sender, to the receiver.
 * 
 * This code assumes both individuals are using the same parameters. 
 * 
 * @todo consider adding advanced options, like allowing the embedding of tuned scrypt parameters
 * on the exchange key.
 * 
 * The scrypt step is important for keysize derivation, and creates uniqueness between message exchanges,
 * but the speed is not as important in this step. 
 * 
 * @param {Contact} sender 
 * @param {Contact} receiver 
 * @param {*} msg
 */
/*export   */function exchange(sender, receiver, msg)
{
    if (!(sender instanceof Promise))
    {
        sender = Promise.resolve(sender)
    }

    if (!(receiver instanceof Promise))
    {
        receiver = Promise.resolve(receiver)
    }

    if (!(msg instanceof Promise))
    {
        msg = Promise.resolve(msg)
    }

    return Promise.all([sender, receiver, msg]).then(([sender, receiver, msg]) =>
    {
        if (!remember[sender.public + ',' + receiver.public])
        {
            remember[sender.public + ',' + receiver.public] = modPow(receiver.publicKey(), sender.privateKey(), sender.params.prime).toString(16)
        }

        msg = JSON.stringify(msg)

        let dhexchange = remember[sender.public + ',' + receiver.public]
        let key = exports.randomBytes(32)
        msg = aesjs.utils.utf8.toBytes(msg)

        let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
        hmac.setHMACKey(key, 'ARRAYBUFFER')
        hmac.update(msg)

        hmac = hmac.getHMAC('HEX')

        return exports.utils.scryptPromise(Buffer.from(dhexchange, 'hex'), hmac, receiver.scryptConfig.N, receiver.scryptConfig.r, receiver.scryptConfig.p, 32).then(dhkey =>
        {
            let ctr = new aesjs.ModeOfOperation.ctr(dhkey, Buffer.from(truncate(hmac, 32), 'hex'))

            let ekey = ctr.encrypt(key)

            ekey = aesjs.utils.hex.fromBytes(ekey)

            let ctr2 = new aesjs.ModeOfOperation.ctr(key, Buffer.from(truncate(hmac, 32), 'hex'))

            let payload = ctr2.encrypt(msg)
            payload = aesjs.utils.hex.fromBytes(payload)

            return {
                payload: payload,
                key: ekey,
                hmac: hmac,
                public: sender.publicKey().toString(16)
            }
        })
    })
}

/**
 * DiscreteCrypt Symmetric Utilities
 * @hideconstructor
 */
/*export   */class Symmetric 
{
    /**
     * Uses the Authenticated Encryption Mechanism from the DiscreteCrypt Protocol to symmetrically encrypt the data 
     * using a given input key.
     * 
     * Uses the input key rather than a DH Exchange.
     * 
     * @param {String|Buffer|Array} inputKey 
     * @param {*} msg 
     * @param {Object=} options 
     */
    static encrypt(inputKey, msg, options)
    {
        if (!options) options = {}

        if (!options.scrypt) options.scrypt = DEFAULT_SCRYPT_CONFIG

        if (typeof inputKey === "undefined")
        {
            return Promise.reject('No input key provided.')
        }

        /* istanbul ignore else */
        if (typeof inputKey === "string")
        {
            inputKey = Buffer.from(inputKey.normalize('NFKC'))
        }

        if (inputKey.length === 0)
        {
            return Promise.reject('Input key empty.')
        }

        let key = exports.randomBytes(32)

        if(!options.raw)
        {
            msg = aesjs.utils.utf8.toBytes(JSON.stringify(msg))
        }

        let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
        hmac.setHMACKey(key, 'ARRAYBUFFER')
        hmac.update(msg)
        hmac = hmac.getHMAC('HEX')

        return exports.utils.scryptPromise(inputKey, hmac, options.scrypt.N, options.scrypt.r, options.scrypt.p, 32).then(dhkey =>
        {
            let ctr = new aesjs.ModeOfOperation.ctr(dhkey, Buffer.from(truncate(hmac, 32), 'hex'))

            let ekey = ctr.encrypt(key)

            ekey = aesjs.utils.hex.fromBytes(ekey)

            let ctr2 = new aesjs.ModeOfOperation.ctr(key, Buffer.from(truncate(hmac, 32), 'hex'))

            let payload = ctr2.encrypt(msg)
            payload = aesjs.utils.hex.fromBytes(payload)

            return {
                payload: payload,
                key: ekey,
                hmac: hmac
            }
        })
    }

    /**
     * Uses the Authenticated Encryption Mechanism from the DiscreteCrypt Protocol to symmetrically encrypt the data 
     * using a given input key.
     * 
     * Uses the input key rather than a DH Exchange.
     * 
     * @param {String|Buffer|Array} inputKey 
     * @param {Object} data 
     * @param {Object=} options 
     */
    static decrypt(inputKey, data, options)
    {
        if (!options) options = {}
        if (!options.scrypt) options.scrypt = DEFAULT_SCRYPT_CONFIG

        if (typeof inputKey === "undefined")
        {
            return Promise.reject('No input key provided.')
        }

        /* istanbul ignore else */
        if (typeof inputKey === "string")
        {
            inputKey = Buffer.from(inputKey.normalize('NFKC'))
        }

        if (inputKey.length === 0)
        {
            return Promise.reject('Input key empty.')
        }

        return exports.utils.scryptPromise(inputKey, data.hmac, options.scrypt.N, options.scrypt.r, options.scrypt.p, 32).then(ikey =>
        {
            let ctr = new aesjs.ModeOfOperation.ctr(ikey, Buffer.from(truncate(data.hmac, 32), 'hex'))

            let ekey = ctr.decrypt(aesjs.utils.hex.toBytes(data.key))

            let ctr2 = new aesjs.ModeOfOperation.ctr(ekey, Buffer.from(truncate(data.hmac, 32), 'hex'))

            let payload = ctr2.decrypt(aesjs.utils.hex.toBytes(data.payload))

            let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
            hmac.setHMACKey(ekey, 'ARRAYBUFFER')
            hmac.update(payload)

            hmac = hmac.getHMAC('HEX')

            if (hmac === data.hmac)
            {
                if(!options.raw)
                {
                    payload = aesjs.utils.utf8.fromBytes(payload)
                    return JSON.parse(payload)
                }
                else
                {
                    return payload
                }
            }
            else
            {
                return Promise.reject('Decryption failed.')
            }
        })
    }
}

/**
 * Provides sane defaults for use in DiscreteCrypt.js applications
 */
/*export   */class defaults 
{
    /**
     * Returns the default parameters of DiscreteCrypt.js.
     * @returns {Object}
     */
    static params()
    {
        return Object.freeze(DEFAULT_PARAMS)
    }

    /**
     * 
     * This Scrypt configuration is the default recommended scrypt configuration.
     * This is for securing highly sensitive data in worst case conditions.
     * @returns {Object}
     */
    static scrypt()
    {
        return Object.freeze(DEFAULT_SCRYPT_CONFIG)    
    }

    /**
     * This Scrypt Configuration should be applied when the keys are ephemeral.
     * @returns {Object}
     * 
     */
    static ephemeralScrypt() 
    {
        return Object.freeze(EPHEMERAL_SCRYPT_CONFIG)
    }

    /**
     * 
     * Should be applied for performance reasons when the author is willing to accept 
     * slightly reduced security for performance reasons. 
     * 
     * This can securely be applied in situations where password input is reasonably decent.
     * 
     * Consider it a healthy middle ground between the default (top-secret) and 
     * ephemeral.
     * @returns {Object}
     */
    static tunedScrypt()
    {
        return Object.freeze(TUNED_SCRYPT_CONFIG)
    }

}

exports.utils = {
    modPow: modPow,
    truncate: truncate,
    scryptPromise: scryptPromise,
    hex: toHexString,
    pohlig: pohlig
}

exports.defaults = defaults
exports.Symmetric = Symmetric

exports.clearCache = function()
{
    remember = {}
}

exports.Contact = Contact
exports.open = open
exports.exchange = exchange
exports.SCRYPT_PAUSE = 0