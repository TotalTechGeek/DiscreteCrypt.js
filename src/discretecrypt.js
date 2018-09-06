
function DiscreteCrypt(scrypt, bigInt, aesjs, jsSHA, Buffer, randomBytes)
{
    const DEFAULT_SCRYPT_CONFIG = {
        N: 1 << 14,
        r: 10,
        p: 3,
        len: 64
    }

    // Funnily enough, it seems the default params can have their pohlig found in 7.    
    const DEFAULT_PARAMS = {
        prime: new bigInt('1236027852723267358067496240415081192016632901798652377386974104662393263762300791015297301419782476103015366958792837873764932552461292791165884073898812814414137342163134112441573878695866548152604326906481241134560091096795607547486746060322717834549300353793656273878542405925895784382400028374603183267116520399667622873636417533621785188753096887486165751218947390793886174932206305484313257628695734926449809428884085464402485504798782585345665225579018127843073619788513405272670558284073983759985451287742892999484270521626583252756445695489268987027078838378407733148367649564107237496006094048593708959670063677802988307113944522310326616125731276572628521088574537964296697257866765026848588469121515995674723869067535040253689232576404893685613618463095967906841853447414047313021676108205138971649482561844148237707440562831931089544088821151806962538015278155763187487878945694840272084274212918033049841007502061'),
        gen: new bigInt('2')
    }


    /**
     * This assumes that this is a Nearly Safe Prime, with factors under 4096 (default). 
     * @param {BigInt|bigInt|string} prime
     * @param {Number=} range The largest allowed prime factor (aside from the pohlig itself)
     */
    function native_pohlig(prime, range)
    {
        if(typeof prime === "string") prime = BigInt(prime)
        else if(typeof prime === "object") prime = BigInt(prime.toString())

        prime -= BigInt(1)
        let factors = BigInt(1)

        let max = BigInt((range || (1 << 12)) + 1)

        for(let i = BigInt(2); i < max; i++)
        {
            while(!(prime % i))
            {
                prime /= i
                factors *= i
            }
        }

        return [prime.toString(), factors.toString()]
    }

    /**
     * This assumes that this is a Nearly Safe Prime, with factors under 4096 (default). 
     * @param {BigInt|bigInt|string} prime
     * @param {Number=} range The largest allowed prime factor (aside from the pohlig itself)
     */
    function pohlig(prime, range)
    {
        if(typeof BigInt !== "undefined")
        {
            return native_pohlig(prime, range)
        }

        if(typeof prime === "string") prime = new bigInt(prime)
        
        prime.isubn(1)
        let factors = new bigInt(1)
        let max = (range || (1 << 12)) + 1
        for(let i = 2; i < max; i++)
        {

            while(!prime.modn(i))
            {
                prime.idivn(i)
                factors.imuln(i)
            }
        }

        return [prime.toString(), factors.toString()]
    }


    function modPow(a, b, c)
    {
        if(typeof a === "string") a = new bigInt(a)
        if(typeof b === "string") b = new bigInt(b)
        if(typeof c === "string") c = new bigInt(c)

        function pow(a,b,c)
        {
            let one = BigInt(1)
            let res = BigInt(1)
            a = a % c;

            while(b > 0)
            {
                if(b & one)
                    res = (res * a) % c

                b = b >> one
                a = (a*a) % c
            }

            return res
        }

        if(typeof BigInt !== "undefined")
        {
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


    if(!randomBytes)
    {
        if(window.crypto)
        {
            randomBytes = function(n)
            {
                let arr = new Uint8Array(n)
                window.crypto.getRandomValues(arr)
                return arr
            }
        }
        else
        {
            console.warn('Window.crypto not detected. This might be insecure, please override the randomBytes function with a secure one.')
            randomBytes = function(n)
            {
                let arr = new Uint8Array(n)
                for(var i = 0; i < arr.length; i++)
                {
                    arr[i] = (Math.random() * 256) | 0
                }
                return arr
            }
        }
    }

    let exports = {}

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
     * @param {String|Buffer|Array} key 
     * @param {String|Buffer|Array} salt 
     * @param {Number=} N 
     * @param {Number=} r 
     * @param {Number=} p 
     * @param {Number=} len 
     */
    function scryptPromise(key, salt, N, r, p, len)
    {
        if(typeof key === "string")
        {
            key = [...Buffer.from(key.normalize('NFKC'))]
        }

        if(typeof salt === "string") salt = Buffer.from(salt, 'hex')

    
        N = N || DEFAULT_SCRYPT_CONFIG.N
        r = r || DEFAULT_SCRYPT_CONFIG.r
        p = p || DEFAULT_SCRYPT_CONFIG.p
        len = len || DEFAULT_SCRYPT_CONFIG.len

        return new Promise((resolve, reject) =>
        {
            scrypt(key, salt, {
                N: N,
                r: r,
                p: p,
                dkLen: len,
                interruptStep: exports.SCRYPT_PAUSE,
                encoding: 'binary'
            }, (key) =>
            {
                if(key) resolve(key)
            })
        })
    }

    class Contact 
    {
        /**
         * @returns {bigInt}
         */
        publicKey()
        {
            if(!this.public)
            {
                throw "Public key not set."
            }

            return new bigInt(this.public)
        }

        /**
         * @returns {bigInt}
         */
        privateKey()
        {
            if(!this.private)
            {
                throw "Private key not set."
            }

            return new bigInt(this.private)
        }


        /**
         * 
         * @param {*} params 
         * @returns {Contact}
         */
        setParams(params)
        {
            this.params = { prime: params.prime.toString(), gen: params.gen.toString() }
            return this
        }

        /**
         * 
         * @param {*} scryptConfig
         * @returns {Contact} 
         */
        setScrypt(scryptConfig)
        {
            this.scryptConfig = scryptConfig
            return this
        }

        /**
         * Alias for fromJSON
         * @param {String|Object} json 
         */
        static import(json)
        {
            return this.fromJSON(json)
        }


        /**
         * 
         * @param {String|Object} json
         * @returns {Contact} 
         */
        static fromJSON(json)
        {
            if(typeof json === "string")
            {
                json = JSON.parse(json)
            }

            let contact = new Contact()
            for(var prop in json)
            {
                contact[prop] = json[prop]
            }
            return contact
        }

        /**
        * Used to export the (safe) JSON for the Contact
        * @param {Object} extra 
        */
        export(extra)
        {
            let res = Object.assign({}, this)

            delete res.private

            if(extra)
            {
                if(extra.params || extra.all)
                {
                    delete res.params
                }

                if(extra.scryptConfig || extra.all)
                {
                    delete res.scryptConfig
                }
            }

            return JSON.stringify(res)
        }


        /**
         * Sends the data to the recipient, encrypted.
         * @param {Contact} recipient 
         * @param {*} data 
         */
        send(recipient, data)
        {
            return exchange(this, recipient, data)
        }

        /**
         * Opens an encrypted payload for the contact.
         * @param {*} data 
         */
        open(data)
        {
            return open(this, data)
        }


        /**
         * This is not how DiscreteCrypt (C++) does it,
         * but it will be modified to match this approach.
         * @param {*} data 
         */
        sign(data)
        {
            // todo: add BigInt native implementation
            // todo: cache pohlig values

            let d = Buffer.from(JSON.stringify(data))
            let priv = this.privateKey()

            let [ph, factor] = pohlig(this.params.prime)

            ph = new bigInt(ph)

            // compute the DSA pub key
            let g = modPow(this.params.gen, factor, this.params.prime)


            // compute a private k value by using an HMAC
            // the difference between this and DiscreteCrypt (C++) is that
            // the key for the HMAC is the private key, not the contact's password (which is secure but meh).
            let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
            hmac.setHMACKey(priv.toString(16), 'HEX')
            hmac.update(d)
            hmac = hmac.getHMAC('HEX')

            // compute a public hash
            let hash = new jsSHA('SHA-256', 'ARRAYBUFFER')
            hash.update(d)
            hash = hash.getHash('HEX')

            // perform the DSA Algorithm
            let x = priv
            let k = new bigInt(hmac, 16)
            let H = new bigInt(hash, 16)

            let r = modPow(g, k, this.params.prime).mod(ph)
            let s = k.invm(ph).imul(H.iadd(x.imul(r))).mod(ph)

            return {
                r: r.toString(16),
                s: s.toString(16), 
                data: data
            }
        }


        /**
         * Verifies the signed data.
         * @param {*} data 
         */
        verify(data)
        {
            // todo: discover ways to optimize this (unnecessary when bigint comes around).
            // takes 1.2s on non-native BigInt JS engines.
            
            // This is fine in quite a few use cases (where verification is rare, on public data),
            // but is not good in quite a few others.
            
            if(!data.s || !data.r) return false

            let pub = this.publicKey()

            let [ph, factor] = pohlig(this.params.prime)

            ph = new bigInt(ph)

            // compute the DSA pub keys
            pub = modPow(pub, factor, this.params.prime)
            let g = modPow(this.params.gen, factor, this.params.prime)

            // get the data
            let d = Buffer.from(JSON.stringify(data.data))

            // compute the hash for the data to verify against
            let hash = new jsSHA('SHA-256', 'ARRAYBUFFER')
            hash.update(d)
            hash = hash.getHash('HEX')

            // get the s & r values for verification
            let s = new bigInt(data.s, 16)
            let r = new bigInt(data.r, 16)

            // perform DSA verification
            let H = new bigInt(hash, 16)
            let w = s.invm(ph)

            let u1 = H.mul(w).mod(ph)
            let u2 = r.mul(w).mod(ph)

            let g_u1 = modPow(g, u1, this.params.prime)
            let g_u2 = modPow(pub, u2, this.params.prime)

            let v = g_u1.imul(g_u2).mod(new bigInt(this.params.prime)).mod(ph)

            return v.eq(r)
        }


        /**
         * 
         * @param {*} extra 
         * @returns {Contact}
         */
        clean(extra)
        {
            delete this.private
        
            if(extra)
            {
                if(extra.params || extra.all)
                {
                    delete this.params
                }

                if(extra.scryptConfig || extra.all)
                {
                    delete this.scryptConfig
                }
            }

            return this
        }

        /**
         * 
         * @param {String|Buffer|Array} key 
         * @returns {Promise.<Contact>}
         */
        compute(key)
        {
            let salt = Buffer.from(this.salt, 'hex')

            if(typeof key === "string")
            {
                key = Buffer.from(key.normalize('NFKC'))
            }

            return scryptPromise(key, salt, this.scryptConfig.N, this.scryptConfig.r, this.scryptConfig.p, this.scryptConfig.len).then(key =>
            {
                this.private = new bigInt(toHexString(key), 16).mod(new bigInt(this.params.prime)).toString()

                let publicTest = modPow(this.params.gen, this.privateKey(), this.params.prime).toString() 

                if(this.public !== publicTest) return Promise.reject("Incorrect Key")

                return this
            })
        }


        /**
         * Creates a contact from the given key / salt. 
         * If no salt is provided, it will randomly generate it.
         * @param {String|Buffer|Array} key 
         * @param {*} salt 
         * @param {Object=} scryptConfig
         * @param {Object=} params
         * 
         * @returns {Promise.<Contact>}
         */
        static create(key, salt, scryptConfig, params) 
        {
            let contact = new Contact()

            scryptConfig = scryptConfig || DEFAULT_SCRYPT_CONFIG
            params = params || DEFAULT_PARAMS
            
            function getKeyPair(key, salt)
            {
                if(typeof key === "string")
                {
                    key = Buffer.from(key.normalize('NFKC'))
                } else if(!key)
                {
                    key = randomBytes(32)
                }

                if(typeof salt === "string") salt = Buffer.from(salt, 'hex')
                else if(!salt) salt = Buffer.from('00', 'hex')

                return scryptPromise(key, salt, scryptConfig.N, scryptConfig.r, scryptConfig.p, scryptConfig.len).then(key =>
                {
                    key = new bigInt(toHexString(key), 16)
                    let pub = modPow(params.gen, key, params.prime)
                    return [key, pub]  
                })
            }

            if(salt)
            {
                contact.salt = salt
            }
            else
            {
                contact.salt = toHexString(randomBytes(16))
            }

            contact.setScrypt(scryptConfig).setParams(params)

            let keyPairPromise = getKeyPair(key, contact.salt).then(([priv, pub]) =>
            {
                contact.private = priv.toString()
                contact.public = pub.toString()
                return contact
            })

            return keyPairPromise
        }
    }


    let remember = {}


    function truncate(x, len)
    {
        if(x.length > len)
        {
            return x.substring(0, len)
        }
        return x
    }

    // Todo: add some sort of cache cleaner for remember, to prevent memory bloat

    /**
     * Opens an encrypted payload
     * @param {Contact} receiver 
     * @param {*} data 
     */
    function open(receiver, data)
    {
        if(!remember[data.public + ',' + receiver.public])
        {
            remember[data.public + ',' + receiver.public] =  modPow(new bigInt(data.public, 16), receiver.privateKey(), receiver.params.prime).toString(16)
        }

        let dhexchange = remember[data.public + ',' + receiver.public]

        return scryptPromise([...Buffer.from(dhexchange, 'hex')], data.hmac, receiver.scryptConfig.N, receiver.scryptConfig.r, receiver.scryptConfig.p, 32).then(dhkey =>
            {
                let ctr = new aesjs.ModeOfOperation.ctr(dhkey, Buffer.from(truncate(data.hmac, 32), 'hex'))
            
                let ekey = ctr.decrypt(aesjs.utils.hex.toBytes(data.key))
            
                let ctr2 = new aesjs.ModeOfOperation.ctr(ekey, Buffer.from(truncate(data.hmac, 32), 'hex'))
            
                let payload = ctr2.decrypt(aesjs.utils.hex.toBytes(data.payload))
            
                let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
                hmac.setHMACKey(ekey, 'ARRAYBUFFER')
                hmac.update(payload)

                hmac = hmac.getHMAC('HEX')

                if(hmac === data.hmac)
                {   
                    payload = aesjs.utils.utf8.fromBytes(payload)
                    return JSON.parse(payload)
                }
                else
                {
                    return Promise.reject('Decryption failed.')
                }
            })
    }


    /**
     * This code assumes both individuals are using the same parameters. 
     * Sends an encrypted message from the sender to the receiver.
     * 
     * @param {Contact} sender 
     * @param {Contact} receiver 
     * @param {*} msg
     */
    function exchange(sender, receiver, msg)
    {
        if(!remember[sender.public + ',' + receiver.public])
        {
            remember[sender.public + ',' + receiver.public] = modPow(receiver.publicKey(), sender.privateKey(), sender.params.prime).toString(16) 
        }

        msg = JSON.stringify(msg)

        let dhexchange = remember[sender.public + ',' + receiver.public]
        let key = randomBytes(32)
        msg = aesjs.utils.utf8.toBytes(msg)

        let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
        hmac.setHMACKey(key, 'ARRAYBUFFER')
        hmac.update(msg)

        hmac = hmac.getHMAC('HEX')

        return scryptPromise([...Buffer.from(dhexchange, 'hex')], hmac, receiver.scryptConfig.N, receiver.scryptConfig.r, receiver.scryptConfig.p, 32).then(dhkey =>
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
    }

    /**
     * Uses the Authenticated Encryption Mechanism from the DiscreteCrypt Protocol to symmetrically encrypt the data 
     * using a given input key.
     * 
     * Uses the input key rather than a DH Exchange.
     * 
     * @param {String|Buffer|Array} inputKey 
     * @param {*} msg 
     * @param {Object=} scryptConfig 
     */
    function symmetricEncrypt(inputKey, msg, scryptConfig)
    {
        if(!scryptConfig) scryptConfig = DEFAULT_SCRYPT_CONFIG

        if(typeof inputKey === "undefined")
        {
            return Promise.reject('No input key provided.')
        } 

        if(typeof inputKey === "string")
        {
            inputKey = Buffer.from(inputKey.normalize('NFKC'))
        } 

        if(inputKey.length === 0)
        {
            return Promise.reject('Input key empty.')
        }

        let key = randomBytes(32)
        msg = aesjs.utils.utf8.toBytes(JSON.stringify(msg))
        
        let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
        hmac.setHMACKey(key, 'ARRAYBUFFER')
        hmac.update(msg)
        hmac = hmac.getHMAC('HEX')

        return scryptPromise([...inputKey], hmac, scryptConfig.N, scryptConfig.r, scryptConfig.p, 32).then(dhkey =>
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
     * @param {Object=} scryptConfig 
     */
    function symmetricDecrypt(inputKey, data, scryptConfig)
    {
        if(!scryptConfig) scryptConfig = DEFAULT_SCRYPT_CONFIG
        
        if(typeof inputKey === "undefined")
        {
            return Promise.reject('No input key provided.')
        } 

        if(typeof inputKey === "string")
        {
            inputKey = Buffer.from(inputKey.normalize('NFKC'))
        } 

        if(inputKey.length === 0)
        {
            return Promise.reject('Input key empty.')
        }
        
        return scryptPromise([...inputKey], data.hmac, scryptConfig.N, scryptConfig.r, scryptConfig.p, 32).then(ikey =>
            {
                let ctr = new aesjs.ModeOfOperation.ctr(ikey, Buffer.from(truncate(data.hmac, 32), 'hex'))
            
                let ekey = ctr.decrypt(aesjs.utils.hex.toBytes(data.key))
            
                let ctr2 = new aesjs.ModeOfOperation.ctr(ekey, Buffer.from(truncate(data.hmac, 32), 'hex'))
            
                let payload = ctr2.decrypt(aesjs.utils.hex.toBytes(data.payload))
            
                let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
                hmac.setHMACKey(ekey, 'ARRAYBUFFER')
                hmac.update(payload)

                hmac = hmac.getHMAC('HEX')

                if(hmac === data.hmac)
                {   
                    payload = aesjs.utils.utf8.fromBytes(payload)
                    return JSON.parse(payload)
                }
                else
                {
                    return Promise.reject('Decryption failed.')
                }
            })
    }

    exports.utils = {
        truncate: truncate,
        scryptPromise: scryptPromise,
        hex: toHexString,
        randomBytes: randomBytes,
        pohlig: pohlig
    }

    exports.Symmetric = {
        encrypt: symmetricEncrypt,
        decrypt: symmetricDecrypt
    }

    exports.clearCache = function()
    {
        remember = {}
    }

    exports.Contact = Contact
    exports.open = open
    exports.exchange = exchange
    exports.SCRYPT_PAUSE = 0
    return exports
}

if(typeof module !== "undefined")
module.exports = DiscreteCrypt