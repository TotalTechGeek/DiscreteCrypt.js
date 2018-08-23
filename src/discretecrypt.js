
function DiscreteCrypt(scrypt, bigInt, aesjs, jsSHA, bufferFunc, randomBytes)
{

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

    function scryptPromise(key, salt, N, r, p, len, progressCallback)
    {
        if(typeof key === "string")
        {
            key = [...bufferFunc(key.normalize('NFKC'))]
        }

        if(typeof salt === "string") salt = bufferFunc(salt, 'hex')


        return new Promise((resolve, reject) =>
        {
            scrypt(key, salt, N, r, p, len, (error, progress, key) =>
            {
                if(error) reject(error)
                if(key) resolve(key)
                if(progressCallback) progressCallback(progress)
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
            return new bigInt(this.public)
        }

        /**
         * @returns {bigInt}
         */
        privateKey()
        {
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
         * 
         * @param {Object} json
         * @returns {Contact} 
         */
        static fromJSON(json)
        {
            let contact = new Contact()
            for(var prop in json)
            {
                contact[prop] = json[prop]
            }
            return contact
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
         * @param {*} key 
         * @returns {Promise.<Contact>}
         */
        compute(key)
        {
            let salt = bufferFunc(this.salt, 'hex')

            return scryptPromise(key, salt, this.scryptConfig.N, this.scryptConfig.r, this.scryptConfig.p, this.scryptConfig.len).then(key =>
            {
                this.private = new bigInt(toHexString(key), 16).mod(new bigInt(this.params.prime)).toString()
                return this
            })
        }


        /**
         * Creates a contact from the given key / salt. 
         * If no salt is provided, it will randomly generate it.
         * @param {*} key 
         * @param {*} salt 
         * @returns {Promise.<Contact>}
         */
        static create(key, salt, scryptConfig, params) 
        {
            let contact = new Contact()
            function getKeyPair(key, salt)
            {
                if(typeof key === "string")
                {
                    key = bufferFunc(key.normalize('NFKC'))
                } else if(!key)
                {
                    key = randomBytes(32)
                }

                if(typeof salt === "string") salt = bufferFunc(salt, 'hex')
                else if(!salt) salt = bufferFunc('00', 'hex')

                return scryptPromise(key, salt, scryptConfig.N, scryptConfig.r, scryptConfig.p, scryptConfig.len).then(key =>
                {
                    key = new bigInt(toHexString(key), 16)
                    let pub = params.gen.modPow(key, params.prime)
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

    /**
     * 
     * @param {Contact} receiver 
     * @param {*} data 
     */
    function open(receiver, data)
    {
        let dhexchange = new bigInt(data.public, 16).modPow(receiver.privateKey(), new bigInt(receiver.params.prime)).toString(16)

        return scryptPromise([...bufferFunc(dhexchange, 'hex')], data.hmac, receiver.scryptConfig.N, receiver.scryptConfig.r, receiver.scryptConfig.p, 32).then(dhkey =>
            {
                let ctr = new aesjs.ModeOfOperation.ctr(dhkey, bufferFunc(truncate(data.hmac, 32), 'hex'))
            
                let ekey = ctr.decrypt(aesjs.utils.hex.toBytes(data.key))
            
                let ctr2 = new aesjs.ModeOfOperation.ctr(ekey, bufferFunc(truncate(data.hmac, 32), 'hex'))
            
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
     * @param {Contact} sender 
     * @param {Contact} receiver 
     */
    function exchange(sender, receiver, msg)
    {
        if(!remember[sender.public + ',' + receiver.public])
        {
            remember[sender.public + ',' + receiver.public] = receiver.publicKey().modPow(sender.privateKey(), new bigInt(sender.params.prime)).toString(16)
        }

        msg = JSON.stringify(msg)

        let dhexchange = remember[sender.public + ',' + receiver.public]
        let key = randomBytes(32)
        msg = aesjs.utils.utf8.toBytes(msg)

        let hmac = new jsSHA('SHA-256', 'ARRAYBUFFER')
        hmac.setHMACKey(key, 'ARRAYBUFFER')
        hmac.update(msg)

        hmac = hmac.getHMAC('HEX')

        return scryptPromise([...bufferFunc(dhexchange, 'hex')], hmac, receiver.scryptConfig.N, receiver.scryptConfig.r, receiver.scryptConfig.p, 32).then(dhkey =>
        {
            let ctr = new aesjs.ModeOfOperation.ctr(dhkey, bufferFunc(truncate(hmac, 32), 'hex'))

            let ekey = ctr.encrypt(key)

            ekey = aesjs.utils.hex.fromBytes(ekey)

            let ctr2 = new aesjs.ModeOfOperation.ctr(key, bufferFunc(truncate(hmac, 32), 'hex'))

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

    exports.Contact = Contact
    exports.open = open
    exports.exchange = exchange
    return exports
}

if(typeof module !== "undefined")
module.exports = DiscreteCrypt