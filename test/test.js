const assert = require('assert')
const DiscreteCrypt = require('../index.js')

 // scrypt tuned down for performance, since security isn't necessary here.
 let scrypt = DiscreteCrypt.defaults.ephemeralScrypt()

const PW = 'Hello World'
const SALT = '00'
const TXT = 'Hello, World'

let contact = DiscreteCrypt.Contact.create(PW, SALT, scrypt), contact2 = DiscreteCrypt.Contact.create(null, null, scrypt)
let signedData = contact.sign(TXT)

describe('DiscreteCrypt.Contact', () =>
{
    describe('#create', () =>
    {
        function checkHas(test, attr, contact)
        {
            it(test, (done) =>
            {
                contact.then(contact =>
                {
                    if(typeof contact[attr] === "undefined") return done(new Error())
                    return done()
                })
            })
        }

        it('should create a contact', (done) =>
        {
            contact.then(contact =>
            {
                if(typeof contact === "undefined") return done(new Error())
                return done()
            })
        })

        checkHas('should have a salt', 'salt', contact)
        checkHas('should have a salt, randomly generated if no salt provided', 'salt', contact2)
        checkHas('should have a private key', 'private', contact)
        checkHas('should have a private key, randomly generated if no key provided', 'private', contact2)
        checkHas('should have a public key', 'public', contact)
        checkHas('should have the DH parameters', 'params', contact)
        checkHas('should have the scrypt parameters', 'scryptConfig', contact)

        it('private key matches (scrypt check)', (done) =>
        {
            contact.then(contact =>
            {   
                if(contact.private === '100393829911931591529540054103479785938321494005673330544449391501206113347665')
                    return done()
                return done(new Error())
            })
        })

        it('public key matches (bignum check)', (done) =>
        {
            contact.then(contact =>
            {   
                if(contact.public === '979253254867288891967997159876475563523428315115070379898037410671970893052378719795080920134161132722536212738117574115401782451094787522598090992054372064598686322515206942690533325183109033388366388258967054364511924791230936162994441799393174462328138452995963359794559067052401106064676446149140165062957043023531815547806211569202228452738862014602884695411418059172452846425814972935346893067365822215836958732024701103216644016550924411802573560930362399946418617062948752292904645917298505214852822434175598397098613310094987763255685554011756285786491020221665846580644712301750701767223394947590841613567365320360471998600391508649023989443901075181195196400874248346469507662246760605179726496644492617699071146687559977651160685004158105198747086131185838869841361510252394788459024726812022545674342067414667845399676006168448374914787462159370004197462147612033356205470238970206950413832384381187006393689014778')
                    return done()
                return done(new Error())
            })
        })
        
    })

    describe('#export', () =>
    {
        it('should not have a private key', (done) =>
        {
            contact.then(contact =>
            {
                contact = JSON.parse(contact.export())
                if(typeof contact.private !== "undefined") return done(new Error())
                return done()
            })
        })


        it('should remove the scrypt', (done) =>
        {
            contact.then(contact =>
            {
                contact = JSON.parse(contact.export({ scrypt : true }))
                if(typeof contact.scryptConfig !== "undefined") return done(new Error())
                return done()
            })
        })


        it('should remove the params', (done) =>
        {
            contact.then(contact =>
            {
                contact = JSON.parse(contact.export({ params: true }))
                if(typeof contact.params !== "undefined") return done(new Error())
                return done()
            })
        })
    })


    describe('#sign', () =>
    {
        it('should output an object with r, s, and the data', (done) =>
        {
            signedData.then(data =>
            {
                if(data.s && data.e && data.data)
                {
                    if(data.data === TXT)
                    {
                        return done()
                    }
                }

                return done(new Error())
            })
        })
    })

    describe('#privateKey', () =>
    {
        it('should return an object', (done) =>
        {
            contact.privateKey().then(priv =>
            {
                if(typeof priv === "object") return done()
                return done(new Error())
            })
        })

        it('should throw an error if no private key', (done) =>
        {
            // test chained asynchronous methods
            DiscreteCrypt.Contact.import(contact.export()).privateKey().then(priv =>
            {
                return done(new Error())
            }).catch(err =>
            {
                return done()
            })
        })
    })

    describe('#publicKey', () =>
    {
        it('should return an object', (done) =>
        {
            contact.publicKey().then(pub =>
            {
                if(typeof pub === "object") return done()
                return done(new Error())
            })
        })

        it('should throw an error if no public key', (done) =>
        {
            contact.then(contact =>
            {
                try {
                    // I need a synchronous contact for this to be easy
                    contact = DiscreteCrypt.Contact.import(contact.export(), true)
                    contact.public = 0
                    contact.publicKey()
                    return done(new Error())
                }
                catch(ex)
                {
                    return done()
                }

            })
        })
    })

    describe('#async', () =>
    {
        // should convert to the asynchronous promise structure
        it('should convert to the asynchronous promise structure', (done) =>
        {
            // clones the contact
            DiscreteCrypt.Contact.import(contact.async()).then(contact =>
            {
                if(contact instanceof DiscreteCrypt.Contact)
                {
                    contact = contact.async()
                    if(contact instanceof Promise)
                    {
                        // check if it has these functions
                        if(contact.send && contact.open)
                        {
                            return done()
                        }
                    }
                }
                return done(new Error())
            })
        })
    })

    describe('#verify', () =>
    {
        it('should verify when the signature is real', (done) =>
        {
            contact.verify(signedData).then(valid =>
            {
                if(valid) return done()
                return done(new Error())
            })
        })

        it('should not verify when the signature is false', (done) =>
        {
            signedData.then(data =>
            {
                data.s = '1234567'
                contact.verify(data).then(valid =>
                {
                    if(!valid) return done()
                    return done(new Error())
                }).catch(err =>
                {
                    return done(new Error())
                })
            })

        })

    })

    // also tests the import code.
    describe('#compute', () =>
    {
        it('should correctly compute and add the private key', (done) =>
        {
            contact.then(contact =>
            {   
                DiscreteCrypt.Contact.import(contact.export()).compute('Hello World').then(contact =>
                {
                    if(typeof contact.private === "undefined") return done(new Error())
                    if(contact.private !== '100393829911931591529540054103479785938321494005673330544449391501206113347665') return done(new Error())
                    return done()
                }).catch(() =>
                {
                    return done(new Error())
                })
            })
        })

        it('should correctly reject the key', (done) =>
        {
            contact.then(contact =>
            {   
                DiscreteCrypt.Contact.import(contact.export()).compute('Hello, World!').then(contact =>
                {
                    return done(new Error())
                }).catch(() =>
                {
                    return done()
                })
            })
        })
    })

    describe('#send', () =>
    {
        it('should call the exchange code and open as expected (using asynchronous data)', (done) =>
        {
            contact2.open(contact.send(contact2, Promise.resolve(TXT))).then(data =>
            {
                if(data === TXT) return done()
                return done(new Error())
            }).catch(err =>
            {
                return done(new Error())
            })
        })

    })


    // also tests import code
    describe('#clean', () =>
    {
        it('should remove the params from the cleaned object', (done) =>
        {
            contact.then(contact =>
            {
                contact = DiscreteCrypt.Contact.import(contact)
                contact.clean({ params : true })
                if(contact.params) return done(new Error())
                return done()
            })
        })

        it('should remove the scrypt from the cleaned object', (done) =>
        {
            contact.then(contact =>
            {
                contact = DiscreteCrypt.Contact.import(contact)
                contact.clean({ scrypt : true })
                if(contact.scryptConfig) return done(new Error())
                return done()
            })
        })


        it('should remove the scrypt & params from the cleaned object', (done) =>
        {
            contact.then(contact =>
            {
                contact = DiscreteCrypt.Contact.import(contact)
                contact.clean({ all : true })
                if(contact.scryptConfig || contact.params) return done(new Error())
                return done()
            })
        })
    
    })
})

// Creates an exchange, and tests with a synchronous version of the contact
let exchange = contact2.then(contact2 => DiscreteCrypt.exchange(contact, contact2, 'Hello World!'))

describe('DiscreteCrypt', () =>
{
    describe('#exchange', () =>
    {
        it('Exchange is created', (done) =>
        {
            exchange.then(msg =>
            {
                if(msg === "undefined") return done(new Error())
                return done()
            }).catch(() =>
            {
                return done(new Error())
            })
        })

        it('Exchange has sender public key', (done) =>
        {
            exchange.then(msg =>
            {
                contact.then(contact =>
                {
                    if(msg['public'] === "undefined" && msg['public'] === contact['public']) return done(new Error())
                    return done()
                })
            }).catch(() =>
            {
                return done(new Error())
            })
        })
    })

    describe('#open', () =>
    {
        it('Exchange is opened', (done) =>
        {
            exchange.then(exchange =>
            {
                // test synchronous data
                DiscreteCrypt.open(contact2, exchange).then(msg =>
                {
                    if(msg === "undefined") return done(new Error())
                    if(msg !== "Hello World!") return done(new Error())
                    return done()
                }).catch(() =>
                {
                    return done(new Error())
                })
            })
        })

        it('Bad Exchange is rejected', (done) =>
        {
            DiscreteCrypt.open(contact, exchange).then(() =>
            {
                return done(new Error())
            }).catch(err =>
            {
                return done()
            })
        })

    })
})

describe('DiscreteCrypt', () =>
{
    describe('#clearCache', () =>
    {
        it('should execute without issue', () =>
        {
            DiscreteCrypt.clearCache()
        })
    })

    describe('utils', () =>
    {
        describe('#pohlig', () =>
        {
            it('should compute the Pohlig-Hellman prime from the Nearly-Safe Prime', (done) =>
            {
                let val = DiscreteCrypt.utils.pohlig(DiscreteCrypt.defaults.params().prime)[1]
                if(val == 420) return done()
                return done(new Error())
            })
        })

        describe('#scryptPromise', () =>
        {
            // todo: more tests in here, though it is already covered by other tests tbh.
            let scryptP = DiscreteCrypt.utils.scryptPromise(TXT, '00', scrypt.N, scrypt.r, scrypt.p, scrypt.len)

            it('should be able to process string input', (done) =>
            {
                scryptP.then(data =>
                {
                    return done()
                })
            })

            it('should match the test vector (output test)', (done) =>
            {
                scryptP.then(data =>
                {
                    if(DiscreteCrypt.utils.hex(data).toLowerCase() === '8a2d641456a541d54ed820b4d891399028b6df7df6736ce818717855751690ab')
                        return done()
                })
            })
        })

        describe('#truncate', () =>
        {
            it('should truncate to a specified len', (done) =>
            {
                let v = DiscreteCrypt.utils.truncate('0'.repeat(32), 16)
                if(v.length == 16) return done()
                return done(new Error())
            })

            it('should not need to truncate if under the length', (done) =>
            {
                let v = DiscreteCrypt.utils.truncate('0'.repeat(14), 16)
                if(v.length == 14) return done()
                return done(new Error())
            })
        })
    })

    describe('defaults', () =>
    {
        describe('#params', () =>
        {
            // I could test for the default values in here, but these are subject to change so eh. 
            it('should get the default params', (done) =>
            {
               let params = DiscreteCrypt.defaults.params()
               if(params.prime && params.gen) return done()
               return done(new Error())
            })
        })

        describe('#scrypt', () =>
        {
            it('should get the default scrypt', (done) =>
            {
                // I could test for the default values in here, but these are subject to change so eh. 
                let config = DiscreteCrypt.defaults.scrypt()
                if(config.N && config.r && config.p && config.len)
                {
                    return done()
                }
                return done(new Error())

            })
        })

        describe('#ephemeralScrypt', () =>
        {
            it('should get the tuned scrypt', (done) =>
            {
                // I could test for the default values in here, but these are subject to change so eh. 
                let config = DiscreteCrypt.defaults.tunedScrypt()
                if(config.N && config.r && config.p && config.len)
                {
                    return done()
                }
                return done(new Error())
            })
        })

        describe('#ephemeralScrypt', () =>
        {
            it('should get the ephemeral scrypt', (done) =>
            {
                // I could test for the default values in here, but these are subject to change so eh. 
                let config = DiscreteCrypt.defaults.ephemeralScrypt()
                if(config.N && config.r && config.p && config.len)
                {
                    return done()
                }
                return done(new Error())
            })
        })
    })

    describe('Symmetric', () =>
    {
        const SYM_KEY = 'Hello, World!'
        const WRONG_KEY = 'Wrong, Key!'
        const MESSAGE = 'This is the message.'
        let encryption = DiscreteCrypt.Symmetric.encrypt(SYM_KEY, MESSAGE, DiscreteCrypt.defaults.ephemeralScrypt()) 
        let decryption = encryption.then(i=>DiscreteCrypt.Symmetric.decrypt(SYM_KEY, i, DiscreteCrypt.defaults.ephemeralScrypt()))

        describe('#encrypt', () =>
        {
            it('should reject upon empty key', (done) =>
            {
                DiscreteCrypt.Symmetric.encrypt('', MESSAGE).then(() =>
                {
                    return done(new Error())
                }).catch(c =>
                {
                    return done()
                })
            })

            it('should reject upon no key', (done) =>
            {
                DiscreteCrypt.Symmetric.encrypt(undefined, MESSAGE).then(() =>
                {
                    return done(new Error())
                }).catch(c =>
                {
                    return done()
                })
            })

            it('should produce result', (done) =>
            {
                encryption.then(result =>
                {
                    if(result) return done()
                    return done(new Error())
                })
            })
        })

        describe('#decrypt', () =>
        {
            it('should reject upon empty key', (done) =>
            {
                DiscreteCrypt.Symmetric.decrypt('', MESSAGE).then(() =>
                {
                    return done(new Error())
                }).catch(c =>
                {
                    return done()
                })
            })

            it('should reject upon no key', (done) =>
            {
                DiscreteCrypt.Symmetric.decrypt(undefined, MESSAGE).then(() =>
                {
                    return done(new Error())
                }).catch(c =>
                {
                    return done()
                })
            })

            it('should decrypt properly', (done) =>
            {
                decryption.then(result =>
                {
                    if(result && result === MESSAGE)
                    {
                        return done()
                    }

                    return done(new Error())
                })
            })

            it('should reject upon failed decryption', (done) =>
            {
                encryption.then(i=>DiscreteCrypt.Symmetric.decrypt(WRONG_KEY, i, scrypt)).then(result =>
                {
                    return done(new Error())
                }).catch(error =>
                {
                    return done()
                })
            })
        })
    })


})