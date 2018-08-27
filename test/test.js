const assert = require('assert')
const DiscreteCrypt = require('../index.js')

 // scrypt tuned down for performance, since security isn't necessary here.
 let scrypt = {
    N: 1 << 10, 
    r: 4, 
    p: 1,
    len: 32
}


let contact = DiscreteCrypt.Contact.create('Hello World', '00', scrypt)
let contact2 = DiscreteCrypt.Contact.create(null, null, scrypt)

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
})


let exchange = Promise.all([contact, contact2]).then(([contact, contact2]) =>
{
    return DiscreteCrypt.exchange(contact, contact2, 'Hello World!')
})


let open_exchange = Promise.all([exchange, contact2]).then(([exchange, contact2]) =>
{
    return DiscreteCrypt.open(contact2, exchange)
})



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
            open_exchange.then(msg =>
            {
                if(msg === "undefined") return done(new Error())
                if(msg !== "Hello World!") return done(new Error())
                return done()
            }).catch(() =>
            {
                return done(new Error())
            })
        })

        it('Bad Exchange is rejected', (done) =>
        {
            Promise.all([exchange, contact]).then(([exchange, contact]) =>
            {
                return DiscreteCrypt.open(contact, exchange)
            }).then(() =>
            {
                return done(new Error())
            }).catch(err =>
            {
                return done()
            })
        })

    })
})