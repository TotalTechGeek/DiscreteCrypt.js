# Getting Started

Welcome to DiscreteCrypt.js! 

First, I feel like we need to clarify what the term "Contact" means in DiscreteCrypt. It is an object-oriented abstraction of public key cryptography, to make it easier to think about the flow of data.

You can create a personal contact (private key), or you can receive other people's contacts (public keys).

## Creating an Ephemeral Contact

Let's start by creating an ephemeral contact.

This is a type of contact that is not meant to be recovered, and is good for one-off sessions.

```js
let me = DiscreteCrypt.Contact.create()

me.export().then(contact =>
{
    // send the "contact" variable to someone else, over Ajax or websocket.
}) 
```

## Importing Someone's Contact 

Here is how one should import an exported contact.

```js
let you = DiscreteCrypt.Contact.import(receivedContact)
```

## Encrypting Data for a Contact

Let's encrypt data for someone's contact. This uses asymmetric cryptography to ensure only the intended recipient can open the message.

```js
me.send(you, "Hey, this is a secret message").then(encrypted =>
{
    // send the "encrypted" variable over ajax or websocket
})
```

You are not limited to strings. You can send any other JSON-serializable type using DiscreteCrypt.js (like Numbers, Booleans, Arrays, Objects)


## Opening Encrypted Data 

To open received data, just do the following: 

```js
me.open(dataFromYou).then(data =>
{
    // Hey! we decrypted this and got the data back :)
    console.log(data)
}).catch(err =>
{
    // Oh no! It didn't decrypt properly. 
    console.error(err)
})
```

## Creating a Long-Term Contact

Now we're getting into PGP/GPG territory. This is a contact that you intend to use over a longer period of time, and not just for a one-off chat session with someone. 

To do this, all you need to do is pass in a key in the "Create" method.

```js
// the key doesn't have to be a string. You can actually use any Uint8Array or Buffer-like structure.
let me = DiscreteCrypt.Contact.create("SuperSecurePassword")
```

To store it, you'll need to export it (which you need to do anyway for other people to "contact" you).

```js
me.export().then(contact =>
{
    // store contact somewhere, in a database or in a json file or something.
})
```

Then you can load it back in by importing it and executing the "compute" method, restoring your "personal"/private access. 

```js
// me_stored is your exported contact loaded in from a file
let me = DiscreteCrypt.Contact.import(me_stored).compute("SuperSecurePassword")
```

In crypto-terms: This allows you to easily recover your private key from your public key. This is only possible because your private key is derived using scrypt (which makes brute-force exceptionally difficult). 

These long-term contacts can be used for a variety of things, like securing communication of nodes in a cloud cluster, or allowing you to create a really modern end-to-end encrypted chat app.  



# Symmetric 

You can also use DiscreteCrypt.js to encrypt data symmetrically. This can be done in two ways:

## Using Contacts

You could in theory send data to your own contact.

```js

// creates a long term contact to store
let me = DiscreteCrypt.Contact.Create('some pass')

me.export().then(contact_to_store =>
{
    // store it somewhere
})

me.send(me, { a: 'Secret Data' }).then(encrypted =>
{
    // encrypted data only your contact file can open
})
```


## Using Symmetric Utilities

By removing the key exchange steps of the DiscreteCrypt protocol, the scheme can be simplified to a convenient symmetric authenticated encryption scheme.


### Encrypt

To encrypt:

```js
DiscreteCrypt.Symmetric.encrypt('password', data).then(encrypted_data =>
{
    // do something with the encrypted data, like store it
})
```

### Decrypt

And decrypting is very similar:

```js
DiscreteCrypt.Symmetric.decrypt('password', encrypted_data).then(decrypted_data =>
{
    // do something with the decrypted data,
    console.log(decrypted_data)
})
```

# Signatures

Some might want to be able to use their contacts to "sign" data. Here's how:

## Signing

Here is how to sign data:

```js
// assuming "me" is a contact

me.sign(data).then(sig =>
{
    // <code to send the signature somewhere>
})
```

## Verifying 

```js
me.verify(sig, data).then(data =>
{
    // the data verified against is passed to then
}).catch(err =>
{
    // rejects if not verified
})
```


## Signature Bundling

You are also able to bundle in the source data with the signature itself. This might be useful if you plan to release the data along with the signature anyway.

### Signing

```js
me.sign(data, true).then(sig =>
{
    // the data is bundled in with the signature.
    // <code to send the bundled signature somewhere>

})
```

### Verifying

```js
me.verify(sig).then(data =>
{
    // returns the data that was verified by the signature
}).catch(err =>
{

})
```


# Advanced

## Tuning Scrypt Performance

DiscreteCrypt's various functions will allow you to manually tune their performance based on security thresholds you feel comfortable with.

By default, DiscreteCrypt is tuned to its strictest security parameters (though DiscreteCrypt automatically optimizes the performance of ephemeral contacts). These parameters are tuned in an attempt to guarantee their lifetimes will outlast your own.

We offer three sane defaults for Scrypt Parameters:

Type | Method | Explanation
-- | -- |  --
Default | `DiscreteCrypt.defaults.scrypt()` | Strict. Makes it extremely difficult to bruteforce the key-space. Should protect passwords rated at least 40-48 bits in zxcvbn. (Decent Performance)
Tuned | `DiscreteCrypt.defaults.tunedScrypt()` | Makes it difficult to bruteforce the key-space. Should protect passwords rated at least 60 bits in zxcvbn. (Great Performance)
Ephemeral | `DiscreteCrypt.defaults.ephemeralScrypt()` | Used for contacts where you can either guarantee that the key will have quite a bit of entropy, or will be completely random. (Best Performance)

Keep in mind that the tuning for Ephemeral is above what GPG was using as its key derivation algorithm by default until quite recently.


Example Calls:

```js
// create fully random key manually, rather than letting DiscreteCrypt do it.  
let key = crypto.randomBytes(32)
let me = DiscreteCrypt.Contact.create(key, null, DiscreteCrypt.defaults.ephemeralScrypt())
```

```js
DiscreteCrypt.Symmetric.encrypt('Some really long and secure password', { organization: 1, txt: 'Hello' }, DiscreteCrypt.defaults.tunedScrypt())
```


# Upcoming

### Alternative Formats 

The current format is based mostly on hexadecimal values stored as JSON. This is not optimal. 

I will be implementing binary (and base64) formats that will improve the space efficiency of the data produced by DiscreteCrypt.js.

### DiscreteCrypt (C++) Compatibility

This is not the first iteration of DiscreteCrypt, there is a C++ tool that is much more powerful, but much more difficult to use.

Once I improve the C++ implementation, I aim to make the C++ version capable of interacting with the JS version, and vice versa.

### Multi-Recipient Encryption

The DiscreteCrypt protocol was designed to allow for multi-recipient encryption, support for this is planned in DiscreteCrypt.js 

### Multi-Signatures

DiscreteCrypt.js implements Schnorr's algorithm, which allows for space-efficient multi-party signatures.

This will be supported in later versions of the library.

### Proof-Of-Work 

I will eventually implement a proof-of-work utility, just to make it easier to implement your security.

### More

There are a few other things I'm planning on supporting that are a bit difficult to describe.