# DiscreteCrypt.js

[![Coverage Status](https://coveralls.io/repos/github/TotalTechGeek/DiscreteCrypt.js/badge.svg?branch=master)](https://coveralls.io/github/TotalTechGeek/DiscreteCrypt.js?branch=master) [![GitHub license](https://img.shields.io/github/license/TotalTechGeek/DiscreteCrypt.js.svg)](https://github.com/TotalTechGeek/DiscreteCrypt.js/blob/master/LICENSE)

![Shield](https://svgshare.com/i/8D1.svg)

A project for simple & secure data transmission, based on the DiscreteCrypt protocol (an alternative to PGP).


## What's it do?

This library makes it quite easy to implement end-to-end encryption both in the web browser and in Node.js, and provides extra utilities to make it convenient to encrypt symmetrically as well.

The library out of the box is tuned heavily against a variety of attacks, implementing scrypt for key derivation, a strong authenticated encryption scheme using HMAC-SHA256, and AES-256 in CTR mode for encryption. It uses provably secure 3072 Bit Discrete Log Parameters generated from nspdh. 

A neat feature of this implementation is that a password can be used to quickly & securely derive a private key (via scrypt), which allows for convenient public-key encryption. The code makes heavy use of JavaScript Promises.

You may alternatively generate keys ephemerally, and encrypt the generated "contact" symmetrically (like traditional cryptosystems).

## How do I use it?

(More documentation necessary)

In DiscreteCrypt, we refer to "public keys" as "contacts," and they are generated asynchronously as promises. 

The create method returns a promise with a few helper functions tossed onto it, to make it slightly more convenient to use the library. 

All of the helper functions return a promise that execute the generated contact's function once it completes.


#### Sending and Opening Data

```js
const Contact = DiscreteCrypt.Contact

// generates the contact ephemerally.
let me = Contact.create()

// the Contact.create().export() would happen on someone else's computer
let you = Contact.import(Contact.create().export())

// any JSON-serializable object can be passed into the "send" function.
me.send(you, 'Hello, World!').then(encrypted =>
{
    // code to send encrypted data to other user
})
```


Then to open the data, 

```js 
you.open(encrypted).then(data =>
{
    console.log(data) // Hello, World!
}).catch(err =>
{
    // the decryption didn't occur correctly.
    console.error(err)
})
```


#### Creating a Reusable Contact 

To create a re-usable contact for public-key cryptography (one you can import at a later date), do the following:

**1 - Create the Contact** 

```js
// you can also pass in an Buffer or Uint8-like object for the password.
let me = Contact.create('<SuperSecurePassword>')

// creates the public contact, store this somewhere
let pub = me.export()
```


**2 - Import the Public Contact & Compute (To turn it back into a private contact)**

```js
let me = Contact.import(pub).compute('<SuperSecurePassword>')
```

And that's it! 


#### Symmetrically Encrypting Data

Sometimes you'll want to encrypt data symmetrically. These methods use a slight reduction of the DiscreteCrypt protocol (removing the asymmetric steps) that allow you to securely store a payload.  

Out of the box these methods perform data authenticity checks, and the necessary key stretching to keep your data safe. 

```js
// key can be a string, buffer or uint8array-like structure.
DiscreteCrypt.Symmetric.encrypt(key, data).then(encrypted =>
{
    // store encrypted somewhere
    // ... and then later on
    DiscreteCrypt.Symmetric.decrypt(key, encrypted).then(decrypted =>
    {
        console.log(decrypted)
    })
})
```


## To Build (for browser)

Run the following commands:
```
npm i
npm run build
```

This will produce the necessary output.


## Dependencies

The following libraries were used:
- aes-js
- bn.js 
- buffer
- jsSHA
- scrypt-async

## Notes

This library can leverage the new proposal for [native BigInts](https://github.com/tc39/proposal-bigint) in JavaScript, achieving far greater performance.

At the time of writing, Chrome is the only browser with support for this proposal.
