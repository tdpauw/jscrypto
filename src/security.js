
var security = function() {
  sjcl.random.startCollectors();
  
  var pwd = {
    iter : 1000,
    keysize : 256
  };
  
  var mstkey = {
    saltnb : 2,
    iter : 10,
    keysize : 128
  }
  
  /**
   * Generates random words.
   * @param {type} nrOfWords Number of words to generate.
   * @returns An array of words.
   */
  function randomize(nrOfWords) {
    return sjcl.random.randomWords(nrOfWords, 0);
  }
  
  /**
   * Generates a salted key given a password and a salt.
   * @param {type} password The password from which to generate the key.
   * @param {type} salt The salt to add to the password (defaults to 2 random words).
   * @param {type} iter Number of iterations to apply on the key generation (defaults to 1000).
   * @param {type} keysize The size of the key to generate: 128, 192, 256 (defaults to 128).
   * @returns {unresolved} an object with the salted key and the salt.
   */
  function generate(password, salt, iter, keysize) {
    var p = {}, data;

    if (password.length === 0) {
      throw {
        name : "SecurityError",
        message : "Can't generate key: need a password"
      };
    }

    if (salt.length === 0) {
      throw {
        name : "SecurityError",
        message : "Can't generate key: need a salt for PBKDF2"
      };
    }

    p.iter = iter;
    p.salt = salt;
    data = sjcl.misc.cachedPbkdf2(password, p);
    data.key = data.key.slice(0, keysize/32);
    return data;
  }
  
  var service = {
    
    /**
     * Generates a salted password based on a password. 
     * This will iterate 1000 times and generates 257 bits key.
     * @param {type} password The user password.
     * @param {type} salt The salt.
     * @returns {undefined} the salted password.
     */
    saltedPassword : function (password, salt) {
      if (salt === undefined || salt.length === 0) {
        throw {
          name : "SecurityError",
          message : "Can' generate salted password: need a salt"
        };
      }
      var data = generate(password, salt, pwd.iter, pwd.keysize);
      return data.key;
    },
    
    /**
     * Generates a masterkey from a password and salt. The masterkey is the 
     * encryption key that will be used to encrypt messages. 
     * This will iterate 10 times, use a 2 random words as salt and generates a 128 bits key.
     * @param {type} password The password from which to generate the key.
     * @returns {unresolved} an object with the salted master key and the salt.
     */
    masterKey : function(password) {
      var salt = randomize(mstkey.saltnb).concat(salt);
      return generate(password, salt, mstkey.iter, mstkey.keysize);
    },
            
    /**
      * Encrypts plaintext. Uses the OCB2 cyper mode.
      * @param {type} plaintext
      * @param {type} key The key to use to encrypt the plain text.
      * @param {type} tag The length of the authentication tag to add to the message: 64, 96 or 128 (defaults to 64).
      * @param {type} iter Number of iterations to apply (defaults to 1000).
      * @param {type} iv Initialization vector (similar to salt, defaults to 4 random words).
      * @param {type} adata Authentication data: auxiliary message which is not encrypted
      * but its integrity will be checked along with the message.
      * @returns {unresolved} A jsonified string containing the cyphered text and all parameters needed
      * to encrypt, except the encryption key.
      */
     encrypt : function(plaintext, key, tag, iter, iv, adata) {
       var rp = {}, p = {}, ct;

       if (plaintext === '') { return; }
       if (key.length === 0) {
         throw {
           name : "SecurityError",
           message : "Can't encrypt: need a key"
         };
       }

       p.mode ='ocb2';
       p.ts = parseInt(tag);
       if (iter !== undefined) {
         p.iter = iter;
       }
       if(iv !== undefined) {
         p.iv = iv;
       }
       if(adata !== undefined) {
         p.adata = adata;
       }

       ct = sjcl.encrypt(key, plaintext, p, rp);
       return ct;
     },
     
     /**
      * Decrypts a cyphered text to plain text given a key. Uses the OCB2 cyper mode.
      * @param {type} ciphertext A jsonified string containing the cyphered text and all necessary parameters.
      * @param {type} key The key to decrypt.
      * @returns {unresolved} The unencrypted text.
      */
     decrypt : function(ciphertext, key) {
       var rp = {};

       if (ciphertext.length === 0) { return; }
       if (!key.length) {
         throw {
           name : "SecurityError",
           message : "Can't decrypt: need a key"
         };
       }

         try {
           plaintext = sjcl.decrypt(key, ciphertext, {}, rp);
         } catch(e) {
           throw {
              name : "SecurityError",
              message : "Can't decrypt: "+e
            };
         }

         return plaintext;
     },

     /**
      * Decrypts a cyphered text to plain text given a key. Similar to decrypt where the data is passed
      * as distinct parameters as opposed to the jsonized data.
      * @param {type} ciphertext The encrypted data.
      * @param {type} key The encryption key.
      * @param {type} iv The initialization vector used during the encryption: adds randomness 
      * to the message send, so that the same message will look different each time its send.
      * @param {type} tag The length of the authentication tag added the message: 64, 96 or 128
      * @param {type} adata The authenticated data: This auxilliary message isn't secret, 
      * but its integrity will be checked along with the integrity of the message.
      * @returns {unresolved}
      */
     decrypt2 : function(ciphertext, key, iv, tag, adata) {
       var mode = 'ocb2', p, aes, plaintext;

       if (key.length === 0) {
         throw {
           name : "SecurityError",
           message : "Can't decrypt: need a key"
         };
       }

       if (iv.length === 0) {
         throw {
           name : "SecurityError",
           message : "Can't decrypt: need an initialization vector"
         };
       }
       
       if (tag === undefined) {
         throw {
           name : "SecurityError",
           message : "Can't decrypt: need an authentication tag length of 64, 96 or 128"
         };
       }
       
       if (adata === undefined) {
         throw {
           name : "SecurityError",
           message : "Can't decrypt: need an authenticated data"
         };
       }

       aes = new sjcl.cipher.aes(key);

       ciphertext = sjcl.codec.base64.toBits(ciphertext);
       
       try {
         plaintext = sjcl.codec.utf8String.fromBits(sjcl.mode[mode].decrypt(aes, ciphertext, iv, adata, tag));
       } catch (e) {
         throw {
           name : "SecurityError",
           message : "Can't decrypt: " + e
         };
       }
       return plaintext;
     }
  };
  
  return service;
}();

