describe("Security", function() {
   
    beforeEach(function() {
       //initialize(); 
    });
    
    it("should be able to generate a salted password", function() {
        var password = 'mypassword';
        var salt = ['toto'];
        var data = security.saltedPassword(password, salt);
        expect(data).not.toBeNull();
        expect(data).toBeDefined();
        expect(data.length).toEqual(8);
        expect(data).not.toEqual(password);
    });
    
    it("should be able to generate the same salted password given the same password and salt", function() {
      var password = 'mypassword';
      var salt = ['thierry.depauw'];
      
      var data1 = security.saltedPassword(password, salt);
      expect(data1).not.toEqual(password);
      
      var data2 = security.saltedPassword(password, salt);
      expect(data2).toEqual(data1);
      
      var data3 = security.saltedPassword(password, salt);
      expect(data3).toEqual(data1);
    });
    
    it("should be able to generate a masterkey", function() {
      var password = 'mypassword';
      var data = security.masterKey(password);
      expect(data).not.toBeNull();
      expect(data.key).toBeDefined();
      expect(data.key.length).toEqual(4);
    });
    
    it("should generate different masterkeys at each run", function() {
      var password = 'mypassword';
      var data1 = security.masterKey(password);
      var data2 = security.masterKey(password);
      expect(data2).not.toEqual(data1);
      var data3 = security.masterKey(password);
      expect(data3).not.toEqual(data1);
      expect(data3).not.toEqual(data2);
    });
    
    it("should be able to generate a salted password and masterkey", function() {
      var password = 'mypassword';
      var salt = 'aSalt';
      
      var saltedPwd = security.saltedPassword(password, salt);
      var masterKey = security.masterKey(saltedPwd);
      expect(saltedPwd).not.toEqual(password);
      expect(masterKey).not.toEqual(password);
      expect(masterKey).not.toEqual(saltedPwd);
    });
    
    it("should be able to encrypt and decrypt a message", function() {
      var password = 'mypassword';
      var masterKey = security.masterKey(password);
      var text = 'hello world!';
      var cyphertext = security.encrypt(text, masterKey.key, 64);
      expect(cyphertext).not.toBeNull();

      var decryptedtext = security.decrypt(cyphertext, masterKey.key);
      expect(decryptedtext).toEqual(text);

      var ct = sjcl.json.decode(cyphertext);
      var cyphertext2 = sjcl.codec.base64.fromBits(ct.ct);
      var decryptedtext2 = security.decrypt2(cyphertext2, masterKey.key, ct.iv, ct.ts, []);
      expect(decryptedtext2).toEqual(text);
    });
});

