using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Security.Cryptography;

namespace Lösenordshanterare
{
    class Kryptering
    {
        #region IV Generate
        public static byte[] generateIV() //IV gör att vi inte får samma värde när vi krypterar
        {
            Aes ivektor = Aes.Create();
            return ivektor.IV;

        }
        #region Secretkey Generate
        public static byte[] generateSecretkey()
        {
            Aes secretKey = Aes.Create();
            return secretKey.Key;
        }
        #endregion
        public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key"); //key ska vara vaultkey
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            string plaintext = null;

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;


                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }


        #endregion
        public static string EncryptVault(Dictionary<string, string> vaultdict, string clientfile, string serverfile, string pwd)
        {
            string serverDictString = File.ReadAllText(serverfile);
            var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(serverDictString);
            string clientDictString = File.ReadAllText(clientfile);
            var clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(clientDictString);


            string IVektorx = serverDict["iv"];
            byte[] initV = Convert.FromBase64String(IVektorx);

            string vaultString = JsonSerializer.Serialize(vaultdict);
            byte [] secretKeyByte = null;
            try
            {
                secretKeyByte = Convert.FromBase64String(clientDict["Secretkey"]);   //omvandla secretkey till byte []

            }
            catch (FormatException)
            {
                Console.WriteLine("Wrong format secret key");
                Environment.Exit(0);
            }
            byte[] vaultKey = inputhandle.createVaultKey(pwd, secretKeyByte);

            byte[] encVault = EncryptStringToBytes_Aes(vaultString, vaultKey, initV);

            return Convert.ToBase64String(encVault);
        }
        public static string DecryptVault(string clientfile, string serverfile, string pwd)
        {
            string serverDictString = File.ReadAllText(serverfile);
            string clientDictString = File.ReadAllText(clientfile);
            var clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(clientDictString);
            var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(serverDictString);

            string IVektorx = serverDict["iv"];
            byte[] encvault = Convert.FromBase64String(serverDict["vault"]);

            string vaultDictString = Convert.ToBase64String(encvault);

            // Eftersom vaultdict är sparat som en sträng i dictionaryt så gör man bara om den till en byte arr först
            //det är sen den vi skickar in för dekryptering, när den sen är dekrypterad kan vi dezerialisa om den till en dictionary

            byte[] secretKeyByte = null;
           
            try
            {
                secretKeyByte = Convert.FromBase64String(clientDict["Secretkey"]);   //omvandla secretkey till byte []

            }
            catch (FormatException)
            {
                Console.WriteLine("Wrong format secret key");
                Environment.Exit(0);

            }

            byte[] vaultKey = inputhandle.createVaultKey(pwd, secretKeyByte);       //generera valvnyckel

            byte[] initV = Convert.FromBase64String(IVektorx); //omvandla IV till byte [] ist för sträng

            string decryptVaultString = Kryptering.DecryptStringFromBytes_Aes(encvault, vaultKey, initV); //dekryptera valvet genom att kombinera valvnyckel och IV

            return decryptVaultString;

        }

    }

}