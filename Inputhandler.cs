using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Security.Cryptography;
using System.Linq;

namespace Lösenordshanterare
{
    class inputhandle
    {
        public static void welcome(string[] choicearr)
        {
            string choice = choicearr[0].ToUpper();
            string clientfile = choicearr[1];
            string serverfile;

            Console.WriteLine("Welcome to you passwordmanager");
            switch (choice)
            {
                case "INIT":
                    serverfile = choicearr[2];
                    Console.WriteLine("Masterpassword");
                    string pwd = Console.ReadLine();
                    if (checkPassword(pwd) == true)
                    {
                        Init(clientfile, serverfile, pwd);
                    }
                    else
                    {
                        Console.WriteLine("Wrong password!");
                    }
                    break;
                case "CREATE":
                    serverfile = choicearr[2];
                    Console.WriteLine("Masterpassword");
                    pwd = Console.ReadLine();
                    Console.WriteLine("Secretkey");
                    string sKey = Console.ReadLine();
                    Create(clientfile, serverfile, pwd, sKey);
                    break;
                case "GET":
                    serverfile = choicearr[2];
                    Console.WriteLine("Masterpassword");
                    pwd = Console.ReadLine();
                    string prop; 
                    if (choicearr.Length == 4)
                    {
                        prop = choicearr[3];
                    }
                    else
                    {
                        prop = null;
                    }
                    Get(clientfile, serverfile, prop, pwd);

                    break;
                case "SET":
                    serverfile = choicearr[2];
                    prop = choicearr[3];
                    string generatePass;
                    Console.WriteLine("Masterpassword");
                    pwd = Console.ReadLine();
                    if (choicearr.Length == 5)
                    {
                        generatePass = choicearr[4];
                    }
                    else
                    {
                        generatePass = null;
                    }
                    Set(clientfile, serverfile, prop, generatePass, pwd);

                    break;
                case "DELETE":

                    serverfile = choicearr[2];
                    prop = choicearr[3];
                    Console.WriteLine("Masterpassword");
                    pwd = Console.ReadLine();
                    Delete(clientfile, serverfile, prop, pwd);
                    break;
                case "SECRET":
                    Secret(clientfile);
                    break;
                default:
                    Console.WriteLine("no typos, press anykey to continue");
                    Console.ReadKey();
                    break;
            }
        }

        #region Check password
        public static bool checkPassword(string pwd)
        {
            string masterpwd = "qwerty";
            if (pwd == masterpwd)
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        #endregion

        #region Check Secretkey
        public static bool checkSecretkey(string sKey, string clientfile)
        {
            string sKeyString = File.ReadAllText(clientfile);
            var clientFileDict = JsonSerializer.Deserialize<Dictionary<string, string>>(sKeyString);
            if (sKey == clientFileDict["Secretkey"])
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        #endregion

        #region Initilize
        public static void Init(string clientfile, string serverfile, string pwd)
        {

            Dictionary<string, string> clientDict = new Dictionary<string, string>();
            byte[] sByteKey = Kryptering.generateSecretkey(); // byte array för att kunna använda till kryptering
            string Secretkey = Convert.ToBase64String(sByteKey);
            clientDict.Add("Secretkey", Secretkey);

            Dictionary<string, string> vaultDict = new Dictionary<string, string>();
            string vaultDictString = JsonSerializer.Serialize(vaultDict);

            byte[] IVbyte = Kryptering.generateIV();
            byte[] VaultKey = createVaultKey(pwd, sByteKey);
            string Ivektorstring = Convert.ToBase64String(IVbyte);

            // kryptera valv
            byte[] encVault = Kryptering.EncryptStringToBytes_Aes(vaultDictString, VaultKey, IVbyte);
            string encVaultString = Convert.ToBase64String(encVault);

            Dictionary<string, string> serverDict = new Dictionary<string, string>();
            serverDict.Add("iv", Ivektorstring);
            serverDict.Add("vault", encVaultString);

            string secretKey = JsonSerializer.Serialize(clientDict);
            string serverFileString = JsonSerializer.Serialize(serverDict);

            File.WriteAllText(clientfile, secretKey);
            File.WriteAllText(serverfile, serverFileString);
        }
        #endregion

        #region Set
        public static void Set(string clientfile, string serverfile, string prop, string genPass, string pwd)
        {
            if (checkPassword(pwd) == true)
            {
                var decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
                //här gör vi om det dekrypterade valvet till en dictionary igen

                if (decryptVaultDict.ContainsKey(prop))
                {
                    Console.WriteLine("Property already exists, try another!");
                    Environment.Exit(0);
                }
                string value;
                if (genPass == null)
                {
                    Console.WriteLine("Please enter new password for the property:");
                    value = Console.ReadLine();
                }
                else
                {
                    value = genereraLosen();                //genererar ett lösen på 20 tecken
                }

                decryptVaultDict.Add(prop, value);          //lägger till genererat eller eget lösen

                //kryptera igen för att spara krypterat valv i server dict
                string newencryptedvaultdict = Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, pwd);

                Filehandlers.WriteToFile(newencryptedvaultdict, serverfile);
                //Öppnar dicitionaryt för att lägga in det nya krypterade valvet
                Console.WriteLine("Success!");
            }
            else
            {
                Console.WriteLine("Wrong password!");
            }
        }
        #endregion

        #region Get 
        public static void Get(string clientfile, string serverfile, string prop, string pwd)
        {
            Dictionary<string, string> decryptVaultDict = new Dictionary<string, string>();
            try
            {
                if (checkPassword(pwd))
                {
                    decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
                }
            }
            catch
            {
                Console.WriteLine("Something went wrong with the password or decryption");
                Environment.Exit(0);
            }

            if (prop != null)
            {

                if (decryptVaultDict.ContainsKey(prop))
                {
                    Console.WriteLine(decryptVaultDict[prop]);
                }
                else
                {
                    //skriver inte ut nånting
                }
            }
            else
            {
                foreach (string key in decryptVaultDict.Keys)
                {
                    Console.WriteLine("Property = {0}", key);
                }
            }
        }
        #endregion

        #region Create
        public static void Create(string clientfile, string serverfile, string pwd, string sKey) // ska skapa en ny inloggning i client för en existerande server
        {
            Dictionary<string, string> decryptVaultDict = new Dictionary<string, string>();

            if (checkPassword(pwd) == true)
            {
                Dictionary<string, string> newClientdict = new Dictionary<string, string>();
                newClientdict.Add("Secretkey", sKey);
                string newClient = JsonSerializer.Serialize(newClientdict);
                try
                { 
                    
                    decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(newClient, serverfile, pwd));
                }
                catch (Exception)
                {
                    Console.WriteLine("Decryption failed");
                    Environment.Exit(0);
                }
                File.WriteAllText(clientfile, newClient);

                string encryptVaultstring = Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, pwd);
                Filehandlers.WriteToFile(encryptVaultstring, serverfile);

                Console.WriteLine("success");
            }
            else
            {
                Console.WriteLine("Wrong password!");
            }
            //skapa en ny client fil eller skriver över en gammal
            //try catch för dekrypering av valvet
        }
        #endregion

        #region Delete
        public static void Delete(string clientfile, string serverfile, string property, string pwd)
        {
            string clientsecret = File.ReadAllText(clientfile);
            string serverprops = File.ReadAllText(serverfile);
            Dictionary<string, string> decryptVaultDict = new Dictionary<string, string>();

            try
            {
                if (checkPassword(pwd))
                {
                    decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
                }
            }
            catch
            {
                Console.WriteLine("Something went wrong with the password or decryption");
                Environment.Exit(0);
            }

            if (decryptVaultDict.ContainsKey(property))
            {
                try
                {
                    decryptVaultDict.Remove(property);
                }
                catch (System.Exception)
                {
                    Console.WriteLine("Something went wrong with the deletion, try again.");
                    Environment.Exit(0);
                }

                //krypterar och skriver över till fil
                string newencryptedvaultdict = Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, pwd);
                Filehandlers.WriteToFile(newencryptedvaultdict, serverfile);
            }
            else
            {
                Console.WriteLine("Property not found, try again!");
            }
            Console.WriteLine("success");
        }
        #endregion

        #region Secret
        public static void Secret(string clientfile)
        {
            string clientsecret = File.ReadAllText(clientfile);
            var clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(clientsecret);
            Console.WriteLine("Here is your secret key: " + clientDict["Secretkey"]);
        }
        #endregion

        #region Create Vault Key
        public static byte[] createVaultKey(string pwd, byte[] secretKey)
        {
            Aes VaultAes = Aes.Create();
            try
            {
                Rfc2898DeriveBytes k1 = new Rfc2898DeriveBytes(pwd, secretKey);
                VaultAes.Key = k1.GetBytes(16);
            }
            catch
            {
            }
            return VaultAes.Key;
        }
        #endregion

        public static string genereraLosen()
        {
            Random random = new Random();
            const string characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            return new string(Enumerable.Repeat(characters, 20)
            .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}