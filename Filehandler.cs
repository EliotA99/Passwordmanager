using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Security.Cryptography;
using System.Linq;

namespace Lösenordshanterare
{
    class Filehandlers
    {
        public static void WriteToFile(string enkryptedvault, string serverfile)
        {
            string serverDictString = File.ReadAllText(serverfile);
            var serverDict = JsonSerializer.Deserialize<Dictionary<string, string>>(serverDictString);
            if (serverDict.ContainsKey("vault"))
            {
                serverDict["vault"] = enkryptedvault;
            }
            else
            {
                Console.WriteLine("Vault did not successfully get stored");
            }
            string newServerDictString = JsonSerializer.Serialize(serverDict);
            //gör om valvet och spara i serverdict

            File.WriteAllText(serverfile, newServerDictString);
            //lägg till nya lösenord 
            //serialize och skriver till server fil
        }
    }
}