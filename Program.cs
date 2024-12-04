using System;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System.Threading.Tasks;
using AzureKeyVault;
class Program
{
    static async Task Main(string[] args)
    {
        using (var akvManager = new AzureKeyVaultManager())
        {
            //Key Vault'ta saklanan secret'ın adı
            //string secretName = "Redis";
            //akvManager.ReadSecretFromAzureKeyVault(secretName);

            //akvManager.AddSecretToAzureKeyVaultEvenIfDeleted("ApiKey", "12345624");

            //akvManager.DeleteSecretFromAzureKeyVault("TestSecret2");
            //akvManager.AddSecretToAzureKeyVaultEvenIfDeleted("TestSecret", "Cut The Night With The Light");
            //akvManager.AddSecretToAzureKeyVault("TestSecret", "Cut The Night With The Light");

            var secrets = new string[] { "ApiKey", "DbPassword", "StorageConnectionString" };
            var result = akvManager.ReadSecretsFromAzureKeyVault(secrets);
            foreach (var item in result)
            {
                Console.WriteLine(item.Key + " : " + item.Value);
            }
            //akvManager.DeleteSecretsFromAzureKeyVault(secrets);

            var secrets2 = new Dictionary<string, string>
            {
                { "ApiKey", "12345624" },
                { "DbPassword", "MySecurePassword4" },
                { "StorageConnectionString", "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=mykey;4" }
            };
            akvManager.AddSecretsToAzureKeyVaultEvenIfDeleted(secrets2);

            //akvManager.DeleteSecretFromAzureKeyVault("ApiKey");       
        }

    }
}