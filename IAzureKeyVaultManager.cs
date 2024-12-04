using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVault
{
    public interface IAzureKeyVaultManager
    {
        string ReadSecretFromAzureKeyVault(string key);
        Dictionary<string, string> ReadSecretsFromAzureKeyVault(string[] keys);
        bool AddSecretToAzureKeyVault(string name, string value);
        bool AddSecretsToAzureKeyVault(Dictionary<string, string> secrets);
        bool AddSecretToAzureKeyVaultEvenIfDeleted(string name, string value);
        bool AddSecretsToAzureKeyVaultEvenIfDeleted(Dictionary<string, string> secrets);
        bool DeleteSecretFromAzureKeyVault(string key);
        bool DeleteSecretsFromAzureKeyVault(string[] secrets);
        string GenerateVaultKey(VaultLocation location, string entity, string company, string key);
    }
}
