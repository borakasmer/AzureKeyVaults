using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace AzureKeyVault
{
    public enum VaultLocation
    {
        AppSettings = 1,
        Database
    }
    public class AzureKeyVaultManager : IAzureKeyVaultManager, IDisposable
    {
        private bool _disposed = false;
        public AzureKeyVaultManager() { }
        public string ReadSecretFromAzureKeyVault(string key)
        {
            // Key Vault'ta saklanan secret'ın adı
            string secretName = key;
            try
            {
                // Azure Key Vault istemcisi oluşturuluyor
                var client = GetSecretClient();
                // Secret değerini almak
                Console.WriteLine($"'{secretName}' adlı secret Key Vault'tan alınıyor...");
                KeyVaultSecret secret = client.GetSecret(secretName);
                // Secret değerini elde etme
                string secretValue = secret.Value;
                Console.WriteLine("Secret başarıyla alındı!");
                Console.WriteLine($"Secret Value: {secretValue}");
                return secretValue;
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                // Secret mevcut değil, devam edin
                Console.WriteLine($"'{secretName}' adlı secret bulunamadı...");
                return string.Empty;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata oluştu: {ex.Message}");
                return string.Empty;
            }
        }
        public Dictionary<string, string> ReadSecretsFromAzureKeyVault(string[] keys)
        {
            var secrets = new Dictionary<string, string>();
            try
            {
                // Azure Key Vault istemcisi oluşturuluyor
                var client = GetSecretClient();

                Console.WriteLine("Secret'lar Key Vault'tan toplu olarak alınıyor...");

                foreach (var key in keys)
                {
                    try
                    {
                        Console.WriteLine($"'{key}' adlı secret alınıyor...");
                        KeyVaultSecret secret = client.GetSecret(key);
                        secrets[key] = secret.Value;
                        Console.WriteLine($"'{key}' adlı secret başarıyla alındı!");
                    }
                    catch (RequestFailedException ex) when (ex.Status == 404)
                    {
                        Console.WriteLine($"'{key}' adlı secret bulunamadı...");
                        secrets[key] = string.Empty;
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"'{key}' adlı secret alınırken hata oluştu: {ex.Message}");
                        secrets[key] = string.Empty;
                    }
                }

                Console.WriteLine("Tüm secret'lar okuma işlemi tamamlandı.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Genel bir hata oluştu: {ex.Message}");
            }

            return secrets;
        }
        public bool AddSecretToAzureKeyVault(string name, string value)
        {
            // Key Vault'ta saklanacak secret'ın adı
            string secretName = name;
            // Key Vault'ta saklanacak secret'ın değeri
            string secretValue = value;
            try
            {
                // Azure Key Vault istemcisi oluşturuluyor
                var client = GetSecretClient();
                // Secret'ı Key Vault'a ekleme
                Console.WriteLine($"'{secretName}' adlı secret Key Vault'a ekleniyor...");
                client.SetSecret(secretName, secretValue);
                Console.WriteLine("Secret başarıyla eklendi!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata oluştu: {ex.Message}");
                return false;
            }
        }
        public bool AddSecretsToAzureKeyVault(Dictionary<string, string> secrets)
        {
            try
            {
                var client = GetSecretClient();
                // Secret'ları topluca ekleme
                Console.WriteLine("Secret'lar Key Vault'a ekleniyor...");
                foreach (var secret in secrets)
                {
                    client.SetSecret(secret.Key, secret.Value);
                    Console.WriteLine($"'{secret.Key}' adlı secret başarıyla eklendi!");
                }

                Console.WriteLine("Tüm secret'lar başarıyla eklendi!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata oluştu: {ex.Message}");
                return false;
            }
        }
        public bool AddSecretToAzureKeyVaultEvenIfDeleted(string name, string value)
        {
            string secretName = name;
            string secretValue = value;
            try
            {
                // Azure Key Vault istemcisi oluşturuluyor
                var client = GetSecretClient();

                // Secret mevcut mu diye kontrol edin
                try
                {
                    var existingSecret = client.GetSecret(secretName);
                    Console.WriteLine($"'{secretName}' adlı secret zaten mevcut. Güncelleniyor...");
                    client.SetSecret(secretName, secretValue);
                    Console.WriteLine("Secret başarıyla güncellendi!");
                    return true;
                }
                catch (RequestFailedException ex) when (ex.Status == 404)
                {
                    // Secret mevcut değil, devam edin
                    Console.WriteLine($"'{secretName}' adlı secret bulunamadı. Yeni secret ekleniyor...");
                }

                // Silinmiş ama kurtarılabilir durumda mı kontrol edin      
                try
                {
                    var deletedSecret = client.GetDeletedSecret(secretName);
                    Console.WriteLine($"'{secretName}' adlı secret silinmiş ama kurtarılabilir durumda. Kurtarılıyor...");
                    var recoverOption = client.StartRecoverDeletedSecret(secretName);
                    recoverOption.WaitForCompletion();
                    Console.WriteLine("Secret kurtarıldı. Güncelleniyor...");
                    client.SetSecret(secretName, secretValue);
                    Console.WriteLine("Secret başarıyla güncellendi!");
                    return true;
                }
                catch (RequestFailedException ex) when (ex.Status == 404)
                {
                    // Kurtarılabilir durumda değil, devam edin
                    Console.WriteLine($"'{secretName}' adlı secret kurtarılabilir durumda değil. Yeni secret ekleniyor...");
                }

                // Yeni secret ekle
                client.SetSecret(secretName, secretValue);
                Console.WriteLine("Secret başarıyla eklendi!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata oluştu: {ex.Message}");
                return false;
            }
        }
        public bool AddSecretsToAzureKeyVaultEvenIfDeleted(Dictionary<string, string> secrets)
        {
            try
            {
                // Azure Key Vault istemcisi oluşturuluyor
                var client = GetSecretClient();
                Console.WriteLine("Secret'lar Key Vault'a ekleniyor...");
                foreach (var secret in secrets)
                {
                    // Secret mevcut mu diye kontrol edin
                    try
                    {
                        var existingSecret = client.GetSecret(secret.Key);
                        Console.WriteLine($"'{secret.Key}' adlı secret zaten mevcut. Güncelleniyor...");
                        client.SetSecret(secret.Key, secret.Value);
                        Console.WriteLine("Secret başarıyla güncellendi!");
                        continue;
                    }
                    catch (RequestFailedException ex) when (ex.Status == 404)
                    {
                        // Secret mevcut değil, devam edin
                        Console.WriteLine($"'{secret.Key}' adlı secret bulunamadı. Yeni secret ekleniyor...");
                    }
                    // Silinmiş ama kurtarılabilir durumda mı kontrol edin
                    try
                    {
                        var deletedSecret = client.GetDeletedSecret(secret.Key);
                        Console.WriteLine($"'{secret.Key}' adlı secret silinmiş ama kurtarılabilir durumda. Kurtarılıyor...");
                        var recoverOption = client.StartRecoverDeletedSecret(secret.Key);
                        recoverOption.WaitForCompletion();
                        Console.WriteLine("Secret kurtarıldı. Güncelleniyor...");
                        client.SetSecret(secret.Key, secret.Value);
                        Console.WriteLine("Secret başarıyla güncellendi!");
                        continue;
                    }
                    catch (RequestFailedException ex) when (ex.Status == 404)
                    {
                        // Kurtarılabilir durumda değil, devam edin
                        Console.WriteLine($"'{secret.Key}' adlı secret kurtarılabilir durumda değil. Yeni secret ekleniyor...");
                    }
                    // Yeni secret ekle
                    client.SetSecret(secret.Key, secret.Value);
                    Console.WriteLine("Secret başarıyla eklendi!");
                }
                Console.WriteLine("Tüm secret'lar başarıyla eklendi!");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata oluştu: {ex.Message}");
                return false;
            }
        }
        //public bool DeleteSecretsFromAzureKeyVault(string[] secrets)
        //{
        //    //string keyVaultUrl = "https://******.vault.azure.net/";
        //    string secretKey = string.Empty;
        //    try
        //    {
        //        // Azure Key Vault istemcisi oluşturuluyor
        //        var client = GetSecretClient();
        //        Console.WriteLine("Secret'lar Key Vault'tan siliniyor...");

        //        foreach (var secret in secrets)
        //        {
        //            secretKey = secret;
        //            client.StartDeleteSecret(secret);
        //            Console.WriteLine($"'{secret}' adlı secret silindi!");
        //        }

        //        Console.WriteLine("Tüm secret'lar başarıyla silindi!");
        //        return true;
        //    }
        //    catch (RequestFailedException ex) when (ex.Status == 404)
        //    {
        //        Console.WriteLine($"'{secretKey}' adlı secret bulunamadı.");
        //        return false;
        //    }
        //    catch (Exception ex)
        //    {
        //        Console.WriteLine($"Hata oluştu: {ex.Message}");
        //        return false;
        //    }
        //}
        public bool DeleteSecretsFromAzureKeyVault(string[] secrets)
        {
            try
            {
                //string keyVaultUrl = "https://********.vault.azure.net/";
                bool allSuccess = true; // Tüm işlemlerin başarı durumunu takip etmek için
                var client = GetSecretClient();

                Console.WriteLine("Secret'lar Key Vault'tan siliniyor...");

                foreach (var secret in secrets)
                {
                    try
                    {
                        client.StartDeleteSecret(secret);
                        Console.WriteLine($"'{secret}' adlı secret başarıyla silindi!");
                    }
                    catch (RequestFailedException ex) when (ex.Status == 404)
                    {
                        Console.WriteLine($"'{secret}' adlı secret bulunamadı. Silme işlemi atlandı.");
                        allSuccess = false; // En az bir işlem başarısız oldu
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"'{secret}' adlı secret silinirken hata oluştu: {ex.Message}");
                        allSuccess = false; // En az bir işlem başarısız oldu
                    }
                }

                if (allSuccess)
                {
                    Console.WriteLine("Tüm secret'lar başarıyla silindi!");
                }
                else
                {
                    Console.WriteLine("Bazı secret'lar silinirken hatalar oluştu.");
                }
                return allSuccess;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata oluştu: {ex.Message}");
                return false;
            }            
        }


        public bool DeleteSecretFromAzureKeyVault(string secretName)
        {
            try
            {
                // Azure Key Vault istemcisi oluşturuluyor
                var client = GetSecretClient();
                Console.WriteLine($"'{secretName}' adlı secret Key Vault'tan siliniyor...");

                // Secret silme işlemini başlat
                client.StartDeleteSecret(secretName);

                Console.WriteLine($"'{secretName}' adlı secret başarıyla silindi!");
                return true;
            }
            catch (RequestFailedException ex) when (ex.Status == 404)
            {
                Console.WriteLine($"'{secretName}' adlı secret bulunamadı.");
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Hata oluştu: {ex.Message}");
                return false;
            }
        }
        // IDisposable arayüzü ile gelen Dispose metodu
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        // Kaynakları serbest bırakma işlemi
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {

                }
                _disposed = true;
            }
        }

        // Finalize metodu (destructor) - yalnızca yönetilmeyen kaynaklar için
        ~AzureKeyVaultManager()
        {
            Dispose(false);
        }
        private SecretClient GetSecretClient()
        {
            string keyVaultUrl = "https://******.vault.azure.net/";
            return new SecretClient(new Uri(keyVaultUrl), new DefaultAzureCredential());
        }

        public string GenerateVaultKey(VaultLocation location, string entity, string company, string key)
        {
            return string.Format("{0}:{1}:{2}:{3}", location, entity, company, key);
        }
    }
}
