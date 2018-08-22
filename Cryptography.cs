using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Cryptography
{
    public class CBCCryptography
    {
        public static void SetData(string password, string iv = null)
        {
            Config.Password = password;
            if (iv != null)
            {
                Config.IV = iv;
            }
            else
            {
                using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                {
                    byte[] bytes = null;
                    rng.GetBytes(bytes);
                    Config.IV = Encoding.Default.GetString(bytes);
                }
            }
        }

        public void NewIV()
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                byte[] bytes = null;
                rng.GetBytes(bytes);
                Config.IV = Encoding.Default.GetString(bytes);
            }
        }

        public static string ReturnIV()
        {
            return Config.IV;
        }

        public static string EnCrypt(string plainText)
        {
            string result = null;
            using (Rijndael cryptor = Rijndael.Create())
            {
                cryptor.Mode = CipherMode.CBC;
                cryptor.IV = Encoding.UTF8.GetBytes(Config.IV);
                cryptor.Key = Encoding.UTF8.GetBytes(Config.Password);
                cryptor.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = cryptor.CreateEncryptor();

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                    }

                    result = Encoding.Default.GetString(msEncrypt.ToArray());
                }
            }

            return result;
        }

        public static string DeCrypt(string plainText)
        {
            string result = null;

            using (Rijndael cryptor = Rijndael.Create())
            {
                cryptor.Mode = CipherMode.CBC;
                cryptor.IV = Encoding.UTF8.GetBytes(Config.IV);
                cryptor.Key = Encoding.UTF8.GetBytes(Config.Password);
                cryptor.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = cryptor.CreateDecryptor();

                using (MemoryStream msDecrypt = new MemoryStream(Encoding.Default.GetBytes(plainText)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            result = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return result;
        }
    }
}
