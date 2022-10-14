using System;
using static System.Console;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace AesEncryption{
    class Program{
        static void Main(string[] args){
            AESCryptography protection = new AESCryptography();
            RSACryptography rs = new RSACryptography();

            string ciph = string.Empty;

            try
            {
                using (Aes aes = Aes.Create()){
                    Write("Enter some text:");
                    string text = ReadLine();

                    byte[] encrypted = protection.Encrypt(text,aes.Key,aes.IV);
                    string eText = String.Empty;
                    eText += System.Text.Encoding.ASCII.GetString(encrypted);
                    // foreach (var b in encrypted)
                    // {
                    //     eText += b.ToString()+", ";
                    // }

                    WriteLine(Environment.NewLine + $"Encrypted text: {eText}");
                    
                    string decrypted = protection.Decrypt(encrypted,aes.Key,aes.IV);
                    WriteLine(Environment.NewLine + $"Decrypted text: {decrypted}");
                }
            }
            catch (Exception e)
            {
                WriteLine(Environment.NewLine + $"Error: {e.Message}");
            }

            WriteLine(Environment.NewLine + "Press any key to continue");
            ReadKey();
        }
    }
    
    class AESCryptography{
        public byte[] Encrypt(string Text,byte[] Key, byte[] IV){
            // check value
            if (Text == null || Text.Length <= 0) throw new ArgumentNullException("Text");
            if (Key == null || Key.Length <= 0) throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0) throw new ArgumentNullException("IV");
            
            byte[] eData;

            // create AES object w/ specified key and iv

            using (Aes aes = Aes.Create()){
                aes.Key = Key;
                aes.IV = IV;

                using (MemoryStream ms = new MemoryStream()){
                    using (CryptoStream cs = new CryptoStream(ms,aes.CreateEncryptor(aes.Key, aes.IV),CryptoStreamMode.Write)){
                        using (StreamWriter sw = new StreamWriter(cs)){
                            sw.Write(Text);
                        }

                        eData = ms.ToArray();
                    }
                }
            }
            return eData;
        }

        public string Decrypt(byte[] cText, byte[] Key, byte[] IV){
            if (cText == null || cText.Length <= 0) throw new ArgumentNullException("cText");
            if (Key == null || Key.Length <= 0) throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0) throw new ArgumentNullException("IV");

            string dData;

            using (Aes aes = Aes.Create()){
                aes.Key = Key;
                aes.IV = IV;

                using (MemoryStream ms = new MemoryStream(cText)){
                    using (CryptoStream cs = new CryptoStream(ms,aes.CreateDecryptor(aes.Key,aes.IV),CryptoStreamMode.Read)){
                        using (StreamReader sr = new StreamReader(cs)){
                           
                            dData = sr.ReadToEnd();
                        }
                    }
                }
            }
            return dData;
        }
    }

    class RSACryptography{
        private static RSACryptoServiceProvider csp = new RSACryptoServiceProvider(2048);
        private RSAParameters _privateKey;
        private RSAParameters _publicKey;

        public RSACryptography()
        {
            _privateKey = csp.ExportParameters(true);
            _publicKey = csp.ExportParameters(false);
        }

        // public string GetPublicKey(){
        //     var sw = new StringWriter();
        //     var xs = new XmlSerializer(typeof(RSAParameters));
        //     xs.Serialize(sw,_publicKey);
        //     return sw.ToString();
        // }

        public string Encrypt(string plainText){
            csp = new RSACryptoServiceProvider();
            csp.ImportParameters(_publicKey);
            var data = Encoding.Unicode.GetBytes(plainText);
            var cypher = csp.Encrypt(data,false);
            return Convert.ToBase64String(cypher);
        }

        public string Decrypt(string cipherText){
            var dataBytes = Convert.FromBase64String(cipherText);
            csp.ImportParameters(_privateKey);
            var plainText = csp.Decrypt(dataBytes,false);
            return Encoding.Unicode.GetString(plainText);
        }
    }
}
