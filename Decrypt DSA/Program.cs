using System;
using System.IO;
using System.Threading;
using System.Collections.Generic;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Decrypt_DSA.Model;

namespace Decrypt_DSA
{
    class Program
    {
        private const int PBKDF2_ITERATIONS = 50000;
        private const int KEY_SIZE_BYTES = 32;

        [STAThread]
        static void Main(string[] args)
        {
            ManifestData manifest;
            List<ManifestEntryData> listEntries;
            string folderWithKeys;
            string folderForResult;
            int checkCount = 0;
            string password;



            manifest = getManifestData();
            if (manifest == null) { Console.WriteLine("END"); Console.ReadKey(); return; }

            listEntries = manifest.Entries;
            showEntries(listEntries);
            if (listEntries.Count == 0) { Console.WriteLine("END"); Console.ReadKey(); return; }

            folderWithKeys = getFolderWith_maFile();
            if (folderWithKeys == null || !Directory.Exists(folderWithKeys)) { Console.WriteLine("END"); Console.ReadKey(); return; }
            folderForResult = getFolderForResult();
            if (folderForResult == null) { Console.WriteLine("END"); Console.ReadKey(); return; }
            checkCount = checkFiles(listEntries, folderWithKeys);
            if (checkCount == 0) { Console.WriteLine($"CHECK: Count: {checkCount}\nFiles not found\nEND"); Console.ReadKey(); return; }

            Console.Write("Password: ");
            password = Console.ReadLine();

            decryptFiles(folderWithKeys, folderForResult, password, listEntries);

            Console.WriteLine("END");
            Console.ReadKey();
        }

        private static ManifestData getManifestData()
        {
            string pathFile_Manifest;
            string textManifest;

            Console.Write("Manifest: ");
            Thread.Sleep(TimeSpan.FromSeconds(1));
            pathFile_Manifest = FileIO.GetFilePath(FileIO.FILTER_MANIFEST);
            Console.Write($"{(pathFile_Manifest != null ? pathFile_Manifest : "null")}\n");
            if (pathFile_Manifest == null) return null;

            Console.WriteLine("Read manifest...");
            textManifest = File.ReadAllText(pathFile_Manifest);

            return JsonConvert.DeserializeObject<ManifestData>(textManifest);
        }
        private static void showEntries(List<ManifestEntryData> list)
        {
            Console.WriteLine("Get Entries...");
            Console.WriteLine($"Count: {list.Count}");

            foreach (ManifestEntryData item in list)
            {
                Console.WriteLine($"Entry____\nFilename: {item.Filename}");
            }
        }
        private static string getFolderWith_maFile()
        {
            string path;

            Console.Write("Folder with *.maFile: ");
            Thread.Sleep(TimeSpan.FromSeconds(1));
            path = FileIO.GetDirectory();
            Console.Write($"{(path != null ? path : "null")}\n");
            return path;
        }
        private static string getFolderForResult()
        {
            string path;

            Console.Write("Folder for result: ");
            Thread.Sleep(TimeSpan.FromSeconds(1));
            path = FileIO.GetDirectory();
            Console.Write($"{(path != null ? path : "null")}\n");
            return path;
        }
        private static int checkFiles(List<ManifestEntryData> list, string folder)
        {
            int count = 0;

            foreach (var item in list)
            {
                if (File.Exists(folder + "/" + item.Filename)) count++;
            }

            return count;
        }
        private static void decryptFiles(string folderWithKeys, string folderForResult, string password, List<ManifestEntryData> entries)
        {
            string fileKey;
            string fileDec;

            Console.WriteLine("Decrypt...");
            foreach (var item in entries)
            {
                fileKey = folderWithKeys + "/" + item.Filename;

                if (File.Exists(fileKey))
                {
                    string decData = decryptData(password, item.Salt, item.IV, File.ReadAllText(fileKey));
                    SteamGuardData account = JsonConvert.DeserializeObject<SteamGuardData>(decData);
                    fileDec = folderForResult + "/" + account.AccountName + ".maFile";
                    if (!File.Exists(fileDec)) File.Create(fileDec).Close();
                    File.WriteAllText(fileDec, JsonConvert.SerializeObject(account));
                }
            }


        }
        private static byte[] getEncryptionKey(string password, string salt)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is empty");
            }
            if (string.IsNullOrEmpty(salt))
            {
                throw new ArgumentException("Salt is empty");
            }
            using (Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(password, Convert.FromBase64String(salt), PBKDF2_ITERATIONS))
            {
                return pbkdf2.GetBytes(KEY_SIZE_BYTES);
            }
        }
        private static string decryptData(string password, string passwordSalt, string IV, string encryptedData)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is empty");
            }
            if (string.IsNullOrEmpty(passwordSalt))
            {
                throw new ArgumentException("Salt is empty");
            }
            if (string.IsNullOrEmpty(IV))
            {
                throw new ArgumentException("Initialization Vector is empty");
            }
            if (string.IsNullOrEmpty(encryptedData))
            {
                throw new ArgumentException("Encrypted data is empty");
            }

            byte[] cipherText = Convert.FromBase64String(encryptedData);
            byte[] key = getEncryptionKey(password, passwordSalt);
            string plaintext = null;

            using (RijndaelManaged aes256 = new RijndaelManaged())
            {
                aes256.IV = Convert.FromBase64String(IV);
                aes256.Key = key;
                aes256.Padding = PaddingMode.PKCS7;
                aes256.Mode = CipherMode.CBC;

                //create decryptor to perform the stream transform
                ICryptoTransform decryptor = aes256.CreateDecryptor(aes256.Key, aes256.IV);

                //wrap in a try since a bad password yields a bad key, which would throw an exception on decrypt
                try
                {
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
                catch (CryptographicException)
                {
                    plaintext = null;
                }
            }
            return plaintext;
        }
    }
}
