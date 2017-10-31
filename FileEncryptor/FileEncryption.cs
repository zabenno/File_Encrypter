using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FileEncryptor
{
    class FileEncryption
    {
        Aes aes = Aes.Create();
        SHA256CryptoServiceProvider sha = new SHA256CryptoServiceProvider();
        Random random = new Random();
        byte[] salt = new byte[16];

        public FileEncryption()
        {
            aes.KeySize = 256;
        }

        public void CreateKey(string password)
        {
            byte[] pass = Encoding.Unicode.GetBytes(password);
            random.NextBytes(salt);
            byte[] saltedPassword = new byte[16 + pass.Length];
            Array.Copy(pass, saltedPassword, pass.Length);
            Array.Copy(salt, 0, saltedPassword, password.Length, salt.Length);

            aes.Key = sha.ComputeHash(saltedPassword);
        }

        public void discoverKey(string password, byte[] salt)
        {
            byte[] pass = Encoding.Unicode.GetBytes(password);
            byte[] saltedPassword = new byte[16 + pass.Length];
            Array.Copy(pass, saltedPassword, pass.Length);
            Array.Copy(salt, 0, saltedPassword, password.Length, salt.Length);
            aes.Key = sha.ComputeHash(saltedPassword);
        }

        public void encryptFile(string filePath)
        {
            //Setup temporary file name.
            var temporaryName = getTemporaryName(filePath);
            
            //Opening file to be encrypted.
            FileStream oldfile = new FileStream(filePath, FileMode.Open, FileAccess.Read);

            //Creating new Random IV for aes.
            aes.GenerateIV();

            //Creating a file to write to and adding salt used for hash and IV.
            FileStream newFile = new FileStream(temporaryName, FileMode.CreateNew, FileAccess.Write);
            newFile.Write(salt, 0, 16);
            newFile.Write(aes.IV, 0, aes.IV.Length);

            //Creating encryptor to be used.
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            int bytesRead = 0;

            //While the old file has not been entirely encrypted.
            while (oldfile.Length > bytesRead)
            {
                //Decide how many bytes to encrypt at once and read them in.
                int bytesToRead = Math.Min(320000000, (int) oldfile.Length - bytesRead);
                byte[] readFromFile = new byte[bytesToRead];
                oldfile.Read(readFromFile, 0, bytesToRead);
                bytesRead += bytesToRead;

                //Encrypt bytes that have been read into memory then write them to the new file.
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                    {
                        cryptStream.Write(readFromFile, 0, readFromFile.Length);
                    }
                    byte[] bytesToWrite = memStream.ToArray();
                    newFile.Write(bytesToWrite, 0, bytesToWrite.Length);
                }
            }

            //Clean up.
            oldfile.Close();
            newFile.Flush();
            newFile.Close();
            moveFile(filePath, temporaryName);

        }

        public string getTemporaryName(string filePath)
        {
            string[] seperators = { "\\" };
            string[] seperatorsv2 = { "." };
            string[] dirs = filePath.Split(seperators, StringSplitOptions.RemoveEmptyEntries);
            string filename = dirs[dirs.Length - 1];
            string[] nameParts = filename.Split(seperatorsv2, StringSplitOptions.RemoveEmptyEntries);
            string temporaryName = System.Environment.CurrentDirectory + "\\" + nameParts[0] + "temporary." + nameParts[1];
            return temporaryName;
        }

        public void decryptFile(string filePath, string password)
        {
            //Setup temporary file name.
            var temporaryName = getTemporaryName(filePath);

            //Opening file to be encrypted.
            FileStream oldfile = new FileStream(filePath, FileMode.Open, FileAccess.Read);

            long fileLength = oldfile.Length- 16 - aes.IV.Length;
            //Obtain IV and salt for decryption.
            byte[] salt = new byte[16];
            oldfile.Read(salt, 0, 16);
            byte[] IV = new byte[aes.IV.Length];
            oldfile.Read(IV, 0, aes.IV.Length);
            aes.IV = IV;

            discoverKey(password, salt);

            //Creating a file to write to.
            FileStream newFile = new FileStream(temporaryName, FileMode.Create, FileAccess.Write);

            //Creating decryptor to be used.
            ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            int bytesRead = 0;

            //While the old file has not been entirely decrypted.
            while (fileLength > bytesRead)
            {
                //Decide how many bytes to Decrypt at once and read them in.
                int bytesToRead = Math.Min(320000000, (int)fileLength - bytesRead);
                byte[] readFromFile = new byte[bytesToRead];
                oldfile.Read(readFromFile, 0, bytesToRead);
                bytesRead += bytesToRead;

                //Decrypt bytes that have been read into memory then write them to the new file.
                using (MemoryStream memStream = new MemoryStream())
                {
                    using (CryptoStream cryptStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptStream.Write(readFromFile, 0, readFromFile.Length);
                    }
                    byte[] bytesToWrite = memStream.ToArray();
                    newFile.Write(bytesToWrite, 0, bytesToWrite.Length);
                }
            }

            //Clean up.
            oldfile.Close();
            newFile.Flush();
            newFile.Close();
            moveFile(filePath, temporaryName);
        }

        private void moveFile(string newFilePath, string file)
        {
            try
            {
                if (File.Exists(newFilePath))
                {
                    File.Delete(newFilePath);
                }

                File.Move(file, newFilePath);
            }
            catch
            {
                Console.Out.WriteLine("I am sorry, I have failed you.");
            }
        }
    }
}
