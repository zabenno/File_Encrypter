using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

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

        /// <summary>
        /// Creates a key that will be used later for encrypting.
        /// </summary>
        /// <param name="password">The password submitted by the user.</param>
        public void CreateKey(string password)
        {
            //Salting the password.
            byte[] pass = Encoding.Unicode.GetBytes(password);
            random.NextBytes(salt);
            byte[] saltedPassword = new byte[16 + pass.Length];
            Array.Copy(pass, saltedPassword, pass.Length);
            Array.Copy(salt, 0, saltedPassword, password.Length, salt.Length);

            //Computing the hash that will be used as the aes key.
            aes.Key = sha.ComputeHash(saltedPassword);
        }

        /// <summary>
        /// Given the salt from the file and the password a user enters an aes key will be generated to decrypt the file.
        /// </summary>
        /// <param name="password">The password submitted by the user.</param>
        /// <param name="salt">The salt obtained from the file.</param>
        public void discoverKey(string password, byte[] salt)
        {
            //Salting the password.
            byte[] pass = Encoding.Unicode.GetBytes(password);
            byte[] saltedPassword = new byte[16 + pass.Length];
            Array.Copy(pass, saltedPassword, pass.Length);
            Array.Copy(salt, 0, saltedPassword, password.Length, salt.Length);
            //Computing the hash to be used as the aes key.
            aes.Key = sha.ComputeHash(saltedPassword);
        }

        /// <summary>
        /// Encrypts the file with the given file path. Requires a key to have been generated.
        /// </summary>
        /// <param name="filePath">The path of the file to be encrypted.</param>
        public void encryptFile(string filePath)
        {
            //Setup temporary file name.
            var temporaryName = getTemporaryName(filePath);
            
            //Opening file to be encrypted.
            FileStream oldfile = new FileStream(filePath, FileMode.Open, FileAccess.Read);

            //Creating new Random IV for aes.
            aes.GenerateIV();

            //Creating a file to write to and adding salt used for hash and IV.
            FileStream newFile = new FileStream(temporaryName, FileMode.Create, FileAccess.Write);
            newFile.Write(salt, 0, 16);
            newFile.Write(aes.IV, 0, aes.IV.Length);

            //Creating encryptor to be used.
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            //Encrypting file.
            try
            {
                using (CryptoStream cryptStream = new CryptoStream(newFile, encryptor, CryptoStreamMode.Write))
                {
                    oldfile.CopyTo(cryptStream);
                }
            }
            catch(Exception e)
            {
                Console.Out.WriteLine(e.ToString());
                oldfile.Close();
                newFile.Close();
                File.Delete(temporaryName);
                return;
            }

            //Clean up.
            oldfile.Close();
            moveFile(filePath, temporaryName);

        }

        /// <summary>
        /// Makes a temporary file path for use while a file is being encrypted/decrypted.
        /// </summary>
        /// <param name="filePath">Path of the file being encrypted/decrypted.</param>
        /// <returns>The temporary file path to be used.</returns>
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

        /// <summary>
        /// Decrypts the given file using the salt and IV from the file and the password the user submits.
        /// </summary>
        /// <param name="filePath">The location of the file.</param>
        /// <param name="password">The password being attempted.</param>
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

            //Decrypting file.
            try
            {
                using (CryptoStream cryptStream = new CryptoStream(newFile, decryptor, CryptoStreamMode.Write))
                {
                    oldfile.CopyTo(cryptStream);
                }
            }
            catch(Exception e)
            {
                Console.Out.WriteLine(e.ToString());
                oldfile.Close();
                newFile.Close();
                File.Delete(temporaryName);
                return;
            }

            //Clean up.
            oldfile.Close();
            moveFile(filePath, temporaryName);
        }

        /// <summary>
        /// Moves a file from one location to another. Overwrites.
        /// </summary>
        /// <param name="newFilePath">The new file location.</param>
        /// <param name="file">The old file location.</param>
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
