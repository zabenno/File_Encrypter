using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FileEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            FileEncryption fe = new FileEncryption();
            fe.CreateKey("Help");
            fe.encryptFile("C:\\Users\\ben\\Documents\\Visual Studio 2017\\Projects\\FileEncryptor\\FileEncryptor\\bin\\Debug\\test.txt");
            fe.decryptFile("C:\\Users\\ben\\Documents\\Visual Studio 2017\\Projects\\FileEncryptor\\FileEncryptor\\bin\\Debug\\testtemporary.txt");
        }
    }
}
