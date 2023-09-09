namespace Nancy.Cryptography
{
    using System;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Default encryption provider using Aes
    /// </summary>
    public class AesEncryptionProvider : IEncryptionProvider
    {
        private readonly byte[] key;
        private readonly IKeyGenerator keyGenerator;

        /// <summary>
        /// Creates a new instance of the AesEncryptionProvider class
        /// </summary>
        /// <param name="keyGenerator">Key generator to use to generate the key and iv</param>
        public AesEncryptionProvider(IKeyGenerator keyGenerator)
        {
            this.keyGenerator = keyGenerator;
            this.key = keyGenerator.GetBytes(32);
        }

        /// <summary>
        /// Encrypt data
        /// </summary>
        /// <param name="data">Data to encrypt</param>
        /// <returns>Encrypted string</returns>
        public string Encrypt(string data)
        {
            var iv = this.keyGenerator.GetBytes(16);
            using (var provider = Aes.Create())
            using (var encryptor = provider.CreateEncryptor(this.key, iv))
            {
                var input = Encoding.UTF8.GetBytes(data);
                var cipherText = encryptor.TransformFinalBlock(input, 0, input.Length);

                var output = new byte[iv.Length + cipherText.Length];
                iv.CopyTo(output, 0);
                cipherText.CopyTo(output, iv.Length);

                return Convert.ToBase64String(output);
            }
        }

        /// <summary>
        /// Decrypt string
        /// </summary>
        /// <param name="data">Data to decrypt</param>
        /// <returns>Decrypted string</returns>
        public string Decrypt(string data)
        {
            try
            {
                var input = Convert.FromBase64String(data);
                var iv = new byte[16];
                input.CopyTo(iv, 0);

                using (var provider = Aes.Create())
                using (var decryptor = provider.CreateDecryptor(this.key, iv))
                {
                    var output = decryptor.TransformFinalBlock(input, iv.Length, input.Length - iv.Length);

                    return Encoding.UTF8.GetString(output);
                }
            }
            catch (FormatException)
            {
                return String.Empty;
            }
            catch (CryptographicException)
            {
                return String.Empty;
            }
            catch(ArgumentException ex)
            {
                if (ex.ParamName == null)
                {
                    return String.Empty;
                }
                throw;
            }
        }
    }
}
