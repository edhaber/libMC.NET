using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using libMC.NET.Common;
using libMC.NET.Network;
using System.Security.Cryptography;
using SMProxy;

namespace libMC.NET.Client {
    class PacketEventHandler {
        public PacketEventHandler(NetworkHandler nh) {

        }

        public void HandleEncryptionRequest(MinecraftClient client, IPacket packet) {
            var ER = (CBEncryptionRequest)packet;
            var SharedKey = new byte[16];

            var Random = RandomNumberGenerator.Create(); // -- Generate a random shared key.
            Random.GetBytes(SharedKey);

            if (ER.ServerID == "" && client.VerifyNames) {
                // -- Verify with Minecraft.net.
                // -- At this point, the server requires a hash containing the server id,
                // -- shared key, and original public key. So we make this, and then pass to Minecraft.net

                List<byte> HashList = new List<byte>();
                HashList.AddRange(Encoding.ASCII.GetBytes(ER.ServerID));
                HashList.AddRange(SharedKey);
                HashList.AddRange(ER.PublicKey);

                var HashData = HashList.ToArray();
                var Hash = JavaHexDigest(HashData);

                var Verify = new Minecraft_Net_Interaction();

                if (!Verify.VerifyName(client.ClientName, client.AccessToken, client.SelectedProfile, Hash)) {
                    client.RaiseLoginFailure(this, "Failed to verify name with Minecraft session server.");
                    client.Disconnect();
                    return;
                }
            } else
                client.RaiseInfo(this, "Name verification disabled, skipping authentication.");

            // -- AsnKeyParser is a part of the cryptography.dll, which is simply a compiled version
            // -- of SMProxy's Cryptography.cs, with the server side parts stripped out.
            // -- You pass it the key data and ask it to parse, and it will 
            // -- Extract the server's public key, then parse that into RSA for us.

            var KeyParser = new AsnKeyParser(ER.PublicKey);
            var Dekey = KeyParser.ParseRSAPublicKey();

            // -- Now we create an encrypter, and encrypt the token sent to us by the server
            // -- as well as our newly made shared key (Which can then only be decrypted with the server's private key)
            // -- and we send it to the server.

            var cryptoService = new RSACryptoServiceProvider(); // -- RSA Encryption class
            cryptoService.ImportParameters(Dekey); // -- Import the Server's public key to use as the RSA encryption key.

            byte[] EncryptedSecret = cryptoService.Encrypt(SharedKey, false); // -- Encrypt the Secret key and verification token.
            byte[] EncryptedVerify = cryptoService.Encrypt(ER.VerifyToken, false);

            client.nh.wSock.InitEncryption(SharedKey); // -- Give the shared secret key to the socket

            var Response = new SBEncryptionResponse(); // -- Respond to the server

            Response.SharedLength = (short)EncryptedSecret.Length;
            Response.SharedSecret = EncryptedSecret;
            Response.VerifyLength = (short)EncryptedVerify.Length;
            Response.VerifyToken = EncryptedVerify;

            Response.Write(client.nh.wSock);
        }

        #region Encryption Helping Functions
        private static string GetHexString(byte[] p) {
            string result = "";
            for (int i = 0; i < p.Length; i++) {
                if (p[i] < 0x10)
                    result += "0";
                result += p[i].ToString("x"); // Converts to hex string
            }
            return result;
        }

        private static byte[] TwosCompliment(byte[] p) // little endian
        {
            int i;
            bool carry = true;
            for (i = p.Length - 1; i >= 0; i--) {
                p[i] = unchecked((byte)~p[i]);
                if (carry) {
                    carry = p[i] == 0xFF;
                    p[i]++;
                }
            }
            return p;
        }

        public static string JavaHexDigest(byte[] data) {
            SHA1 sha1 = SHA1.Create();
            byte[] hash = sha1.ComputeHash(data);
            bool negative = (hash[0] & 0x80) == 0x80;
            if (negative) // check for negative hashes
                hash = TwosCompliment(hash);
            // Create the string and trim away the zeroes
            string digest = GetHexString(hash).TrimStart('0');
            if (negative)
                digest = "-" + digest;
            return digest;
        }
        #endregion
    }
}
