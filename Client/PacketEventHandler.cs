using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Drawing;

using libMC.NET.Common;
using libMC.NET.Entities;
using libMC.NET.Network;
using libMC.NET.World;

using System.Security.Cryptography;
using Newtonsoft.Json.Linq;
using SMProxy;

namespace libMC.NET.Client {
    class PacketEventHandler {
        public PacketEventHandler(NetworkHandler nh) {
            // -- Login packets
            nh.RegisterLoginHandler(0, new NetworkHandler.PacketHandler(HandleLoginDisconnect));
            nh.RegisterLoginHandler(1, new NetworkHandler.PacketHandler(HandleEncryptionRequest));
            nh.RegisterLoginHandler(2, new NetworkHandler.PacketHandler(HandleLoginSuccess));

            // -- Status Packets
            nh.RegisterStatusHandler(0, new NetworkHandler.PacketHandler(HandleStatusResponse));
            nh.RegisterStatusHandler(1, new NetworkHandler.PacketHandler(HandleStatusPing));

            // -- Play packets
            nh.RegisterPlayHandler(0, new NetworkHandler.PacketHandler(HandleKeepAlive));
            nh.RegisterPlayHandler(0x02, new NetworkHandler.PacketHandler(HandleChat));
            nh.RegisterPlayHandler(0x07, new NetworkHandler.PacketHandler(HandleRespawn));
            nh.RegisterPlayHandler(0x0B, new NetworkHandler.PacketHandler(HandleAnimation));
            nh.RegisterPlayHandler(0x21, new NetworkHandler.PacketHandler(HandleChunkData));
            nh.RegisterPlayHandler(0x26, new NetworkHandler.PacketHandler(HandleMapChunkBulk));
            nh.RegisterPlayHandler(0x40, new NetworkHandler.PacketHandler(HandleDisconnect));
            
        }

        #region Login Packets
        public void HandleLoginDisconnect(MinecraftClient client, IPacket packet) {
            var Disconnect = (CBLoginDisconnect)packet;

            client.RaiseLoginFailure(this, Disconnect.JSONData);
            client.Disconnect();
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

            client.nh.wSock.EncEnabled = true;
            client.nh.RaiseSocketInfo(this, "Encryption Enabled.");
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

        public void HandleLoginSuccess(MinecraftClient client, IPacket packet) {
            var Success = (CBLoginSuccess)packet;
            client.RaiseLoginSuccess(this);
            client.RaiseDebug(this, "UUID: " + Success.UUID + " Username: " + Success.Username);

            if (client.ThisPlayer == null)
                client.ThisPlayer = new Player();

            client.ThisPlayer.playerName = Success.Username;
            client.ServerState = 3;
            client.RaiseDebug(this, "The server state is now 3 (Play)");
        }
        #endregion
        #region Status Packets
        public void HandleStatusResponse(MinecraftClient client, IPacket packet) {
            string versionName, MOTD; // -- Variables that are enclosed in json.
            int ProtocolVersion, MaxPlayers, OnlinePlayers;
            List<string> Players = null;
            Image favicon = null;

            var Response = (CBResponse)packet;
            var jsonObj = JToken.Parse(Response.JSONResponse);

            versionName = jsonObj["version"]["name"].Value<string>();
            ProtocolVersion = jsonObj["version"]["protocol"].Value<int>();

            MaxPlayers = jsonObj["players"]["max"].Value<int>(); ;
            OnlinePlayers = jsonObj["players"]["online"].Value<int>();

            var tempPlayers = jsonObj["players"]["sample"];

            if (tempPlayers != null) {
                Players = new List<string>();

                foreach (JObject b in tempPlayers) {
                    Players.Add(b.Last.First.ToString());
                }
            }

            MOTD = jsonObj["description"].Value<string>();
            string imageString = jsonObj["favicon"].Value<string>();

            if (imageString != null) {
                try {
                    var imageBytes = Convert.FromBase64String(imageString.Replace("data:image/png;base64,", ""));

                    var ms = new MemoryStream(imageBytes);
                    favicon = Image.FromStream(ms, false, true);
                    ms.Close();
                } catch {
                    favicon = null;
                }
            }

            client.RaisePingResponse(versionName, ProtocolVersion, MaxPlayers, OnlinePlayers, Players.ToArray(), MOTD, favicon);

            var Ping = new SBPing();
            Ping.Time = DateTime.UtcNow.Ticks;
            Ping.Write(client.nh.wSock);
        }
        public void HandleStatusPing(MinecraftClient client, IPacket packet) {
            var Ping = (CBPing)packet;
            client.RaisePingMs((int)(DateTime.UtcNow.Ticks - Ping.Time) / 10000); // -- 10,000 ticks per millisecond.
            client.nh.RaiseSocketDebug(this, "Server ping complete.");
        }
        #endregion
        #region Play Packets
        public void HandleKeepAlive(MinecraftClient client, IPacket packet) {
            var KA = (CBKeepAlive)packet;

            var KAS = new SBKeepAlive();
            KAS.KeepAliveID = KA.KeepAliveID;
            KAS.Write(client.nh.wSock);
        }

        public void HandleChat(MinecraftClient client, IPacket packet) {
            var Chat = (CBChatMessage)packet;

            string sender = "";
            string parsedMessage = ParseJsonChat(Chat.JSONData, ref sender);

            client.RaiseMC(this, parsedMessage, sender);
        }
        #region Chat Message Helping Functions
        string ParseJsonChat(string raw, ref string sender) {
            bool bold = false, italic = false, underlined = false, strikethrough = false, obfs = false;
            string text = "", translate = "", color = "", name = "";//, final = "";
            //dynamic clickEvent, hoverEvent;

            JToken jsonObj = JToken.Parse(raw);

            if (jsonObj["text"] != null) // -- Raw text, just let the clients parse it from here.
                return jsonObj["text"].Value<string>();

            if (jsonObj["translate"] != null)
                translate = jsonObj["translate"].Value<string>();

            if (jsonObj["bold"] != null)
                bold = jsonObj["bold"].Value<bool>();

            if (jsonObj["italic"] != null)
                italic = jsonObj["italic"].Value<bool>();

            if (jsonObj["underlined"] != null)
                underlined = jsonObj["underlined"].Value<bool>();

            if (jsonObj["strikethrough"] != null)
                strikethrough = jsonObj["strikethrough"].Value<bool>();

            if (jsonObj["obfuscated"] != null)
                obfs = jsonObj["obfuscated"].Value<bool>();

            if (jsonObj["color"] != null)
                color = jsonObj["color"].Value<string>();

            switch (translate) {
                case "chat.type.text":
                    name = jsonObj["with"][0]["text"].Value<string>();
                    sender = name;
                    text = jsonObj["with"][1].Value<string>();
                    break;
                case "multiplayer.player.joined":
                    sender = "EVENT";
                    text = jsonObj["with"][0]["text"].Value<string>() + " joined the game.";
                    break;
                case "multiplayer.player.left":
                    sender = "EVENT";
                    text = jsonObj["with"][0]["text"].Value<string>() + " left the game.";
                    break;
                case "death.attack.player":
                    //name = jsonObj.with[0].text;
                    sender = "EVENT";
                    text = jsonObj["with"][0]["text"].Value<string>() + " killed by " + jsonObj["with"][2]["text"].Value<string>();
                    break;
                case "chat.type.admin":
                    sender = "EVENT";
                    break;
                case "chat.type.announcement":
                    name = "Server";
                    sender = name;
                    text = string.Join("", jsonObj["with"][1]["extra"][0].Value<string>());
                    break;
            }

            // -- Do post-processing
            // -- Converts the json string into old style string, except it doesn't include the name.
            // -- This makes it so the maker of the client can choose their perfered style of text. <name>, name, [name], ect.

            if (color != "")
                text = Color_To_Code(color) + text;

            if (italic)
                text = "§o" + text;

            if (bold)
                text = "§l" + text;

            if (strikethrough)
                text = "§m" + text;

            if (obfs)
                text = "§k" + text;

            return text;
        }

        public string Color_To_Code(string Color) {
            string code = "";

            switch (Color) {
                case "black":
                    code = "§0";
                    break;
                case "darkblue":
                    code = "§1";
                    break;
                case "darkgreen":
                    code = "§2";
                    break;
                case "darkcyan":
                    code = "§3";
                    break;
                case "darkred":
                    code = "§4";
                    break;
                case "purple":
                    code = "§5";
                    break;
                case "orange":
                    code = "§6";
                    break;
                case "gray":
                    code = "§7";
                    break;
                case "darkgray":
                    code = "§8";
                    break;
                case "blue":
                    code = "§9";
                    break;
                case "brightgreen":
                    code = "§A";
                    break;
                case "cyan":
                    code = "§B";
                    break;
                case "red":
                    code = "§C";
                    break;
                case "pink":
                    code = "§D";
                    break;
                case "yellow":
                    code = "§E";
                    break;
                case "white":
                    code = "§F";
                    break;
            }

            return code;
        }
        #endregion
        public void HandleAnimation(MinecraftClient client, IPacket packet) {
            var Animation = (CBAnimation)packet;

            if (client.ThisPlayer != null && Animation.EntityID == client.ThisPlayer.Entity_ID)
                client.ThisPlayer.Animation = Animation.Animation;

            if (client.MinecraftWorld != null) {
                var index = client.MinecraftWorld.GetEntityById(Animation.EntityID);
                if (index != -1)
                    client.MinecraftWorld.Entities[index].animation = Animation.Animation;
            }

            client.RaiseEntityAnimationChanged(this, Animation.EntityID, Animation.Animation);
        }
        public void HandleChunkData(MinecraftClient client, IPacket packet) {
            var ChunkData = (CBChunkData)packet;

            byte[] trim = new byte[ChunkData.Compressedsize - 2];
            byte[] decompressedData;

            if (ChunkData.Primarybitmap == 0) {
                // -- Unload chunk.
                int cIndex = -1;

                if (client.MinecraftWorld != null)
                    cIndex = client.MinecraftWorld.GetChunk(ChunkData.ChunkX, ChunkData.ChunkZ);

                if (cIndex != -1)
                    client.MinecraftWorld.worldChunks.RemoveAt(cIndex);

                client.RaiseChunkUnload(ChunkData.ChunkX, ChunkData.ChunkZ);
                return;
            }

            // -- Remove GZip Header
            Buffer.BlockCopy(ChunkData.Compresseddata, 2, trim, 0, trim.Length);

            // -- Decompress the data
            decompressedData = Decompressor.Decompress(trim);

            // -- Create new chunk
            Chunk newChunk = new Chunk(ChunkData.ChunkX, ChunkData.ChunkZ, (short)ChunkData.Primarybitmap, (short)ChunkData.Addbitmap, true, ChunkData.GroundUpcontinuous); // -- Skylight assumed true
            newChunk.GetData(decompressedData);

            if (client.MinecraftWorld == null)
                client.MinecraftWorld = new WorldClass();

            // -- Add the chunk to the world
            client.MinecraftWorld.worldChunks.Add(newChunk);

            client.RaiseChunkLoad(ChunkData.ChunkX, ChunkData.ChunkZ);
        }
        public void HandleDisconnect(MinecraftClient client, IPacket packet) {
            var Disconnect = (CBDisconnect)packet;

            client.RaiseInfo(this, "You were kicked! Reason: " + Disconnect.Reason);
            client.RaiseKicked(Disconnect.Reason);
            client.Disconnect();
        }
        public void HandleEffects(MinecraftClient client, IPacket packet) {
            //TODO: Implement this, Pull requests welcome and are encouraged for parsing the IDs and raising an event for this.
        }
        public void HandleMapChunkBulk(MinecraftClient client, IPacket packet) {
            var ChunkPacket = (CBMapChunkBulk)packet;
            int Offset = 0;

            byte[] trim = new byte[ChunkPacket.Datalength - 2];
            byte[] DecompressedData;

            Chunk[] chunks = new Chunk[ChunkPacket.Chunkcolumncount];

            Buffer.BlockCopy(ChunkPacket.Data, 2, trim, 0, trim.Length);

            DecompressedData = Decompressor.Decompress(trim);

            for (int i = 0; ChunkPacket.Chunkcolumncount > i; i++) {
                int x = BitConverter.ToInt32(ChunkPacket.Metainformation, Offset);
                int z = BitConverter.ToInt32(ChunkPacket.Metainformation, Offset + 4);
                short pbitmap = ReverseBytes(BitConverter.ToInt16(ChunkPacket.Metainformation, Offset + 8));
                short abitmap = ReverseBytes(BitConverter.ToInt16(ChunkPacket.Metainformation, Offset + 10));
                Offset += 12;

                chunks[i] = new Chunk(x, z, pbitmap, abitmap, ChunkPacket.Skylightsent, true); // -- Assume true for Ground Up Continuous

                DecompressedData = chunks[i].GetData(DecompressedData); // -- Calls the chunk class to take all of the bytes it needs, and return whats left.

                if (client.MinecraftWorld == null)
                    client.MinecraftWorld = new WorldClass();

                client.MinecraftWorld.worldChunks.Add(chunks[i]);
            }
        }
        #region MapChunkBulk Helping Methods
        public static short ReverseBytes(short value) {
            return (short)((value & 0xFFU) << 8 | (value & 0xFF00U) >> 8);
        }
        #endregion

        public void HandleRespawn(MinecraftClient client, IPacket packet) {
            var Respawn = (CBRespawn)packet;

            client.MinecraftWorld = new WorldClass();
            client.MinecraftWorld.dimension = (sbyte)Respawn.Dimension;
            client.MinecraftWorld.difficulty = Respawn.Difficulty;
            client.MinecraftWorld.levelType = Respawn.LevelType;

            if (client.ThisPlayer == null)
                client.ThisPlayer = new Player();

            client.ThisPlayer.gameMode = Respawn.Gamemode;

            client.RaisePlayerRespawn();
        }
        #endregion
    }
}
