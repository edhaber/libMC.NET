﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CWrapped;
using System.Net.Sockets;
using System.Threading;
using libMC.NET.Network;
using libMC.NET.MinecraftWorld;

namespace libMC.NET.Client {
    public class NetworkHandler {
        #region Variables
        Thread handler;
        MinecraftClient mainMC;
        TcpClient baseSock;
        NetworkStream baseStream;
        public Wrapped wSock;
        public TickHandler worldTick;

        #region Packet Dictionaries
        Dictionary<int, Func<IPacket>> packetsLogin;
        Dictionary<int, Func<IPacket>> packetsPlay;
        Dictionary<int, Func<IPacket>> packetsStatus;
        #endregion
        #endregion

        public NetworkHandler(MinecraftClient mc) {
            mainMC = mc;
            PopulateLists();
        } 
        
        /// <summary>
        /// Starts the network handler.
        /// </summary>
        public void Start() {
            try {
                baseSock = new TcpClient();
                var AR = baseSock.BeginConnect(mainMC.ServerIP, mainMC.ServerPort, null, null);
                var wh = AR.AsyncWaitHandle;

                try {
                    if (!AR.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5), false)) {
                        baseSock.Close();
                        RaiseSocketError(this, "Failed to connect: Connection Timeout");
                        return;
                    }

                    baseSock.EndConnect(AR);
                } finally {
                    wh.Close();
                }

            } catch (Exception e) {
                RaiseSocketError(this, "Failed to connect: " + e.Message);
                return;
            }
            
            mainMC.Running = true;

            RaiseSocketInfo(this, "Connected to server.");
            RaiseSocketDebug(this, string.Format("IP: {0} Port: {1}", mainMC.ServerIP, mainMC.ServerPort.ToString()));

            // -- Create our Wrapped socket.
            baseStream = baseSock.GetStream();
            wSock = new Wrapped(baseStream);

            RaiseSocketDebug(this, "Socket Created");

            // -- Send a handshake packet
            
            var hs = new SBHandshake();
            hs.ProtocolVersion = 4;
            hs.ServerAddress = mainMC.ServerIP;
            hs.ServerPort = (short)mainMC.ServerPort;
            hs.NextState = 2;

            if (mainMC.ServerState == 1)
                hs.NextState = 1;

            hs.Write(wSock);

            if (mainMC.ServerState == 1) {
                var PingRequest = new SBRequest();
                PingRequest.Write(wSock);
            }

            RaiseSocketDebug(this, "Handshake sent.");

            // -- Start network parsing.
            handler = new Thread(PacketHandler);
            handler.Start();
            RaiseSocketDebug(this, "Handler thread started");
        }
       
        /// <summary>
        /// Stops the network handler.
        /// </summary>
        public void Stop() {
            DebugMessage(this, "Stopping network handler...");
            handler.Abort();

            wSock = null;
            baseStream = null;

            baseSock.Close();
            InfoMessage(this, "Disconnected from Minecraft Server.");


        }
        
        /// <summary>
        /// Populates the packet lists with reconized types.
        /// </summary>
        /// 
        void PopulateLists() {
            packetsLogin = new Dictionary<int,Func<IPacket>> {
                {0, () => new CBDisconnect() },
                {1, () => new CBEncryptionRequest() },
                {2, () => new CBLoginSuccess() }
            };

            packetsStatus = new Dictionary<int, Func<IPacket>> {
                {0, () => new CBResponse() },
                {1, () => new CBPing() }
            };

            //-------------------
            packetsPlay = new Dictionary<int, Func<IPacket>> {
                {0, () => new CBKeepAlive() },
                {1, () => new CBJoinGame() },
                {2, () => new CBChatMessage() },
                {3, () => new CBTimeUpdate() },
                {4, () => new CBEntityEquipment() },
                {5, () => new CBSpawnPosition() },
                {6, () => new CBUpdateHealth() },
                {7, () => new CBRespawn() },
                {8, () => new CBPlayerPositionAndLook() },
                {9, () => new CBHeldItemChange() },
                {10, () => new CBUseBed() },
                {11, () => new CBAnimation() },
                {12, () => new CBSpawnPlayer() },
                {13, () => new CBCollectItem() },
                {14, () => new CBSpawnObject() },
                {15, () => new CBSpawnMob() },
                {16, () => new CBSpawnPainting() },
                {17, () => new CBSpawnExperienceOrb() },
                {18, () => new CBEntityVelocity() },
                {19, () => new CBDestroyEntities() },
                {20, () => new CBEntity() },
                {21, () => new CBEntityRelativeMove() },
                {22, () => new CBEntityLook() },
                {23, () => new CBEntityLookandRelativeMove() },
                {24, () => new CBEntityTeleport() },
                {25, () => new CBEntityHeadLook() },
                {26, () => new CBEntityStatus() },
                {27, () => new CBAttachEntity() },
                {28, () => new CBEntityMetadata() },
                {29, () => new CBEntityEffect() },
                {30, () => new CBRemoveEntityEffect() },
                {31, () => new CBSetExperience() },
                {32, () => new CBEntityProperties() },
                {33, () => new CBChunkData() },
                {34, () => new CBMultiBlockChange() },
                {35, () => new CBBlockChange() },
                {36, () => new CBBlockAction() },
                {37, () => new CBBlockBreakAnimation() },
                {38, () => new CBMapChunkBulk() },
                {39, () => new CBExplosion() },
                {40, () => new CBEffect() },
                {41, () => new CBSoundEffect() },
                {42, () => new CBParticle() },
                {43, () => new CBChangeGameState() },
                {44, () => new CBSpawnGlobalEntity() },
                {45, () => new CBOpenWindow() },
                {46, () => new CBCloseWindow() },
                {47, () => new CBSetSlot() },
                {48, () => new CBWindowItems() },
                {49, () => new CBWindowProperty() },
                {50, () => new CBConfirmTransaction() },
                {51, () => new CBUpdateSign() },
                {52, () => new CBMaps() }, // Still no clue what this is for.
                {53, () => new CBUpdateBlockEntity() },
                {54, () => new CBSignEditorOpen() },
                {55, () => new CBStatistics() },
                {56, () => new CBPlayerListItem() },
                {57, () => new CBPlayerAbilities() },
                {58, () => new CBTabComplete() },
                {59, () => new CBScoreboardObjective() },
                {60, () => new CBUpdateScore() },
                {61, () => new CBDisplayScoreboard() },
                {62, () => new CBTeams() },
                {63, () => new CBPluginMessage() },
                {64, () => new CBDisconnect() }
            };

            RaiseSocketDebug(this, "List populated");
        }
        /// <summary>
        /// Creates an instance of each new packet, so it can be parsed.
        /// </summary>
        void PacketHandler() {
            try {
                int length = 0;

                while ((length = wSock.readVarInt()) != 0) {
                    if (baseSock.Connected) {
                        var packetID = wSock.readVarInt();

                        switch (mainMC.ServerState) {
                            case (int)ServerState.Status:
                                if (packetsStatus.Keys.Contains(packetID) == false) {
                                    RaiseSocketError(this, "Unknown Packet ID. State: 1, Packet: " + packetID);
                                    wSock.readByteArray(length - 1); // -- bypass the packet
                                    continue;
                                }

                                var packet = packetsStatus[packetID].Invoke();
                                packet.Read(wSock);
                                RaisePacketHandled(this, packet, packetID);

                                break;

                            case (int)ServerState.Login:
                                if (packetsLogin.Keys.Contains(packetID) == false) {
                                    RaiseSocketError(this, "Unknown Packet ID. State: 2, Packet: " + packetID);
                                    wSock.readByteArray(length - 1); // -- bypass the packet
                                    continue;
                                }

                                var packetl = packetsLogin[packetID].Invoke();
                                packetl.Read(wSock);
                                RaisePacketHandled(this, packetl, packetID);

                                break;

                            case (int)ServerState.Play:
                                if (packetsPlay.Keys.Contains(packetID) == false) {
                                    RaiseSocketError(this, "Unknown Packet ID. State: 3, Packet: " + packetID);
                                    wSock.readByteArray(length - 1); // -- bypass the packet
                                    continue;
                                }

                                var packetp = packetsPlay[packetID].Invoke();
                                packetp.Read(wSock);
                                RaisePacketHandled(this, packetp, packetID);

                                break;
                        }
                        if (worldTick != null)
                            worldTick.DoTick();
                    }
                }
            } catch (Exception e) {
                if (e.GetType() != typeof(ThreadAbortException)) {
                    RaiseSocketError(this, "Critical error in handling packets.");
                    RaiseSocketError(this, e.Message);
                    RaiseSocketError(this, e.StackTrace);
                    Stop();
                }
            }
        }

        enum ServerState {
            Status = 1,
            Login,
            Play
        }

        #region Event Messengers
        public void RaiseSocketError(object sender, string message) {
            if (SocketError != null)
                SocketError(sender, message);
            
        }
        public void RaiseSocketInfo(object sender, string message) {
            if (InfoMessage != null)
                InfoMessage(sender, message);
        }
        public void RaiseSocketDebug(object sender, string message) {
            if (DebugMessage != null)
                DebugMessage(sender, message);
        }
        public void RaisePacketHandled(object sender, object packet, int id) {
            if (PacketHandled != null)
                PacketHandled(sender, packet, id);
        }
        #endregion
        #region Event Delegates
        public delegate void SocketErrorHandler(object sender, string message);
        public event SocketErrorHandler SocketError;

        public delegate void NetworkInfoHandler(object sender, string message);
        public event NetworkInfoHandler InfoMessage;

        public delegate void NetworkDebugHandler(object sender, string message);
        public event NetworkDebugHandler DebugMessage;

        public delegate void PacketHandledHandler(object sender, object packet, int id);
        public event PacketHandledHandler PacketHandled;
        #endregion
    }
}
