﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Wrapped;

namespace libMC.NET.Packets.Handshake {
    class Handshake : Packet {

        public Handshake(ref Minecraft mineCraft) {
            if (mineCraft.serverState != 1) {
                mineCraft.nh.wSock.writeVarInt(0); // -- Packet ID
                mineCraft.nh.wSock.writeVarInt(4); // -- protocol version
                mineCraft.nh.wSock.writeString(mineCraft.serverIP);
                mineCraft.nh.wSock.writeShort((short)mineCraft.serverPort);
                mineCraft.nh.wSock.writeVarInt(2); // -- Next state
                mineCraft.nh.wSock.Purge(); // -- Send the packet.

                mineCraft.serverState = 2;

                Login.loginStart ls = new Login.loginStart(ref mineCraft);
            } else {
                mineCraft.nh.wSock.writeVarInt(0); // -- Packet ID
                mineCraft.nh.wSock.writeVarInt(4); // -- protocol version
                mineCraft.nh.wSock.writeString(mineCraft.serverIP);
                mineCraft.nh.wSock.writeShort((short)mineCraft.serverPort);
                mineCraft.nh.wSock.writeVarInt(1); // -- Next state
                mineCraft.nh.wSock.Purge(); // -- Send the packet.

                Packets.Status.Request rp = new Status.Request(ref mineCraft);
            }
        }
    }
}
