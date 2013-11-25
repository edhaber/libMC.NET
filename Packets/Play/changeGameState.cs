﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace libMC.NET.Packets.Play {
    class changeGameState : Packet {
        public byte reason;
        public float value;
        public string eventName;

        public changeGameState(ref Minecraft mc) {
            reason = mc.nh.wSock.readByte();
            value = mc.nh.wSock.readFloat();

            handleReason();

            mc.raiseGameStateChanged(eventName, value);
        }
        void handleReason() {
            switch (reason) {
                case 0:
                    eventName = "Invalid bed";
                    break;
                case 1:
                    eventName = "Rain Start";
                    break;
                case 2:
                    eventName = "Rain End";
                    break;
                case 3:
                    eventName = "Game Mode";
                    break;
                case 4:
                    eventName = "Credits";
                    break;
                case 5:
                    eventName = "Demo";
                    break;
                case 6:
                    eventName = "Bow Hit";
                    break;
                case 7:
                    eventName = "Fade value";
                    break;
                case 8:
                    eventName = "Fade time";
                    break;
            }
        }
    }
}
