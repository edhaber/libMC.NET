﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace libMC.NET.Packets.Play {
    class entityHeadLook : Packet {
        public entityHeadLook(ref Minecraft mc) {
            int Entity_ID = mc.nh.wSock.readInt();
            byte head_Yaw = mc.nh.wSock.readByte();

            if (mc.minecraftWorld != null) {
                int eIndex = mc.minecraftWorld.getEntityById(Entity_ID);

                if (eIndex != -1) {
                    mc.minecraftWorld.Entities[eIndex].headPitch = head_Yaw;
                }
            }

            mc.raiseEntityHeadLookChanged(Entity_ID, head_Yaw);
        }
    }
}
