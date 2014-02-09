using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using CWrapped;

namespace libMC.NET.Entities {
    public class Item {
        public int itemID;
        public byte itemCount;
        public short itemDamage;
        public byte[] nbtData;

        public void ReadSlot(ref Wrapped wSock) {
            int blockID = wSock.readShort();

            if (blockID == -1) {
                itemID = 0;
                itemCount = 0;
                itemDamage = 0;
                return;
            }

            itemCount = wSock.readByte();
            itemDamage = wSock.readShort();
            int NBTLength = wSock.readShort();

            if (NBTLength == -1) {
                return;
            }

            nbtData = wSock.readByteArray(NBTLength);

            return;
        }
        public string FriendlyName() {
            // -- Return the friendly name for the item we represent

            return ((Block.blockitemid)itemID).ToString();
        }

        public static void WriteSlot(ref Wrapped wSock, Item item) {
            if (item == null) {
                wSock.writeShort(-1);
                return;
            }

            wSock.writeShort((short)item.itemID);
            wSock.writeByte(item.itemCount);
            wSock.writeShort(item.itemDamage);
            wSock.writeShort(-1);
        }
    }
}
