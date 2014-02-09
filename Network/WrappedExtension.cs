﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using libMC.NET.Common;
using CWrapped;

namespace libMC.NET.Network {
    public struct SlotData {
        public short ID {get; set;}
        public byte ItemCount { get; set; }
        public short ItemDamage { get; set; }
        public byte[] NbtData { get; set; }
    }

    public struct ObjectMetadata {
        public int ObjectID;
        public short SpeedX { get; set; }
        public short SpeedY { get; set; }
        public short SpeedZ { get; set; }
    }

    public struct PropertyData {
        public string Key { get; set; }
        public double Value { get; set; }
        public short ListLength { get; set; }
        public ModifierData[] Modifiers { get; set; }
    }

    public struct ModifierData {
        public byte[] UUID { get; set; } // -- 128 bit signed integer, wtf.
        public double Amount { get; set; }
        public byte Operation { get; set; }
    }

    public struct Record {
        byte[] BlockData;
        int X;
        int Y;
        int Z;
        int BlockID;
        int Metadata;
    }

    /// <summary>
    /// Class for handling all of the additional retarded "Data Types" That Mojang decided to create.
    /// </summary>
    public class WrappedExtension {
        public static object[] ReadEntityMetadata(Wrapped wSock) {
            var MetadataDict = new Dictionary<int, object>();

            do {
                var item = wSock.readByte();

                if (item == 127)
                    break;

                var index = item & 0x1F;
                var type = item >> 5;

                switch (type) {
                    case 0:
                        MetadataDict.Add(index, wSock.readByte());
                        break;
                    case 1:
                        MetadataDict.Add(index, wSock.readShort());
                        break;
                    case 2:
                        MetadataDict.Add(index, wSock.readInt());
                        break;
                    case 3:
                        MetadataDict.Add(index, wSock.readFloat());
                        break;
                    case 4:
                        MetadataDict.Add(index, wSock.readString());
                        break;
                    case 5:
                        MetadataDict.Add(index, ReadSlot(wSock));
                        break;
                    case 6:
                        MetadataDict.Add(index, new Vector(wSock.readInt(), wSock.readInt(), wSock.readInt()));
                        break;
                }
            } while (true);

            MetadataDict.OrderBy(o => o.Key); // -- Order the dictionary based on the index values
            return MetadataDict.Values.ToArray(); // -- Return the data as an array.
        }

        public static void WriteEntityMetadata(Wrapped wSock, object[] Metadata) {
            throw new NotImplementedException("Not quite done here yet.");
        }

        public static ObjectMetadata ReadObjectMetadata(Wrapped wSock) {
            var Data = new ObjectMetadata();
            Data.ObjectID = wSock.readInt();

            if (Data.ObjectID != 0) {
                Data.SpeedX = wSock.readShort();
                Data.SpeedY = wSock.readShort();
                Data.SpeedZ = wSock.readShort();
            }

            return Data;
        }

        public static void WriteObjectMetadata(Wrapped wSock, ObjectMetadata Data) {
            wSock.writeInt(Data.ObjectID);
            
            if (Data.ObjectID != 0) {
                wSock.writeShort(Data.SpeedX);
                wSock.writeShort(Data.SpeedY);
                wSock.writeShort(Data.SpeedZ);
            }
        }

        public static PropertyData ReadPropertyData(Wrapped wSock) {
            var Data = new PropertyData();

            Data.Key = wSock.readString();
            Data.Value = wSock.readDouble();
            Data.ListLength = wSock.readShort();
            Data.Modifiers = new ModifierData[Data.ListLength];

            for (int x = 0; x < Data.ListLength; x++) 
                Data.Modifiers[x] = ReadModifierData(wSock);
            
            return Data;
        }

        public static void WritePropertyData(Wrapped wSock, PropertyData Data) {
            wSock.writeString(Data.Key);
            wSock.writeDouble(Data.Value);
            wSock.writeShort(Data.ListLength);
            
            for (int x = 0; x < Data.ListLength; x++)
                WriteModifierData(wSock, Data.Modifiers[x]);
        }

        public static ModifierData ReadModifierData(Wrapped wSock) {
            var Data = new ModifierData();

            Data.UUID = wSock.readByteArray(16); // -- Because fuck Minecraft.
            Data.Amount = wSock.readDouble();
            Data.Operation = wSock.readByte();

            return Data;
        }

        public static void WriteModifierData(Wrapped wSock, ModifierData Data) {
            wSock.Send(Data.UUID);
            wSock.writeDouble(Data.Amount);
            wSock.writeByte(Data.Operation);
        }

        //public static decimal ReadDecimal(Wrapped wSock) {
        //    var Bytes = wSock.readByteArray(16);

        //    var i1 = BitConverter.ToInt32(Bytes, 0);
        //    var i2 = BitConverter.ToInt32(Bytes, 4);
        //    var i3 = BitConverter.ToInt32(Bytes, 8);
        //    var i4 = BitConverter.ToInt32(Bytes, 12);

        //    return new decimal(new int[] { i1, i2, i3, i4 });
        //}

        //public static void WriteDecimal(Wrapped wSock) {
            
        //}

        public static SlotData ReadSlot(Wrapped wSock) {
            var Data = new SlotData();
            Data.ID = wSock.readShort();

            if (Data.ID == -1) {
                Data.ID = 0;
                Data.ItemCount = 0;
                Data.ItemDamage = 0;
                return Data;
            }

            Data.ItemCount = wSock.readByte();
            Data.ItemDamage = wSock.readShort();
            var NBTLength = wSock.readShort();

            if (NBTLength == -1)
                return Data;

            Data.NbtData = wSock.readByteArray(NBTLength);
            return Data;
        }

        public static void WriteSlot(Wrapped wSock, SlotData Data) {
            if (Data.ID == -1) {
                wSock.writeShort(-1);
                return;
            }

            wSock.writeShort(Data.ID);
            wSock.writeByte(Data.ItemCount);
            wSock.writeShort(Data.ItemDamage);

            if (Data.NbtData == null) {
                wSock.writeShort(-1);
                return;
            }

            wSock.writeShort((short)Data.NbtData.Length);
            wSock.Send(Data.NbtData);
        }
    }
}
