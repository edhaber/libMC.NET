﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Newtonsoft.Json.Linq;

namespace libMC.NET.Packets.Play {
    public class chatMessage : Packet {

        public string rawMessage, parsedMessage, sender = "";

        public chatMessage(ref Minecraft mc) {
            rawMessage = mc.nh.wSock.readString();
            parsedMessage = parseJsonChat(rawMessage);

            mc.raiseMC(this, parsedMessage, sender);
        }

        string parseJsonChat(string raw) {
            bool bold = false, italic = false, underlined = false, strikethrough = false, obfs = false;
            string text = "", translate = "", color = "", name = "";//, final = "";
            //dynamic clickEvent, hoverEvent;

            dynamic jsonObj = JObject.Parse(raw);

            if (jsonObj.text != null) // -- Raw text, just let the clients parse it from here.
                return jsonObj.text;

            if (jsonObj.translate != null)
                translate = jsonObj.translate;

            if (jsonObj.bold != null)
                bold = jsonObj.bold;

            if (jsonObj.italic != null)
                italic = jsonObj.italic;

            if (jsonObj.underlined != null)
                underlined = jsonObj.underlined;

            if (jsonObj.strikethrough != null)
                strikethrough = jsonObj.strikethrough;

            if (jsonObj.obfuscated != null)
                obfs = jsonObj.obfuscated;

            if (jsonObj.color != null)
                color = jsonObj.color;

            switch (translate) {
                case "chat.type.text":
                    name = jsonObj.with[0].text;
                    sender = name;
                    text = jsonObj.with[1];
                    break;
                case "multiplayer.player.joined":
                    sender = jsonObj.with[0].text;
                    text = sender + " joined the game.";
                    break;
                case "multiplayer.player.left":
                    sender = jsonObj.with[0].text;
                    text = sender + " left the game.";
                    break;
                case "death.attack.player":
                    //name = jsonObj.with[0].text;
                    sender = jsonObj.with[2].text;
                    text = jsonObj.with[0].text + " killed by " + sender;
                    break;
                case "chat.type.admin":
                    break;
                case "chat.type.announcement":
                    name = "Server";
                    sender = name;
                    text = string.Join(" ", jsonObj.with[1].extra);
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
    }
}
