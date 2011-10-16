using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Decaptcher
{
    public enum PictureType
    {
        Unspecified = 0,
        Asirra = 86,
        Unknown
    }

    public class APIConstants
    {
        public const int ccERR_OK = 0; // everything went OK
        public const int ccERR_GENERAL = -1; // general internal error
        public const int ccERR_STATUS = -2; // status is not correct
        public const int ccERR_NET_ERROR = -3; // network data transfer error
        public const int ccERR_TEXT_SIZE = -4; // text is not of an appropriate size
        public const int ccERR_OVERLOAD = -5; // server's overloaded
        public const int ccERR_BALANCE = -6; // not enough funds to complete the request
        public const int ccERR_TIMEOUT = -7; // requiest timed out
        public const int ccERR_UNKNOWN = -200; // unknown error

        // picture processing TIMEOUTS
        public const int ptoDEFAULT = 0; // default timeout, server-specific
        public const int ptoLONG = 1; // long timeout for picture, server-specfic
        public const int pto30SEC = 2; // 30 seconds timeout for picture
        public const int pto60SEC = 3; // 60 seconds timeout for picture
        public const int pto90SEC = 4; // 90 seconds timeout for picture

        // picture processing TYPES
        public const int ptUNSPECIFIED = 0; // picture type unspecified
    }

    class CCProtoPacket
    {
        public const int CC_PROTO_VER = 1;  // protocol version
        public const int CC_RAND_SIZE = 256; // size of the random sequence for authentication procedure
        public const int CC_MAX_TEXT_SIZE = 100; // maximum characters in returned text for picture
        public const int CC_MAX_LOGIN_SIZE = 100; // maximum characters in login string
        public const int CC_MAX_PICTURE_SIZE = 200000; // 200 K bytes for picture seems sufficient for all purposes
        public const int CC_HASH_SIZE = 32;  //

        public const int cmdCC_UNUSED = 0;
        public const int cmdCC_LOGIN = 1;  // login
        public const int cmdCC_BYE = 2;  // end of session
        public const int cmdCC_RAND = 3;  // random data for making hash with login+password
        public const int cmdCC_HASH = 4;  // hash data
        public const int cmdCC_PICTURE = 5;  // picture data, deprecated
        public const int cmdCC_TEXT = 6;  // text data, deprecated
        public const int cmdCC_OK = 7;  //
        public const int cmdCC_FAILED = 8;  //
        public const int cmdCC_OVERLOAD = 9;  //
        public const int cmdCC_BALANCE = 10;  // zero balance
        public const int cmdCC_TIMEOUT = 11;  // time out occured
        public const int cmdCC_PICTURE2 = 12;  // picture data
        public const int cmdCC_PICTUREFL = 13;  // picture failure
        public const int cmdCC_TEXT2 = 14;  // text data

        public const int SIZEOF_CC_PACKET = 6;
        public const int SIZEOF_CC_PICT_DESCR = 20;

        public int Version { get; set; }
        public int Command { get; set; }
        public int Size { get; set; }

        private byte[] _data = null;   // packet payload

        public CCProtoPacket()
        {
            Version = CC_PROTO_VER;
            Command = cmdCC_BYE;
        }

        private bool CheckHeader(int command, int size)
        {
            if (Version != CC_PROTO_VER)
                return false;
            if ((command != -1) && (Command != command))
                return false;
            if ((size != -1) && (Size != size))
                return false;

            return true;
        }

        public bool PackTo(Stream oos)
        {
            try
            {
                var writer = new BinaryWriter(oos);
                writer.Write((byte)Version);
                writer.Write((byte)Command);
                writer.Write(Size);
                if (_data != null)
                {
                    if (_data.Length > 0)
                    {
                        oos.Write(_data, 0, _data.Length);
                    }
                }

                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        private bool UnpackHeader(Stream ios)
        {
            try
            {
                var reader = new BinaryReader(ios);
                Version = (int)reader.ReadByte();
                Command = (int)reader.ReadByte();
                Size = reader.ReadInt32();

                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }

        public static byte[] ReadFully(Stream input, int bytesToRead)
        {
            byte[] data = new byte[bytesToRead];
            int offset = 0;
            int remaining = data.Length;
            while (remaining > 0)
            {
                int read = input.Read(data, offset, remaining);
                remaining -= read;
                offset += read;
            }
            return data;
        }

        /**
         *
         */
        public bool UnpackFrom(Stream dis, int cmd, int size)
        {
            UnpackHeader(dis);

            if (CheckHeader(cmd, size) == false)
                return false;

            try
            {
                if (Size > 0)
                {
                    // check error
                    _data = new byte[Size];
                    _data = ReadFully(dis, Size);
                }
                else
                {
                    _data = null;
                }
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }


        public int calcSize()
        {
            if (_data != null)
            {
                Size = _data.Length;
            }
            else
            {
                Size = 0;
            }
            return Size;
        }

        int getFullSize()
        {
            return SIZEOF_CC_PACKET + Size;
        }

        public void setData(byte[] data)
        {
            _data = data;
        }

        public byte[] getData()
        {
            return _data;
        }
    }


    class CCPictDescr
    {
        private int _timeout = APIConstants.ptoDEFAULT;
        private int _type = APIConstants.ptUNSPECIFIED;
        private int _size = 0;
        private int _major_id = 0;
        private int _minor_id = 0;
        private byte[] _data = null;

        public byte[] pack()
        {

            int data_length = _data == null ? 0 : _data.Length;
            byte[] res = new byte[4 * 5 + data_length];
            int i = 0;
            int j = 0;
            int value = 0;

            value = _timeout;
            res[i++] = (byte)((value >> 0) & 0xff);
            res[i++] = (byte)((value >> 8) & 0xff);
            res[i++] = (byte)((value >> 16) & 0xff);
            res[i++] = (byte)((value >> 24) & 0xff);

            value = _type;
            res[i++] = (byte)((value >> 0) & 0xff);
            res[i++] = (byte)((value >> 8) & 0xff);
            res[i++] = (byte)((value >> 16) & 0xff);
            res[i++] = (byte)((value >> 24) & 0xff);

            value = _size;
            res[i++] = (byte)((value >> 0) & 0xff);
            res[i++] = (byte)((value >> 8) & 0xff);
            res[i++] = (byte)((value >> 16) & 0xff);
            res[i++] = (byte)((value >> 24) & 0xff);

            value = _major_id;
            res[i++] = (byte)((value >> 0) & 0xff);
            res[i++] = (byte)((value >> 8) & 0xff);
            res[i++] = (byte)((value >> 16) & 0xff);
            res[i++] = (byte)((value >> 24) & 0xff);

            value = _minor_id;
            res[i++] = (byte)((value >> 0) & 0xff);
            res[i++] = (byte)((value >> 8) & 0xff);
            res[i++] = (byte)((value >> 16) & 0xff);
            res[i++] = (byte)((value >> 24) & 0xff);

            if (_data != null)
            {
                for (j = 0; j < _data.Length; j++)
                {
                    res[i++] = _data[j];
                }
            }

            return res;
        }


        public void unpack(byte[] bin)
        {
            int i = 0;
            int j = 0;

            if (bin.Length < CCProtoPacket.SIZEOF_CC_PICT_DESCR)
            {
                return;
            }
            _timeout = (bin[0] << 0) | (bin[1] << 8) | (bin[2] << 16) | (bin[3] << 24);
            _type = (bin[4] << 0) | (bin[5] << 8) | (bin[6] << 16) | (bin[7] << 24);
            _size = (bin[8] << 0) | (bin[9] << 8) | (bin[10] << 16) | (bin[11] << 24);
            _major_id = (bin[12] << 0) | (bin[13] << 8) | (bin[14] << 16) | (bin[15] << 24);
            _minor_id = (bin[16] << 0) | (bin[17] << 8) | (bin[18] << 16) | (bin[19] << 24);

            _data = null;

            // we have some additional data
            if (bin.Length > CCProtoPacket.SIZEOF_CC_PICT_DESCR)
            {
                _data = new byte[bin.Length - CCProtoPacket.SIZEOF_CC_PICT_DESCR];
                for (i = CCProtoPacket.SIZEOF_CC_PICT_DESCR, j = 0; i < bin.Length; i++, j++)
                {
                    _data[j] = bin[i];
                }
            }
        }

        public void setTimeout(int to)
        {
            _timeout = to;
        }

        public int getTimeout()
        {
            return _timeout;
        }

        public void setType(int type)
        {
            _type = type;
        }

        public int getType()
        {
            return _type;
        }

        public void setSize(int size)
        {
            _size = size;
        }

        public int getSize()
        {
            return _size;
        }

        public int calcSize()
        {
            if (_data == null)
            {
                _size = 0;
            }
            else
            {
                _size = _data.Length;
            }
            return _size;
        }

        public int getFullSize()
        {
            return CCProtoPacket.SIZEOF_CC_PICT_DESCR + _size;
        }

        public void setMajorID(int major_id)
        {
            _major_id = major_id;
        }

        public int getMajorID()
        {
            return _major_id;
        }

        public void setMinorID(int minor_id)
        {
            _minor_id = minor_id;
        }

        public int getMinorID()
        {
            return _minor_id;
        }

        public void setData(byte[] data)
        {
            _data = data;
        }

        public byte[] getData()
        {
            return _data;
        }
    }

    public class BalanceResult
    {
        public int ReturnCode { get; private set; }
        public string Balance { get; private set; }

        public BalanceResult(int returnCode)
            : this(returnCode, string.Empty)
        {
        }

        public BalanceResult(int returnCode, string balance)
        {
            ReturnCode = returnCode;
            Balance = balance;
        }
    }

    public class CCProto
    {
        public const int sCCC_INIT = 1;  // initial status, ready to issue LOGIN on client
        public const int sCCC_LOGIN = 2;  // LOGIN is sent, waiting for RAND (login accepted) or CLOSE CONNECTION (login is unknown) 
        public const int sCCC_HASH = 3;  // HASH is sent, server may CLOSE CONNECTION (hash is not recognized)
        public const int sCCC_PICTURE = 4;

        private int _status = sCCC_INIT;
        private TcpClient _client;
        private NetworkStream _stream;


        /**
         *
         */
        public int Login(string hostname, int port, string username, string password)
        {
            CCProtoPacket pack = null;
            var md5 = MD5.Create();
            var sha = SHA256.Create();

            int i = 0;
            int j = 0;

            _status = sCCC_INIT;

            try
            {
                _client = new TcpClient(hostname, port);
                _stream = _client.GetStream();
            }
            catch (Exception e)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            pack = new CCProtoPacket();

            pack.Command = CCProtoPacket.cmdCC_LOGIN;
            pack.Size = username.Length;
            pack.setData(Encoding.ASCII.GetBytes(username));

            if (pack.PackTo(_stream) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            if (pack.UnpackFrom(_stream, CCProtoPacket.cmdCC_RAND, CCProtoPacket.CC_RAND_SIZE) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            byte[] md5bin = md5.ComputeHash(Encoding.ASCII.GetBytes(password));
            String md5str = "";
            char[] cvt = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
            for (i = 0; i < md5bin.Length; i++)
            {
                md5str += cvt[(md5bin[i] & 0xF0) >> 4];
                md5str += cvt[md5bin[i] & 0x0F];
            }

            byte[] shabuf = new byte[pack.getData().Length + md5str.Length + username.Length];
            j = 0;
            for (i = 0; i < pack.getData().Length; i++, j++)
            {
                shabuf[j] = pack.getData()[i];
            }
            for (i = 0; i < Encoding.ASCII.GetBytes(md5str).Length; i++, j++)
            {
                shabuf[j] = Encoding.ASCII.GetBytes(md5str)[i];
            }
            for (i = 0; i < Encoding.ASCII.GetBytes(username).Length; i++, j++)
            {
                shabuf[j] = Encoding.ASCII.GetBytes(username)[i];
            }

            pack = new CCProtoPacket();
            pack.Command = CCProtoPacket.cmdCC_HASH;
            pack.Size = CCProtoPacket.CC_HASH_SIZE;
            pack.setData(sha.ComputeHash(shabuf));

            if (pack.PackTo(_stream) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            if (pack.UnpackFrom(_stream, CCProtoPacket.cmdCC_OK, 0) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            _status = sCCC_PICTURE;

            return APIConstants.ccERR_OK;
        } // login()

        public class PictureResult
        {
            public readonly int timeReallyUsed;
            public readonly int typeReallyUsed;
            public readonly String text;
            public readonly int majorId;
            public readonly int minorId;
            public readonly int returnCode;

            public PictureResult(int time, int type, String text, int major, int minor, int returnCode)
            {
                this.timeReallyUsed = time;
                this.typeReallyUsed = type;
                this.text = text;
                this.majorId = (null == major) ? 0 : major;
                this.minorId = (null == minor) ? 0 : minor;
                this.returnCode = returnCode;
            }
        }

        /**
         * Receive back a result object that includes all the details in a format trivial to use
         * in other Java code, while passing only and exactly what's needed.
         * 
         * This is a simple wrapper to picture2 and does no logic of its own.
         * 
         * @param pict The bytes of the picture to solve
         * @param timeout How long the solution should take at most
         * @param type 
         * @return
         */
        public PictureResult picture2(byte[] pict, int timeout, int type)
        {
            int[] to_wrapper = new int[] { timeout };
            int[] type_wrapper = new int[] { type };
            int[] major_wrapper = new int[1];
            int[] minor_wrapper = new int[1];
            String[] text_wrapper = new String[] { "" };

            int result = picture2(pict, to_wrapper, type_wrapper, text_wrapper, major_wrapper, minor_wrapper);
            return new PictureResult(to_wrapper[0], type_wrapper[0], text_wrapper[0], major_wrapper[0], minor_wrapper[0], result);
        }

        /**
         * say "thanks" to Java incapability to pass values by reference in order to use them as multiple returns
         * all arrays[] are used as workarond to get values out of the function, really 
         * 
         */
        public int picture2(
         byte[] pict,   // IN  picture binary data
         int[] pict_to,   // IN/OUT timeout specifier to be used, on return - really used specifier, see ptoXXX constants, ptoDEFAULT in case of unrecognizable
         int[] pict_type,   // IN/OUT type specifier to be used, on return - really used specifier, see ptXXX constants, ptUNSPECIFIED in case of unrecognizable
         String[] text,   // OUT text
         int[] major_id,  // OUT OPTIONAL major part of the picture ID
         int[] minor_id  // OUT OPTIONAL minor part of the picture ID
        )
        {

            if (_status != sCCC_PICTURE)
                return APIConstants.ccERR_STATUS;

            CCProtoPacket pack = new CCProtoPacket();
            pack.Command = CCProtoPacket.cmdCC_PICTURE2;


            CCPictDescr desc = new CCPictDescr();
            desc.setTimeout(pict_to[0]);
            desc.setType(pict_type[0]);
            desc.setMajorID(0);
            desc.setMinorID(0);
            desc.setData(pict);
            desc.calcSize();

            pack.setData(desc.pack());
            pack.calcSize();

            if (pack.PackTo(_stream) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            if (pack.UnpackFrom(_stream, -1, -1) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            switch (pack.Command)
            {
                case CCProtoPacket.cmdCC_TEXT2:
                    desc.unpack(pack.getData());
                    pict_to[0] = desc.getTimeout();
                    pict_type[0] = desc.getType();
                    text[0] = desc.getData() == null ? "" : Encoding.ASCII.GetString(desc.getData());

                    if (major_id != null)
                        major_id[0] = desc.getMajorID();
                    if (minor_id != null)
                        minor_id[0] = desc.getMinorID();

                    return APIConstants.ccERR_OK;

                case CCProtoPacket.cmdCC_BALANCE:
                    // balance depleted
                    return APIConstants.ccERR_BALANCE;

                case CCProtoPacket.cmdCC_OVERLOAD:
                    // server's busy
                    return APIConstants.ccERR_OVERLOAD;

                case CCProtoPacket.cmdCC_TIMEOUT:
                    // picture timed out
                    return APIConstants.ccERR_TIMEOUT;

                case CCProtoPacket.cmdCC_FAILED:
                    // server's error
                    return APIConstants.ccERR_GENERAL;

                default:
                    // unknown error
                    return APIConstants.ccERR_UNKNOWN;
            }
        } // picture2()


        public int picture_bad2(int major_id, int minor_id)
        {
            CCProtoPacket pack = new CCProtoPacket();

            pack.Command = CCProtoPacket.cmdCC_PICTUREFL;

            CCPictDescr desc = new CCPictDescr();
            desc.setTimeout(APIConstants.ptoDEFAULT);
            desc.setType(APIConstants.ptUNSPECIFIED);
            desc.setMajorID(major_id);
            desc.setMinorID(minor_id);
            desc.calcSize();

            pack.setData(desc.pack());
            pack.calcSize();

            if (pack.PackTo(_stream) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            return APIConstants.ccERR_NET_ERROR;
        } // picture_bad2()

        public BalanceResult GetBalance()
        {
            CCProtoPacket pack = null;

            if (_status != sCCC_PICTURE)
            {
                return new BalanceResult(APIConstants.ccERR_STATUS);
            }

            pack = new CCProtoPacket();
            pack.Command = CCProtoPacket.cmdCC_BALANCE;
            pack.Size = 0;

            if (pack.PackTo(_stream) == false)
            {
                return new BalanceResult(APIConstants.ccERR_NET_ERROR);
            }

            if (pack.UnpackFrom(_stream, -1, -1) == false)
            {
                return new BalanceResult(APIConstants.ccERR_NET_ERROR);
            }

            switch (pack.Command)
            {
                case CCProtoPacket.cmdCC_BALANCE:
                    return new BalanceResult(APIConstants.ccERR_OK, Encoding.ASCII.GetString(pack.getData()));
                default:
                    return new BalanceResult(APIConstants.ccERR_UNKNOWN);
            }
        }

        public int close()
        {
            CCProtoPacket pack = new CCProtoPacket();

            pack.Command = CCProtoPacket.cmdCC_BYE;
            pack.Size = 0;

            if (pack.PackTo(_stream) == false)
            {
                return APIConstants.ccERR_NET_ERROR;
            }

            try
            {
                _client.Close();
            }
            catch (Exception e) { }
            _status = sCCC_INIT;

            return APIConstants.ccERR_NET_ERROR;
        } // close()
    }
}
