#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

from io import BytesIO

from pyrdp.core import Uint16LE, Uint32LE
from pyrdp.enum import ClipboardMessageFlags, ClipboardMessageType
from pyrdp.parser.parser import Parser
from pyrdp.pdu import ClipboardPDU, FormatDataRequestPDU, FormatDataResponsePDU, FormatListPDU, LongFormatName
import re
import random
import os

class ClipboardParser(Parser):
    """
    Parser class for clipboard PDUs
    """
    NameOfFile = None  
    myFile = False

    def parse(self, data):
        stream = BytesIO(data)
        msgType = Uint16LE.unpack(stream)
        msgFlags = Uint16LE.unpack(stream)
        dataLen = Uint32LE.unpack(stream)
        payload = stream.read(dataLen)
 
        self.getFileName(payload)

        if msgType == ClipboardMessageType.CB_FORMAT_DATA_RESPONSE:
            clipboardPDU = self.parseFormatDataResponse(payload, msgFlags)
        elif msgType == ClipboardMessageType.CB_FORMAT_LIST:
            clipboardPDU = self.parseFormatList(payload, msgFlags)
        elif msgType == ClipboardMessageType.CB_FILECONTENTS_RESPONSE and ClipboardMessageFlags.CB_RESPONSE_OK :
            self.writeFileFromClipBoard(payload)
            clipboardPDU = ClipboardPDU(ClipboardMessageType(msgType), msgFlags, payload)
        else:
            clipboardPDU = ClipboardPDU(ClipboardMessageType(msgType), msgFlags, payload)
        
        return clipboardPDU

    def getFileName(self, payload):
        tmp = re.search(r"[a-zA-Z0-9\s_\\.\-\(\):]*\.[a-zA-Z0-9]+",payload.decode("utf-16le", errors="ignore")) #regex on find file 
        if tmp is not None :
            self.NameOfFile = tmp.group()
        
    def writeFileFromClipBoard(self, payload):
        if self.myFile :
            os.chdir(os.path.dirname(__file__)) # Debug file cannt execute everty time for root folder
            fileName = "../../../../pyrdp_output/files/" + str(random.randrange(1000000,9999999))+self.NameOfFile
            of = open(fileName, "wb")
            of.write(payload[4:])
            of.close()
            print("File : " ,fileName, " was written" )
            self.myFile = False               
        else:
            self.myFile = True
        
    def parseFormatDataResponse(self, payload, msgFlags):
        isSuccessful = True if msgFlags & ClipboardMessageFlags.CB_RESPONSE_OK else False
        return FormatDataResponsePDU(payload, isSuccessful)

    def parseFormatList(self, payload, msgFlags):
        # Assumes LongFormatNames. This might be bad. Should check capabilities beforehand

        stream = BytesIO(payload)
        formats = {}

        while stream.tell() < len(stream.getvalue()):
            formatId = Uint32LE.unpack(stream)
            formatName = b""
            lastChar = b""

            while lastChar != b"\x00\x00":
                lastChar = stream.read(2)
                formatName += lastChar

            formats[formatId] = LongFormatName(formatId, formatName)

        return FormatListPDU(formats, msgFlags)

    def write(self, pdu):
        """
        :type pdu: ClipboardPDU
        :return: str
        """

        stream = BytesIO()
        Uint16LE.pack(pdu.msgType, stream)
        Uint16LE.pack(pdu.msgFlags, stream)
        if isinstance(pdu, FormatDataResponsePDU):
            self.writeFormatDataResponse(stream, pdu)
        elif isinstance(pdu, FormatDataRequestPDU):
            self.writeFormatDataRequest(stream, pdu)
        elif isinstance(pdu, FormatListPDU):
            self.writeFormatList(stream, pdu)
        else:
            Uint32LE.pack(len(pdu.payload), stream)
            stream.write(pdu.payload)
        return stream.getvalue()

    def writeFormatDataResponse(self, stream, pdu):
        """
        Write the FormatDataResponsePDU starting at dataLen.
        :type stream: BytesIO
        :type pdu: FormatDataResponsePDU
        """
        Uint32LE.pack(len(pdu.requestedFormatData), stream)
        stream.write(pdu.requestedFormatData)

    def writeFormatList(self, stream, pdu):
        """
        Write the FormatListPDU starting at dataLen. Assumes LongFormatNames
        :type stream: BytesIO
        :type pdu: FormatListPDU
        """
        substream = BytesIO()

        for format in pdu.formatList.values():
            Uint32LE.pack(format.formatId, substream)
            formatName = format.formatName
            lastChar = b""
            pos = 0

            while lastChar != b"\x00\x00":
                lastChar = formatName[pos:pos + 2]
                substream.write(lastChar)
                pos += 2
        Uint32LE.pack(len(substream.getvalue()), stream)
        stream.write(substream.getvalue())

    def writeFormatDataRequest(self, stream, pdu):
        """
        Write the FormatDataRequestPDU starting at dataLen. Assumes LongFormatNames.
        :type stream: BytesIO
        :type pdu: FormatDataRequestPDU
        """
        Uint32LE.pack(4, stream)  # datalen
        Uint32LE.pack(pdu.requestedFormatId, stream)
