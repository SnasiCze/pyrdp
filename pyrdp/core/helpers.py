#
# This file is part of the PyRDP project.
# Copyright (C) 2018 GoSecure Inc.
# Licensed under the GPLv3 or later.
#

"""
File that contains helper methods to use in the library.
"""
import logging
from logging import Logger
import re

def decodeUTF16LE(data: bytes) -> str:
    """
    Decode the provided bytes in UTF-16 in a way that does not crash when invalid input is provided.
    :param data: The data to decode as utf-16.
    :return: The python string
    """
    toRet = data.decode("utf-16le", errors="ignore")
    nameOfFile = re.search(r"[a-zA-Z0-9\s_\\.\-\(\):]*\.[a-zA-Z0-9]+",toRet)
    if nameOfFile :
        return(nameOfFile.group())
    return toRet


def encodeUTF16LE(string: str) -> bytes:
    """
    Encode the provided string in UTF-16 in a way that does not crash when invalid input is provided.
    :param string: The python string to encode to bytes
    :return: The raw bytes
    """
    return string.encode("utf-16le", errors="ignore")


def getLoggerPassFilters(loggerName: str) -> Logger:
    """
    Returns a logger instance where the filters of all the parent chain are applied to it.
    This is needed since Filters do NOT get inherited from parent logger to child logger.
    See: https://docs.python.org/3/library/logging.html#filter-objects
    """
    logger = logging.getLogger(loggerName)
    subLoggerNames = loggerName.split(".")
    filterList = []
    parentLoggerName = ""
    for subLoggerName in subLoggerNames:
        parentLoggerName += subLoggerName
        parentLogger = logging.getLogger(parentLoggerName)
        filterList += parentLogger.filters
        parentLoggerName += "."
    [logger.addFilter(parentFilter) for parentFilter in filterList]
    return logger
