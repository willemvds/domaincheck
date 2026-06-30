from enum import Enum
from typing import Final

UTF8: Final[str] = "utf-8"


class DecodeErrors(str, Enum):
    STRICT = "strict"
    IGNORE = "ignore"
    REPLACE = "replace"
    XML_CHARREF_REPLACE = "xmlcharrefreplace"
    BACKSLASH_REPLACE = "backslashreplace"


#'strict' (default): Raises a UnicodeDecodeError if an encoding error occurs.
#'ignore': Ignores un-decodable characters.
#'replace': Replaces un-decodable characters with a replacement character (e.g., ).
#'xmlcharrefreplace': Replaces un-decodable characters with XML character references.
#'backslashreplace'
