pragma solidity  ^0.4.23;

import "@ensdomains/dnssec-oracle/contracts/BytesUtils.sol";

library NodePtr {
  // Unpack first byte index
  function ixs(uint self) internal pure returns (uint) {
    return uint80(self);
  }
  // Unpack first content byte index
  function ixf(uint self) internal pure returns (uint) {
    return uint80(self>>80);
  }
  // Unpack last content byte index
  function ixl(uint self) internal pure returns (uint) {
    return uint80(self>>160);
  }
  // Pack 3 uint80s into a uint256
  function getPtr(uint _ixs, uint _ixf, uint _ixl) internal pure returns (uint) {
    _ixs |= _ixf<<80;
    _ixs |= _ixl<<160;
    return _ixs;
  }
}

library Asn1Decode {
  using NodePtr for uint;
  using BytesUtils for bytes;

  /*
   * @dev Get the root node. First step in traversing an asn1 structure
   * @param der The der-encoded asn1 structure
   * @return a NodePtr object pointing to the outermost node
   */
  function root(bytes der) internal pure returns (uint) {
  	return asn1_read_length(der, 0);
  }

  function rootOfBitstringAt(bytes der, uint ptr) internal pure returns (uint) {
    require(der[ptr.ixs()] == 0x03, "Not type BIT STRING");
    return asn1_read_length(der, ptr.ixf()+1);
  }

  /*
   * @dev Get the next sibling node
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return a NodePtr object pointing to the next sibling node
   */
  function nextSiblingOf(bytes der, uint ptr) internal pure returns (uint) {
  	return asn1_read_length(der, ptr.ixl()+1);
  }

  /*
   * @dev Get the first child node of the current node
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return a NodePtr object pointing to the first child node
   */
  function firstChildOf(bytes der, uint ptr) internal pure returns (uint) {
  	require(der[ptr.ixs()] & 0x20 == 0x20, "Not a constructed type");
  	return asn1_read_length(der, ptr.ixf());
  }

  /*
   * @dev Returns true if j is child of i or if i is child of j. Used for looping
   * through children of a given node (either i or j).
   *
   * @param i Pointer to an asn1 node
   * @param j Pointer to another asn1 node of the same asn1 structure
   * @return Whether i or j is the direct child of the other.
   */
  function isChildOf(uint i, uint j) internal pure returns (bool) {
  	return ( ((i.ixf() <= j.ixs()) && (j.ixl() <= i.ixl())) ||
             ((j.ixf() <= i.ixs()) && (i.ixl() <= j.ixl())) );
  }
  /*
   * @dev Traverses a der-encoded chunk of bytes by repeatedly using next() and
   * firstChild() in an alternating fashion.
   *
   * @param der The der-encoded asn1 structure to traverse
   * @param location The encoded traversal instructions
   *    - every even-index byte performes a next() operation a number of
          times equal to its value
   *    - every odd-index byte performs a firstChild() operation a number of
          times equal to its value
   *    ex: \x00\x02\x01 performs root() then  (0 x next()) then
          (2 x firstChild()) then (1 x next())
   *
   *  @return a NodePtr struct pointing to the index of the node traversed to
   */
   /* bytes constant internal COMMON_NAME = "\x55\x04\x03";
   // shortcuts to commonly used X509 nodes
   bytes constant internal LOCATION_SERIAL_NUMBER = '\x00\x02\x01';
   bytes constant internal LOCATION_VALID_NOT_BEFORE = '\x00\x02\x04\x01';
   bytes constant internal LOCATION_VALID_NOT_AFTER = '\x00\x02\x04\x01\x01';
   bytes constant internal LOCATION_PUB_KEY = '\x00\x02\x06';
  function traverseTo(bytes der, bytes32 location)
  internal pure returns (uint)
  {
    uint8 j;
    uint8 k;
    uint8 stop;
    uint ptr = root(der);
    for (j=0; j<32; j++) {
      if (location[j] == 0x00) {
        if (j != 32 && location[j+1] == 0x00) break;
      } else {
        if (j % 2 == 0) {
          for (k=0; k<uint8(location[j]); k++) {
            ptr = nextSiblingOf(der, ptr);
            stop = 0;
          }
        } else {
          for (k=0; k<uint8(location[j]); k++) {
            ptr = firstChildOf(der, ptr);
          }
        }
      }
    }
    return ptr;
  } */

  /*
   * @dev Extract value of node from der-encoded structure
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return value bytes of node
   */
  function bytesAt(bytes der, uint ptr) internal pure returns (bytes) {
    return der.substring(ptr.ixf(), ptr.ixl() + 1 - ptr.ixf());
    /* bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[ptr.ixf() + i];
    }
  	return ret; */
  }

  /*
   * @dev Extract node from der-encoded structure
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return bytes of node
   */
  function allBytesAt(bytes der, uint ptr) internal pure returns (bytes) {
    return der.substring(ptr.ixs(), ptr.ixl() + 1 - ptr.ixs());
    /* bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[ptr.ixs() + i];
    }
  	return ret; */
  }

  function bytes32At(bytes der, uint ptr) internal pure returns (bytes32) {
    return der.readBytesN(ptr.ixf(), ptr.ixl() + 1 - ptr.ixf());
  }

  function uintAt(bytes der, uint ptr) internal pure returns (uint) {
    require(der[ptr.ixs()] == 0x02, "Not type INTEGER");
    require(der[ptr.ixf()] & 0x80 == 0, "Not positive");
    return decodeUint(bytesAt(der, ptr));
  }

  function uintBytesAt(bytes der, uint ptr) internal pure returns (bytes) {
    require(der[ptr.ixs()] == 0x02, "Not type INTEGER");
    require(der[ptr.ixf()] & 0x80 == 0, "Not positive");
    uint valueLength = ptr.ixl() + 1 - ptr.ixf();
    if (der[ptr.ixf()] == 0)
      return der.substring(ptr.ixf()+1, valueLength-1);
    else
      return der.substring(ptr.ixf(), valueLength);
  }

  function keccakOfBytesAt(bytes der, uint ptr) internal pure returns (bytes32) {
    return der.keccak(ptr.ixf(), ptr.ixl() + 1 - ptr.ixf());
  }

  function keccakOfAllBytesAt(bytes der, uint ptr) internal pure returns (bytes32) {
    return der.keccak(ptr.ixs(), ptr.ixl() + 1 - ptr.ixs());
  }

  /* function decodeBitstring(bytes bitstr) internal pure returns (bytes) {
    // Only 00 padded bitstr can be converted to bytestr!
  	require(bitstr[0] == 0x00);
  	bytes memory ret = new bytes(bitstr.length-1);
    for (uint i=0; i<ret.length; i++) {
      ret[i] = bitstr[i+1];
    }
  	return ret;
  } */

  function bitstringAt(bytes der, uint ptr) internal pure returns (bytes) {
    require(der[ptr.ixs()] == 0x03, "Not type BIT STRING");
    // Only 00 padded bitstr can be converted to bytestr!
    require(der[ptr.ixf()] == 0x00);
    uint valueLength = ptr.ixl() + 1 - ptr.ixf();
    return der.substring(ptr.ixf()+1, valueLength-1);
  }

  /* function decodeBitstring(bytes bitstr) internal pure returns (bytes) {
    return bitstr.substring(1, bitstr.length-1);
  } */

  // Might need to be looked at / tested thoroughly
  function decodeUint(bytes encodedUint) internal pure returns (uint) {
    uint i = 0;
    for (uint8 j=0; j<encodedUint.length; j++) {
      i <<= 8;
  	i |= uint(encodedUint[j]);
    }
  	return i;
  }

  function asn1_read_length(bytes der, uint ix) private pure returns (uint) {
  	uint first = uint(der[ix+1]);
    uint length;
    uint ix_first_content_byte;
    uint ix_last_content_byte;
  	if ((der[ix+1] & 0x80) == 0) {
  		length = first;
  		ix_first_content_byte = ix+2;
  		ix_last_content_byte = ix_first_content_byte + length -1;
    } else {  // -------------------- not thoroughly tested!! ------------------
      uint lengthbytesLength = first & 0x7F;
      bytes memory lengthbytes = new bytes(lengthbytesLength);
      for (uint i=0; i<lengthbytesLength; i++) {
          lengthbytes[i] = der[ix+2 + i];
      }
  		length = decodeUint(lengthbytes);
  		ix_first_content_byte = ix+2+lengthbytesLength;
  		ix_last_content_byte = ix_first_content_byte + length -1;
    } // -----------------------------------------------------------------------
    return NodePtr.getPtr(ix, ix_first_content_byte, ix_last_content_byte);
  }
}
