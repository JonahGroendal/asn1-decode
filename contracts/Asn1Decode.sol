pragma solidity  ^0.4.23;

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

  /*
   * @dev Get the root node. First step in traversing an asn1 structure
   * @param der The der-encoded asn1 structure
   * @return a NodePtr object pointing to the outermost node
   */
  function root(bytes der) public pure returns (uint) {
  	return asn1_read_length(der, 0);
  }

  /*
   * @dev Get the next sibling node
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return a NodePtr object pointing to the next sibling node
   */
  function nextSiblingOf(bytes der, uint ptr) public pure returns (uint) {
  	return asn1_read_length(der, ptr.ixl()+1);
  }

  /*
   * @dev Get the first child node of the current node
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return a NodePtr object pointing to the first child node
   */
  function firstChildOf(bytes der, uint ptr) public pure returns (uint) {
    // Can only open constructed types
  	require(der[ptr.ixs()] & 0x20 == 0x20);
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
  function isChildOf(uint i/*aka self*/, uint j) public pure returns (bool) {
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
   bytes constant public COMMON_NAME = "\x55\x04\x03";
   // shortcuts to commonly used X509 nodes
   bytes constant public LOCATION_SERIAL_NUMBER = '\x00\x02\x01';
   bytes constant public LOCATION_VALID_NOT_BEFORE = '\x00\x02\x04\x01';
   bytes constant public LOCATION_VALID_NOT_AFTER = '\x00\x02\x04\x01\x01';
   bytes constant public LOCATION_PUB_KEY = '\x00\x02\x06';
  function traverseTo(bytes der, bytes location) public pure returns (uint) {
    uint ptr;
    uint8 j;
    uint8 k;

    ptr = root(der);
    for (j=0; j<location.length; j++) {
      if (j % 2 == 0) {
        for (k=0; k<uint8(location[j]); k++) {
          ptr = nextSiblingOf(der, ptr);
        }
      } else {
        for (k=0; k<uint8(location[j]); k++) {
          ptr = firstChildOf(der, ptr);
        }
      }
    }
    return ptr;
  }

  /*
   * @dev Extract value of node from der-encoded structure
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return value bytes of node
   */
  function bytesAt(bytes der, uint ptr) public pure returns (bytes) {
    uint valueLength = ptr.ixl() + 1 - ptr.ixf();
    bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[ptr.ixf() + i];
    }
  	return ret;
  }

  /*
   * @dev Extract node from der-encoded structure
   * @param der The der-encoded asn1 structure
   * @param ptr Points to the indices of the current node
   * @return bytes of node
   */
  function allBytesAt(bytes der, uint ptr) public pure returns (bytes) {
    uint valueLength = ptr.ixl() + 1 - ptr.ixs();
    bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[ptr.ixs() + i];
    }
  	return ret;
  }

  function uintAt(bytes der, uint ptr) public pure returns (uint) {
    return decodeUint(bytesAt(der, ptr));
  }

  function decodeBitstring(bytes bitstr) public pure returns (bytes) {
    // Only 00 padded bitstr can be converted to bytestr!
  	require(bitstr[0] == 0x00);
  	bytes memory ret = new bytes(bitstr.length-1);
    for (uint i=0; i<ret.length; i++) {
      ret[i] = bitstr[i+1];
    }
  	return ret;
  }

  // Might need to be looked at / tested thoroughly
  function decodeUint(bytes encodedUint) public pure returns (uint) {
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
