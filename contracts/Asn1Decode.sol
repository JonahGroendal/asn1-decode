pragma solidity  ^0.4.23;

library NodePtr {
  function ixs(uint self) internal pure returns (uint) {
    return uint80(self);
  }
  function ixf(uint self) internal pure returns (uint) {
    return uint80(self>>80);
  }
  function ixl(uint self) internal pure returns (uint) {
    return uint80(self>>160);
  }
  function getPtr(uint _ixs, uint _ixf, uint _ixl) internal pure returns (uint) {
    _ixs |= _ixf<<80;
    _ixs |= _ixl<<160;
    return _ixs;
  }
}

library Asn1Decode {
  using NodePtr for uint;

  /*
   * First step in traversing an asn1 structure
   *
   * @param der The der-encoded asn1 structure
   * @return a NodePtr object pointing to the outermost node
   */
  function root(bytes der) public pure returns (uint) {
  	return asn1_read_length(der, 0);
  }

  /*
   * Get the next sibling node
   *
   * @param der The der-encoded asn1 structure
   * @param n The current node
   * @return a NodePtr object pointing to the next sibling node
   */
  function next(uint self, bytes der) public pure returns (uint) {
  	return asn1_read_length(der, self.ixl()+1);
  }

  /*
   * Get the first child node of the current node
   *
   * @param der The der-encoded asn1 structure
   * @param n The current node
   * @return a NodePtr object pointing to the next sibling node
   */
  function firstChild(uint self, bytes der) public pure returns (uint) {
    // Can only open constructed types
  	require(der[self.ixs()] & 0x20 == 0x20);
  	return asn1_read_length(der, self.ixf());
  }

  /*
   * Returs true if j is child of i or if i is child of j. Used for looping
   * through children of a given node (either i or j).
   *
   * @param i Pointer to an asn1 node
   * @param j Pointer to another asn1 node of the same asn1 structure
   * @return weather i or j is the direct child of the other.
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
  function traverse(bytes der, bytes location) public pure returns (uint) {
    uint node;
    uint8 j;
    uint8 k;

    node = root(der);
    for (j=0; j<location.length; j++) {
      if (j % 2 == 0) {
        for (k=0; k<uint8(location[j]); k++) {
          node = next(node, der);
        }
      } else {
        for (k=0; k<uint8(location[j]); k++) {
          node = firstChild(node, der);
        }
      }
    }

    return node;
  }

  // Get the value of the node
  function getValue(uint self, bytes der) public pure returns (bytes) {
    uint valueLength = self.ixl() + 1 - self.ixf();
    bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[self.ixf() + i];
    }
  	return ret;
  }

  // Get the entire node
  function getAll(uint self, bytes der) public pure returns (bytes) {
    uint valueLength = self.ixl() + 1 - self.ixs();
    bytes memory ret = new bytes(valueLength);                 // currently there cannot be dynamic arrays in memory. This will need to be changed next protocol update
    for (uint i=0; i<valueLength; i++) {
      ret[i] = der[self.ixs() + i];
    }
  	return ret;
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

  // helper func
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
