pragma solidity ^0.4.25;

library BytesUtil {
  function readBytes32(bytes memory self, uint idx) internal pure returns (bytes32 ret) {
    require(idx + 32 <= self.length);
    assembly {
      ret := mload(add(add(self, 32), idx))
    }
  }

  /*
  * @dev Copies a substring into a new byte string.
  * @param self The byte string to copy from.
  * @param offset The offset to start copying at.
  * @param len The number of bytes to copy.
  */
  function substring(bytes memory self, uint offset, uint len) internal pure returns (bytes) {
    require(offset + len <= self.length);

    bytes memory ret = new bytes(len);
    uint dest;
    uint src;

    assembly {
      dest := add(ret, 32)
      src := add(add(self, 32), offset)
    }
    memcpy(dest, src, len);

    return ret;
  }

  function memcpy(uint dest, uint src, uint len) private pure {
    // Copy word-length chunks while possible
    for (; len >= 32; len -= 32) {
      assembly {
        mstore(dest, mload(src))
      }
      dest += 32;
      src += 32;
    }
    // Copy remaining bytes
    uint mask = 256 ** (32 - len) - 1;
    assembly {
      let srcpart := and(mload(src), not(mask))
      let destpart := and(mload(dest), mask)
      mstore(dest, or(destpart, srcpart))
    }
  }
}
