var Asn1Decode = artifacts.require("Asn1Decode");
// var NodePtr = artifacts.require("NodePtr");

module.exports = function(deployer, network) {
  // I believe these are not needed since all the libraries are compiled into one because all their functions are declared as `internal`
  // In fact this library shouldn't even be deployed at all since it will be compiled into the contract that uses it
  // deployer.deploy(NodePtr);
  // deployer.link(NodePtr, Asn1Decode);

  deployer.deploy(Asn1Decode);
};
