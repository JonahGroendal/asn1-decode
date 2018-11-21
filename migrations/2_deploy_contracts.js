var Asn1Decode = artifacts.require("Asn1Decode");
var NodePtr = artifacts.require("NodePtr");

module.exports = function(deployer, network) {
  deployer.deploy(NodePtr);
  deployer.link(NodePtr, Asn1Decode);
  deployer.deploy(Asn1Decode);
};
