// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import "forge-std/console2.sol";

import "../src/OpenID.sol";

contract OpenIDTest is Test {
    OpenID public openId_;
    address admin_;

    function setUp() public {
        vm.warp(vm.envUint("TIMESTAMP"));
        admin_ = vm.addr(0x100);
        vm.startPrank(admin_);
        openId_ = new OpenID();

        openId_.updateOpenIDPublicKey(
            keccak256(
                abi.encodePacked(
                    vm.envString("OPENID_ISSUER"),
                    vm.envString("OPENID_KID")
                )
            ),
            vm.envBytes("OPENID_PUB_KEY")
        );
        openId_.addOpenIDAudience(
            keccak256(
                abi.encodePacked(
                    vm.envString("OPENID_ISSUER"),
                    vm.envString("OPENID_AUDIENCE")
                )
            )
        );

        vm.stopPrank();
    }

    function testValidate() public {
        emit log_uint(block.timestamp);
        // (bool succ, , , , ) = openId_.validateIDToken(
        //     0,
        //     vm.envBytes("OPENID_VERIFY_DATA")
        // );
        bytes memory data = abi.encodeWithSelector(
            bytes4(keccak256("validateIDToken(uint256,bytes)")),
            uint256(0),
            vm.envBytes("OPENID_VERIFY_DATA")
        );

        (bool success, bytes memory res) = address(openId_).call(data);
        require(success);
        (bool succ, , bytes32 issHash, bytes32 subHash, bytes32 nonceHash) = abi
            .decode(res, (bool, uint256, bytes32, bytes32, bytes32));

        console2.logBytes32(subHash);
        assert(succ);
    }
}
