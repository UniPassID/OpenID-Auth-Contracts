// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";

import "./TestOpenIDZk.sol";

contract OpenIDZkTest is Test {
    TestOpenIDZk public openId_;
    address admin_;

    function setUp() public {
        vm.warp(vm.envUint("TIMESTAMP"));
        admin_ = vm.addr(0x100);
        vm.startPrank(admin_);
        openId_ = new TestOpenIDZk(admin_);

        openId_.setupSRSHashAndVKHashHelper(
            uint256(bytes32(vm.envBytes32("SRS_HASH"))),
            uint64(vm.envUint("NUM_INPUTS")),
            uint64(vm.envUint("DOMAIN_SIZE")),
            vm.envBytes("VK_DATA")
        );
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

    function testOpenIDZkValidate() public view {
        (bool succ, , , , ) = openId_.validateIDToken(
            0,
            vm.envBytes("OPENIDZK_VERIFY_DATA")
        );

        assert(succ);
    }
}
