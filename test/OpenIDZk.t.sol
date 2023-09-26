// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "./TestOpenIDZk.sol";

contract OpenIDZkTest is Test {
    TestOpenIDZk public openId_;
    address admin_;

    function setUp() public {
        vm.warp(vm.envUint("TIMESTAMP"));
        admin_ = vm.addr(0x100);
        vm.startPrank(admin_);
        OpenIDZk openIdImpl = new TestOpenIDZk();
        bytes memory data = abi.encodeCall(openIdImpl.initialize, ());
        openId_ = TestOpenIDZk(
            address(new ERC1967Proxy(address(openIdImpl), data))
        );

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
