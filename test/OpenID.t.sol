// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "forge-std/Vm.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import "../src/OpenID.sol";

contract OpenIDTest is Test {
    OpenID public openId_;
    address admin_;

    function setUp() public {
        vm.warp(1694682092);
        admin_ = vm.addr(0x100);
        vm.startPrank(admin_);
        OpenID openIdImpl = new OpenID();
        bytes memory data = abi.encodeCall(openIdImpl.initialize, ());
        openId_ = OpenID(address(new ERC1967Proxy(address(openIdImpl), data)));

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
        (
            bool succ,
            uint256 index,
            bytes32 issHash,
            bytes32 subHash,
            bytes32 nonceHash
        ) = openId_.validateIDToken(0, vm.envBytes("OPENID_VERIFY_DATA"));

        assert(succ);
    }
}
