// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../src/OpenIDZk.sol";
import "../src/libraries/LibBytes.sol";

contract TestOpenIDZk is OpenIDZk {
    using LibBytes for bytes;

    function setupSRSHashAndVKHashHelper(
        uint256 srshash_init,
        uint64 num_inputs,
        uint128 domain_size,
        bytes calldata vkDataBytes
    ) public {
        uint256[] memory vkData;
        (vkData, ) = vkDataBytes.mcReadUint256Array(0);
        setupSRSHashAndVKHash(srshash_init, num_inputs, domain_size, vkData);
    }
}
