// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "./PlonkCoreLib.sol";
import "./PlookupSingleCore.sol";

struct OpenIdPublicParams {
    bytes concat_hash;
    uint32 header_base64_len;
    uint32 payload_left_index;
    uint32 payload_base64_len;
    uint32 sub_left_index;
    uint32 sub_len;
}

contract UnipassVerifier is Plonk4SingleVerifierWithAccessToDNext {
    bytes32 openIdhash;

    // first register srshash
    function setupSRSHash(uint256 srshash_init) internal returns (bool) {
        srshash = bytes32(srshash_init);
        return true;
    }

    // then register vkdata
    function setupVKHash(
        uint64 num_inputs,
        uint128 domain_size,
        uint256[] memory vkdata
    ) internal returns (bool) {
        openIdhash = sha256(abi.encodePacked(num_inputs, domain_size, vkdata));
        return true;
    }

    function setBit(bytes1 a, uint8 n) public pure returns (bytes1) {
        return a | bytes1(uint8(2 ** (7 - n)));
    }

    function bitLocation(
        uint32 b_left_index,
        uint32 b_len,
        uint32 maxaLen,
        uint32 maxbLen
    ) public pure returns (bytes memory, bytes memory) {
        require(b_left_index < maxaLen * 8, "b_left_index is out of range");
        require(b_len <= maxbLen * 8, "b_len is too large");

        bytes memory bit_location_a = new bytes(maxaLen / 8);
        bytes memory bit_location_b = new bytes(maxbLen / 8);

        for (uint256 i = 0; i < b_len / 8; ++i) {
            bit_location_b[i] = bytes1(hex"ff");
        }
        for (uint256 i = 0; i < b_len % 8; ++i) {
            bit_location_b[b_len / 8] = setBit(
                bit_location_b[b_len / 8],
                uint8(i)
            );
        }

        uint256 start_bytes = b_left_index / 8;
        uint256 tmp_index = 8 - (b_left_index % 8);
        for (uint256 i = 0; i < tmp_index; ++i) {
            bit_location_a[start_bytes] = setBit(
                bit_location_a[start_bytes],
                uint8(7 - i)
            );
        }

        tmp_index = b_len - tmp_index;
        for (uint256 i = 0; i < tmp_index / 8; ++i) {
            bit_location_a[start_bytes + 1 + i] = bytes1(hex"ff");
        }

        for (uint256 i = 0; i < tmp_index % 8; ++i) {
            bit_location_a[start_bytes + 1 + tmp_index / 8] = setBit(
                bit_location_a[start_bytes + 1 + tmp_index / 8],
                uint8(i)
            );
        }
        return (bit_location_a, bit_location_b);
    }

    function sha256PaddingLen(uint256 input_len) public pure returns (uint256) {
        uint256 input_remainder = (input_len * 8) % 512;
        uint256 padding_count = 0;
        if (input_remainder < 448) {
            padding_count = (448 - input_remainder) / 8;
        } else {
            padding_count = (448 + 512 - input_remainder) / 8;
        }
        return input_len + padding_count + 8;
    }

    function checkPublicInputsOpenId(
        OpenIdPublicParams memory public_params,
        uint256[] memory public_inputs
    ) public pure returns (bool) {
        require(public_inputs.length == 1, "public inputs error");

        (
            bytes memory location_id_token_1,
            bytes memory location_payload_base64
        ) = bitLocation(
                public_params.payload_left_index,
                public_params.payload_base64_len - 1,
                2048,
                1536
            );

        (
            bytes memory location_id_token_2,
            bytes memory location_header_base64
        ) = bitLocation(0, public_params.header_base64_len - 1, 2048, 512);

        (
            bytes memory location_payload_raw,
            bytes memory location_sub
        ) = bitLocation(
                public_params.sub_left_index,
                public_params.sub_len,
                1152,
                192
            );

        bytes memory sha256_input = abi.encodePacked(
            public_params.concat_hash,
            location_id_token_1,
            location_payload_base64,
            location_id_token_2,
            location_header_base64,
            location_payload_raw,
            location_sub
        );

        bytes32 hash_result = sha256(sha256_input);

        hash_result =
            hash_result &
            bytes32(
                0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            );

        return hash_result == bytes32(public_inputs[0]);
    }

    function verifyOpenId(
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public view returns (bool) {
        bytes32 vkhash = sha256(
            abi.encodePacked(uint64(public_inputs.length), domain_size, vkdata)
        );

        require(openIdhash == vkhash, "E: wrong vkey");

        return
            verifyProof(
                vkhash,
                domain_size,
                vkdata,
                public_inputs,
                serialized_proof
            );
    }

    function verifyProof(
        bytes32 vkhash,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public view returns (bool) {
        VerificationKey memory vk;
        vk.domain_size = domain_size;
        vk.num_inputs = uint64(public_inputs.length);
        vk.omega = PairingsBn254.new_fr(vkdata[0]);

        {
            uint256 j = 1;
            for (uint256 i = 0; i < STATE_WIDTH + 2 + 2; ) {
                vk.selector_commitments[i] = PairingsBn254.new_g1_checked(
                    vkdata[j],
                    vkdata[j + 1]
                );
                j += 2;
                unchecked {
                    ++i;
                }
            }

            for (uint256 i = 0; i < STATE_WIDTH; ) {
                vk.permutation_commitments[i] = PairingsBn254.new_g1_checked(
                    vkdata[j],
                    vkdata[j + 1]
                );
                j += 2;
                unchecked {
                    ++i;
                }
            }

            for (uint256 i = 0; i < STATE_WIDTH + 1; ) {
                vk.tables_commitments[i] = PairingsBn254.new_g1_checked(
                    vkdata[j],
                    vkdata[j + 1]
                );
                j += 2;
                unchecked {
                    ++i;
                }
            }

            // q_substring q_substring_r
            for (uint256 i = 0; i < 2; ) {
                vk.selector_commitments[STATE_WIDTH + 2 + 2 + i] = PairingsBn254
                    .new_g1_checked(vkdata[j], vkdata[j + 1]);
                j += 2;
                unchecked {
                    ++i;
                }
            }

            uint256[2] memory tmpx;
            uint256[2] memory tmpy;

            tmpx[1] = vkdata[j];
            j += 1;
            tmpx[0] = vkdata[j];
            j += 1;
            tmpy[1] = vkdata[j];
            j += 1;
            tmpy[0] = vkdata[j];
            j += 1;
            vk.g2_x = PairingsBn254.new_g2(tmpx, tmpy);
        }
        Proof memory proof = deserialize_proof(public_inputs, serialized_proof);

        PartialVerifierState memory state;

        (bool res, PairingsBn254.Fr memory return_zeta_pow_n) = verify_initial(
            state,
            proof,
            vk,
            vkhash
        );
        if (res == false) {
            return false;
        }

        bool success = verify_commitments(return_zeta_pow_n, state, proof, vk);

        return success;
    }

    function deserialize_proof(
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) internal pure returns (Proof memory proof) {
        // require(serialized_proof.length == SERIALIZED_PROOF_LENGTH);
        uint256 inputs_len = public_inputs.length;
        proof.input_values = new uint256[](inputs_len);
        for (uint256 i = 0; i < inputs_len; ) {
            proof.input_values[i] = public_inputs[i];
            unchecked {
                ++i;
            }
        }

        //witness 0123...
        uint256 j = 0;
        for (uint256 i = 0; i < STATE_WIDTH; ) {
            proof.wire_commitments[i] = PairingsBn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j + 1]
            );
            j += 2;
            unchecked {
                ++i;
            }
        }
        //s
        proof.sorted_lookup_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //z
        proof.grand_product_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //zlookup
        proof.grand_product_lookup_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //z_substring
        proof.z_substring_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //t123...
        for (uint256 i = 0; i < STATE_WIDTH; ) {
            proof.quotient_poly_commitments[i] = PairingsBn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j + 1]
            );
            j += 2;
            unchecked {
                ++i;
            }
        }

        //t(z)
        proof.quotient_polynomial_at_z = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //r(z)
        proof.linearization_polynomial_at_z = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //`w_0(z)`, `w_1(z)`, `w_2(z)`...
        for (uint256 i = 0; i < STATE_WIDTH; ) {
            proof.wire_values_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
            unchecked {
                ++i;
            }
        }
        //`sigma_0(z)`, `sigma_1(z)`, `sigma_2(z)`...
        for (uint256 i = 0; i < STATE_WIDTH - 1; ) {
            proof.permutation_polynomials_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
            unchecked {
                ++i;
            }
        }
        // `q_table(z)`
        proof.q_table_at_z = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        // `q_lookup(z)`
        proof.q_lookup_at_z = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        // `table(z)`
        proof.table_at_z = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;

        //w0(zw)
        proof.wire0_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //z(zw)
        proof.grand_product_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //s(zw)
        proof.sorted_lookup_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //zlookup(zw)
        proof.grand_product_lookup_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //table(zw)
        proof.table_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //w2(zw)
        proof.wire2_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //z_substring(zw)
        proof.z_substring_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;

        proof.opening_at_z_proof = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;

        proof.opening_at_z_omega_proof = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
    }
}
