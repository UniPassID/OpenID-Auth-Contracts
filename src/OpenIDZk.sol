// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

import "./libraries/LibRsa.sol";
import "./libraries/LibBytes.sol";
import "./libraries/LibBase64.sol";
import "./UnipassVerifier.sol";
import "./AudManager.sol";
import "./OpenIDKeyManager.sol";

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract OpenIDZk is Ownable, UnipassVerifier, AudManager, OpenIDKeyManager {
    using LibBytes for bytes;

    enum OpenIDParamsIndex {
        issLeftIndex,
        issRightIndex,
        kidLeftIndex,
        kidRightIndex,
        subLeftIndex,
        subRightIndex,
        audLeftIndex,
        audRightIndex,
        nonceLeftIndex,
        iatLeftIndex,
        expLeftIndex,
        headerBase64Len,
        payloadLeftIndex,
        payloadBase64Len
    }
    uint256 constant OpenIDParamsIndexNum = 14;

    // first register srshash
    function setupSRSHashAndVKHash(
        uint256 srshash_init,
        uint64 num_inputs,
        uint128 domain_size,
        uint256[] memory vkdata
    ) public onlyOwner returns (bool) {
        return
            setupSRSHash(srshash_init) &&
            setupVKHash(num_inputs, domain_size, vkdata);
    }

    function _validateTimestamp(
        uint256 _index,
        bytes calldata _data,
        bytes calldata _payload
    ) private view {
        bytes calldata iat;
        {
            uint32 iatLeftIndex;
            (iatLeftIndex, ) = _data.cReadUint32(
                uint256(OpenIDParamsIndex.iatLeftIndex) * 4 + _index
            );

            require(
                bytes32(_payload[iatLeftIndex - 6:iatLeftIndex]) ==
                    bytes32('"iat":'),
                "_validateTimestamp: INVALID_IAT"
            );
            iat = _payload[iatLeftIndex:iatLeftIndex + 10];
        }

        bytes calldata exp;
        {
            uint32 expLeftIndex;
            (expLeftIndex, ) = _data.cReadUint32(
                uint256(OpenIDParamsIndex.expLeftIndex) * 4 + _index
            );

            require(
                bytes32(_payload[expLeftIndex - 6:expLeftIndex]) ==
                    bytes32('"exp":'),
                "_validateTimestamp: INVALID_EXP"
            );
            exp = _payload[expLeftIndex:expLeftIndex + 10];
        }

        bytes32 timestamp = LibBytes.uint32ToASSCIIBytes32(
            uint32(block.timestamp)
        );
        require(
            timestamp > bytes32(iat) && timestamp < bytes32(exp),
            "_validateTimestamp: INVALID_TIMESTAMP"
        );
    }

    function _validatePublicInputs(
        uint256 _index,
        bytes calldata _data,
        bytes memory concat_hash,
        uint256[] memory public_inputs
    ) internal pure returns (bool) {
        uint32 headerBase64Len;
        (headerBase64Len, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.headerBase64Len) * 4 + _index
        );
        uint32 payloadLeftIndex;
        (payloadLeftIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.payloadLeftIndex) * 4 + _index
        );
        uint32 payloadBase64Len;
        (payloadBase64Len, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.payloadBase64Len) * 4 + _index
        );
        uint32 subLeftIndex;
        (subLeftIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.subLeftIndex) * 4 + _index
        );

        uint32 subRightIndex;
        (subRightIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.subRightIndex) * 4 + _index
        );

        OpenIdPublicParams memory public_params;
        public_params.concat_hash = concat_hash;
        public_params.header_base64_len = headerBase64Len;
        public_params.payload_left_index = payloadLeftIndex;
        public_params.payload_base64_len = payloadBase64Len;
        public_params.sub_left_index = subLeftIndex;
        public_params.sub_len = subRightIndex - subLeftIndex;

        return checkPublicInputsOpenId(public_params, public_inputs);
    }

    function _validateZkProof(
        uint256 _index,
        bytes calldata _data,
        bytes memory concat_hash
    ) internal view returns (uint256) {
        uint128 domain_size;
        uint256[] memory vkdata;
        uint256[] memory serialized_proof;
        uint256[] memory public_inputs;
        uint256 index = OpenIDParamsIndexNum * 4 + 64 + _index;
        (domain_size, index) = _data.cReadUint128(index);
        uint32 len;
        (len, index) = _data.cReadUint32(index);
        index += len;
        (len, index) = _data.cReadUint32(index);
        index += len;
        (len, index) = _data.cReadUint32(index);
        index += len;
        (vkdata, index) = _data.mcReadUint256Array(index);
        (public_inputs, index) = _data.mcReadUint256Array(index);
        (serialized_proof, index) = _data.mcReadUint256Array(index);

        require(
            verifyOpenId(domain_size, vkdata, public_inputs, serialized_proof),
            "proof invalid"
        );

        require(
            _validatePublicInputs(_index, _data, concat_hash, public_inputs),
            "input invalid"
        );
        return (index);
    }

    function _validateRSA(
        uint256 _index,
        bytes calldata _data,
        bytes32 idTokenHash,
        bytes calldata signature,
        bytes calldata header,
        bytes calldata payload_pub
    ) internal view returns (bool succ, bytes32 issHash) {
        bytes memory publicKey;
        (issHash, publicKey) = _getPublicKeyAndIssHash(
            _index,
            _data,
            header,
            payload_pub
        );
        succ = LibRsa.rsapkcs1Verify(
            idTokenHash,
            publicKey,
            hex"010001",
            signature
        );
    }

    function _validateZkAndRSA(
        uint256 _index,
        bytes calldata _data,
        bytes calldata signature,
        bytes calldata header,
        bytes calldata payload_pub
    )
        internal
        view
        returns (bool succ, uint256 index, bytes32 issHash, bytes32 subHash)
    {
        bytes32 idTokenHash;
        {
            index = OpenIDParamsIndexNum * 4 + _index;
            idTokenHash = _data.readBytes32(index);
            index = OpenIDParamsIndexNum * 4 + 32 + _index;
            subHash = _data.readBytes32(index);

            bytes memory concat_hash = abi.encodePacked(
                idTokenHash,
                subHash,
                sha256(header),
                sha256(payload_pub)
            );
            _checkSub(_index, _data, payload_pub);
            index = _validateZkProof(_index, _data, concat_hash);
        }

        (succ, issHash) = _validateRSA(
            _index,
            _data,
            idTokenHash,
            signature,
            header,
            payload_pub
        );
    }

    function validateIDToken(
        uint256 _index,
        bytes calldata _data
    )
        external
        view
        returns (
            bool succ,
            uint256 index,
            bytes32 issHash,
            bytes32 subHash,
            bytes32 nonceHash
        )
    {
        bytes calldata header;
        bytes calldata payload_pub;
        bytes calldata signature;
        {
            index = OpenIDParamsIndexNum * 4 + 64 + 16 + _index;
            uint32 len;
            (len, index) = _data.cReadUint32(index);
            header = _data[index:index + len];
            index += len;
            (len, index) = _data.cReadUint32(index);
            payload_pub = _data[index:index + len];
            index += len;
            (len, index) = _data.cReadUint32(index);
            signature = _data[index:index + len];
            index += len;
        }

        _validateTimestamp(_index, _data, payload_pub);
        (succ, index, issHash, subHash) = _validateZkAndRSA(
            _index,
            _data,
            signature,
            header,
            payload_pub
        );

        nonceHash = keccak256(_getNonce(_index, _data, payload_pub));
    }

    function _getNonce(
        uint256 _index,
        bytes calldata _data,
        bytes calldata _payload
    ) internal pure returns (bytes calldata nonce) {
        uint32 nonceLeftIndex;
        (nonceLeftIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.nonceLeftIndex) * 4 + _index
        );

        require(
            bytes32(_payload[nonceLeftIndex - 9:nonceLeftIndex]) ==
                bytes32('"nonce":"'),
            "_getNonce: INVALID_NONCE"
        );
        nonce = _payload[nonceLeftIndex:nonceLeftIndex + 66];
    }

    function _checkSub(
        uint256 _index,
        bytes calldata _data,
        bytes calldata _payload
    ) internal pure {
        uint32 subLeftIndex;
        (subLeftIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.subLeftIndex) * 4 + _index
        );
        require(
            bytes7(_payload[subLeftIndex - 7:subLeftIndex]) ==
                bytes7('"sub":"'),
            "_getSub: INVALID_SUB_LEFT"
        );

        uint32 subRightIndex;
        (subRightIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.subRightIndex) * 4 + _index
        );
        bytes2 suffix = bytes2(_payload[subRightIndex:subRightIndex + 2]);
        require(
            suffix == bytes2('",') || suffix == bytes2('"}'),
            "_getSub: INVALID_SUB_RIGHT"
        );
    }

    function _getPublicKeyAndIssHash(
        uint256 _index,
        bytes calldata _data,
        bytes calldata _header,
        bytes calldata _payload
    ) private view returns (bytes32 issHash, bytes memory publicKey) {
        bytes calldata iss = _getIss(_index, _data, _payload);
        issHash = keccak256(iss);

        bytes calldata aud = _getAud(_index, _data, _payload);
        require(
            isAudienceValid(keccak256(abi.encodePacked(iss, aud))),
            "_getPublicKeyAndIssHash: INVALID_AUD"
        );

        bytes memory kid = _getKid(_index, _data, _header);
        publicKey = getOpenIDPublicKey(keccak256(abi.encodePacked(iss, kid)));
        require(
            publicKey.length > 0,
            "_getPublicKeyAndIssHash: INVALID_PUB_KEY"
        );
    }

    function _getIss(
        uint256 _index,
        bytes calldata _data,
        bytes calldata _payload
    ) internal pure returns (bytes calldata iss) {
        uint32 issLeftIndex;
        (issLeftIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.issLeftIndex) * 4 + _index
        );
        require(
            bytes7(_payload[issLeftIndex - 7:issLeftIndex]) ==
                bytes7('"iss":"'),
            "_getIss: INVALID_ISS_LEFT"
        );

        uint32 issRightIndex;
        (issRightIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.issRightIndex) * 4 + _index
        );
        bytes2 suffix = bytes2(_payload[issRightIndex:issRightIndex + 2]);
        require(
            suffix == bytes2('",') || suffix == bytes2('"}'),
            "_getIss: INVALID_ISS_RIGHT"
        );

        iss = _payload[issLeftIndex:issRightIndex];
    }

    function _getKid(
        uint256 _index,
        bytes calldata _data,
        bytes calldata _header
    ) internal pure returns (bytes calldata kid) {
        uint32 kidLeftIndex;
        (kidLeftIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.kidLeftIndex) * 4 + _index
        );
        require(
            bytes7(_header[kidLeftIndex - 7:kidLeftIndex]) == bytes7('"kid":"'),
            "_getKid: INVALID_KID_LEFT"
        );

        uint32 kidRightIndex;
        (kidRightIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.kidRightIndex) * 4 + _index
        );
        bytes2 suffix = bytes2(_header[kidRightIndex:kidRightIndex + 2]);
        require(
            suffix == bytes2('",') || suffix == bytes2('"}'),
            "_getKid: INVALID_KID_RIGHT"
        );

        kid = _header[kidLeftIndex:kidRightIndex];
    }

    function _getAud(
        uint256 _index,
        bytes calldata _data,
        bytes calldata _payload
    ) internal pure returns (bytes calldata aud) {
        uint32 audLeftIndex;
        (audLeftIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.audLeftIndex) * 4 + _index
        );
        require(
            bytes7(_payload[audLeftIndex - 7:audLeftIndex]) ==
                bytes7('"aud":"'),
            "_getAud: INVALID_AUD_LEFT"
        );

        uint32 audRightIndex;
        (audRightIndex, ) = _data.cReadUint32(
            uint256(OpenIDParamsIndex.audRightIndex) * 4 + _index
        );
        bytes2 suffix = bytes2(_payload[audRightIndex:audRightIndex + 2]);
        require(
            suffix == bytes2('",') || suffix == bytes2('"}'),
            "_getAud: INVALID_AUD_RIGHT"
        );

        aud = _payload[audLeftIndex:audRightIndex];
    }
}
