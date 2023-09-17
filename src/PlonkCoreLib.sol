// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

/// Library for Bn254 curve operations.
library PairingsBn254 {
    uint256 constant private q_mod =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant private r_mod =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    /// b of $y^2 = x^3 + b$
    uint256 constant private bn254_b_coeff = 3;

    /// G1 point, whose X, Y coordinates lie in filed Fq.
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    /// The scalar field Fr
    struct Fr {
        uint256 value;
    }

    /// Check if the input of a 256-bit integer `fr` is an element of Fr field. If yes, return a Fr scalar.
    function new_fr(uint256 fr) internal pure returns (Fr memory) {
        require(fr < r_mod);
        return Fr({value: fr});
    }

    /// Copy of a Fr scalar
    function copy(Fr memory self) internal pure returns (Fr memory n) {
        n.value = self.value;
    }

    /// Assign value of Fr scalar `other` to `self`
    function assign(Fr memory self, Fr memory other) internal pure {
        self.value = other.value;
    }

    /// Return inversion `1/fr`
    function inverse(Fr memory fr) internal view returns (Fr memory) {
        require(fr.value != 0);
        return pow(fr, r_mod - 2);
    }

    /// For Fr scalars: `self` += `other`
    function add_assign(Fr memory self, Fr memory other) internal pure {
        self.value = addmod(self.value, other.value, r_mod);
    }

    /// For Fr scalars: `self` -= `other`
    function sub_assign(Fr memory self, Fr memory other) internal pure {
        self.value = addmod(self.value, r_mod - other.value, r_mod);
    }

    /// For Fr scalars: `self` *= `other`
    function mul_assign(Fr memory self, Fr memory other) internal pure {
        self.value = mulmod(self.value, other.value, r_mod);
    }

    /// For Fr scalars: `self` ^ `power`
    /// `power` is a plain 256-bit integer. More rigorously, `power` should be `power` modulo `r_mod - 1`, but it is rare that `power` exceeds `r_mod`.
    function pow(Fr memory self, uint256 power)
        internal
        view
        returns (Fr memory)
    {
        uint256[6] memory input = [32, 32, 32, self.value, power, r_mod];
        uint256[1] memory result;
        bool success;
        assembly {
            success := staticcall(gas(), 0x05, input, 0xc0, result, 0x20)
        }
        require(success);
        return Fr({value: result[0]});
    }

    // Encoding of field elements is: X[0] * z + X[1]
    /// G2 point, where X, Y are each represented by 2 256-bit integers
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /// Generator of G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    /// Construct G1 point from coordinates `x` and `y`, with the assumption that `(x, y)` is a legitimate point.
    function new_g1(uint256 x, uint256 y)
        internal
        pure
        returns (G1Point memory)
    {
        return G1Point(x, y);
    }

    /// Construct G1 point from coordinates `x` and `y`, with checkings:
    /// 1. point of infinity: `x = 0`, `y = 0`
    /// 2. affine points: `x` and `y` in field Fq, and satisfy the curve equation $y^2 = x^3 + b$
    function new_g1_checked(uint256 x, uint256 y)
        internal
        pure
        returns (G1Point memory)
    {
        if (x == 0 && y == 0) {
            // point of infinity is (0,0)
            return G1Point(x, y);
        }

        // check encoding
        require(x < q_mod, "x-coordinate out of range");
        require(y < q_mod, "y-coordinate out of range");
        // check on curve
        uint256 lhs = mulmod(y, y, q_mod); // y^2
        uint256 rhs = mulmod(x, x, q_mod); // x^2
        rhs = mulmod(rhs, x, q_mod); // x^3
        rhs = addmod(rhs, bn254_b_coeff, q_mod); // x^3 + b
        require(lhs == rhs,"point is not on the curve");

        return G1Point(x, y);
    }

    /// Construct G2 point
    function new_g2(uint256[2] memory x, uint256[2] memory y)
        internal
        pure
        returns (G2Point memory)
    {
        return G2Point(x, y);
    }

    /// Copy of G1 point
    function copy_g1(G1Point memory self)
        internal
        pure
        returns (G1Point memory result)
    {
        result.X = self.X;
        result.Y = self.Y;
    }

    /// Generator of G2
    function P2() internal pure returns (G2Point memory) {
        // for some reason ethereum expects to have c1*v + c0 form

        return
            G2Point(
                [
                    0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2,
                    0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
                ],
                [
                    0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b,
                    0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
                ]
            );
    }

    /// For G1 point: `-self`
    function negate(G1Point memory self) internal pure {
        // The prime q in the base field F_q for G1
        if (self.Y == 0) {
            require(self.X == 0);
            return;
        }

        self.Y = q_mod - self.Y;
    }

    /// For G1 points: return `p = p1 + p2`
    function point_add(G1Point memory p1, G1Point memory p2)
        internal
        view
        returns (G1Point memory r)
    {
        point_add_into_dest(p1, p2, r);
        return r;
    }

    /// For G1 points: `p1 += p2`
    function point_add_assign(G1Point memory p1, G1Point memory p2)
        internal
        view
    {
        point_add_into_dest(p1, p2, p1);
    }

    /// For G1 points: assign sum `p1 + p2` to `dest`
    function point_add_into_dest(
        G1Point memory p1,
        G1Point memory p2,
        G1Point memory dest
    ) internal view {
        if (p2.X == 0 && p2.Y == 0) {
            // we add zero, nothing happens
            dest.X = p1.X;
            dest.Y = p1.Y;
            return;
        } else if (p1.X == 0 && p1.Y == 0) {
            // we add into zero, and we add non-zero point
            dest.X = p2.X;
            dest.Y = p2.Y;
            return;
        } else {
            uint256[4] memory input;

            input[0] = p1.X;
            input[1] = p1.Y;
            input[2] = p2.X;
            input[3] = p2.Y;

            bool success = false;
            assembly {
                success := staticcall(gas(), 6, input, 0x80, dest, 0x40)
            }
            require(success);
        }
    }

    /// For G1 points: `p1 -= p2`
    function point_sub_assign(G1Point memory p1, G1Point memory p2)
        internal
        view
    {
        point_sub_into_dest(p1, p2, p1);
    }

    /// For G1 points: assign difference `p1 - p2` to `dest`
    function point_sub_into_dest(
        G1Point memory p1,
        G1Point memory p2,
        G1Point memory dest
    ) internal view {
        if (p2.X == 0 && p2.Y == 0) {
            // we subtracted zero, nothing happens
            dest.X = p1.X;
            dest.Y = p1.Y;
            return;
        } else if (p1.X == 0 && p1.Y == 0) {
            // we subtract from zero, and we subtract non-zero point
            dest.X = p2.X;
            dest.Y = q_mod - p2.Y;
            return;
        } else {
            uint256[4] memory input;

            input[0] = p1.X;
            input[1] = p1.Y;
            input[2] = p2.X;
            input[3] = q_mod - p2.Y;

            bool success = false;
            assembly {
                success := staticcall(gas(), 6, input, 0x80, dest, 0x40)
            }
            require(success);
        }
    }

    /// Scalar multiplication for G1 point, return `s * p`
    function point_mul(G1Point memory p, Fr memory s)
        internal
        view
        returns (G1Point memory r)
    {
        point_mul_into_dest(p, s, r);
        return r;
    }

    /// Scalar multiplication for G1 point: assign `s * p` to p
    function point_mul_assign(G1Point memory p, Fr memory s) internal view {
        point_mul_into_dest(p, s, p);
    }

    /// Scalar multiplication for G1 point: assign `s * p` to `dest`
    function point_mul_into_dest(
        G1Point memory p,
        Fr memory s,
        G1Point memory dest
    ) internal view {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s.value;
        bool success;
        assembly {
            success := staticcall(gas(), 7, input, 0x60, dest, 0x40)
        }
        require(success);
    }

    /// Pairing: with `p1` and `p2` being arrays of G1 and G2 points respectively,
    /// the function return `true` if:
    /// `p1` and `p2` of the same length
    /// `\sum_i Pairing(p1[i], p2[i]) = 0`
    function pairing(G1Point[] memory p1, G2Point[] memory p2)
        internal
        view
        returns (bool)
    {
        require(p1.length == p2.length);
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; ++i) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint256[1] memory out;
        bool success;
        assembly {
            success := staticcall(
                gas(),
                8,
                add(input, 0x20),
                mul(inputSize, 0x20),
                out,
                0x20
            )
        }
        require(success);
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    /// Return `true` if `Pairing(a1, a2) = Pairing(b1, b2)`
    function pairingProd2(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
}

/// Library for Fiat-Shamir heuristic
library TranscriptLibrary {
    // flip                    0xe000000000000000000000000000000000000000000000000000000000000000;
    uint256 constant private FR_MASK =
        0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    uint32 constant private DST_0 = 0;
    uint32 constant private DST_1 = 1;
    uint32 constant private DST_CHALLENGE = 2;

    struct Transcript {
        bytes32 state_0;
        bytes32 state_1;
        uint32 challenge_counter;
    }

    function new_transcript() internal pure returns (Transcript memory t) {
        t.state_0 = bytes32(0);
        t.state_1 = bytes32(0);
        t.challenge_counter = 0;
    }

    function update_with_u256(Transcript memory self, uint256 value)
        internal
        pure
    {
        bytes32 old_state_0 = self.state_0;
        self.state_0 = keccak256(
            abi.encodePacked(DST_0, old_state_0, self.state_1, value)
        );
        self.state_1 = keccak256(
            abi.encodePacked(DST_1, old_state_0, self.state_1, value)
        );
    }

    function update_with_fr(
        Transcript memory self,
        PairingsBn254.Fr memory value
    ) internal pure {
        update_with_u256(self, value.value);
    }

    function update_with_g1(
        Transcript memory self,
        PairingsBn254.G1Point memory p
    ) internal pure {
        update_with_u256(self, p.X);
        update_with_u256(self, p.Y);
    }

    function get_challenge(Transcript memory self)
        internal
        pure
        returns (PairingsBn254.Fr memory challenge)
    {
        bytes32 query = keccak256(
            abi.encodePacked(
                DST_CHALLENGE,
                self.state_0,
                self.state_1,
                self.challenge_counter
            )
        );
        self.challenge_counter += 1;
        challenge = PairingsBn254.Fr({value: uint256(query) & FR_MASK});
    }
}