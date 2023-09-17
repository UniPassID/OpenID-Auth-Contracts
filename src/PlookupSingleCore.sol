// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.0;

import "./PlonkCoreLib.sol";

/// Plonk verifier
contract Plonk4SingleVerifierWithAccessToDNext {
    using PairingsBn254 for PairingsBn254.G1Point;
    using PairingsBn254 for PairingsBn254.G2Point;
    using PairingsBn254 for PairingsBn254.Fr;

    using TranscriptLibrary for TranscriptLibrary.Transcript;

    /**
     * State width is set to be 5.
     * | w_0 | w_1 | w_2 | w_3 | w_4 |
     * The verifier checks if the arithmetic constraint
     * holds for each the step i.
     *
     * ( q_0[i] * w0[i] + q_1[i] * w1[i] + q_2[i] * w2[i] + q_3[i] * w3[i] + q_m[i] * w0[i] * w1[i] + q_c[i] - PI[i])
     * + alpha * ( z[i]*(w0[X] + 1*beta*X +gamma)(7)(13)(17) - z[wi]*(w0[X] + beta*sigma0[X] +gamma)()()()
     *               + alpha*L1[X]*(z[i] - 1) )
     * + alpha^3 * ( zlookup[i]*(qlookup[i]*v[i] +gamma)*(t[i] + beta*t[wi] + (beta+1)*gamma)
     *                - zlookup[wi]*gamma*(s[i] + beta*s[wi] + (beta+1)*gamma)
     *                   + alpha*L1[X]*(zlookup[i] - 1) )
     * + alpha^5 * ( z_substring[wi] - z_substring[i] + q_substring[i]*(w2[i]*w3[i] -w0[i]*w1[i])
     *                + alpha * q_substring_r[i]*( w0[wi]*w3[i]*(w2[i] +w0[wi] -w0[i]) -w2[wi] )
     *                + alpha^2 * z_substring[i] * L1[X]
     *              )
     * = 0
     */

    uint256 constant STATE_WIDTH = 5;

    struct VerificationKey {
        uint128 domain_size;
        uint128 num_inputs;
        /// Generator of FFT domain: `omega` ^ `domain_size` = 1.
        PairingsBn254.Fr omega;
        /// commitments for selector polynomials `[q_0]`, `[q_1]`, `[q_2]`, `[q_3]`... , `[q_m]`, `[q_c]`
        /// , `[q_lookup]`, `[q_table]`, [q_substring], [q_substring_r]
        PairingsBn254.G1Point[STATE_WIDTH + 2 + 2 + 2] selector_commitments;
        /// commitment for permutation polynomials `[sigma_0]`, `[sigma_1]`, `[sigma_2]`, `[sigma_3]`...
        PairingsBn254.G1Point[STATE_WIDTH] permutation_commitments;
        /// commitment for tables polynomials `[table_0]`, `[table_1]`, `[table_2]`, `[table_3]`, `[table_4]`...
        PairingsBn254.G1Point[STATE_WIDTH + 1] tables_commitments;
        /// x element of G2: [x]_2 (beta_h)
        PairingsBn254.G2Point g2_x;
    }

    bytes32 srshash;

    struct Proof {
        /// input values, Fr array of length `verification_key.num_inputs`
        uint256[] input_values;
        /// commitments for witness polynomials `[w_0]`, `[w_1]`, `[w_2]`, `[w_3]`...
        PairingsBn254.G1Point[STATE_WIDTH] wire_commitments;
        /// commitment for grand product polynomial `[s]`
        PairingsBn254.G1Point sorted_lookup_commitment;
        /// commitment for grand product polynomial `[z]`
        PairingsBn254.G1Point grand_product_commitment;
        /// commitment for grand product polynomial `[z_lookup]`
        PairingsBn254.G1Point grand_product_lookup_commitment;
        /// commitment for grand sum polynomial `[z_substring]`
        PairingsBn254.G1Point z_substring_commitment;
        /// commitments for quotient polynomial `[t_0]`, `[t_1]`, `[t_2]`, `[t_3]`...
        PairingsBn254.G1Point[STATE_WIDTH] quotient_poly_commitments;
        /// evaluation `t(z)` for the quotient polynomial
        PairingsBn254.Fr quotient_polynomial_at_z;
        /// evaluation `r(z)`
        PairingsBn254.Fr linearization_polynomial_at_z;
        /// evaluations `w_0(z)`, `w_1(z)`, `w_2(z)`, `w_3(z)`...
        PairingsBn254.Fr[STATE_WIDTH] wire_values_at_z;
        /// evaluations `sigma_0(z)`, `sigma_1(z)`, `sigma_2(z)` ...
        PairingsBn254.Fr[STATE_WIDTH - 1] permutation_polynomials_at_z;
        /// evaluation `q_lookup(z)`
        PairingsBn254.Fr q_lookup_at_z;
        /// evaluation `q_table(z)`
        PairingsBn254.Fr q_table_at_z;
        /// evaluation `table(z)`
        PairingsBn254.Fr table_at_z;
        /// evaluation `w0(z * omega)`
        PairingsBn254.Fr wire0_at_z_omega;
        /// evaluation `z(z * omega)` for the grand product polynomial at shifted location
        PairingsBn254.Fr grand_product_at_z_omega;
        /// evaluation `s(z * omega)`
        PairingsBn254.Fr sorted_lookup_at_z_omega;
        /// evaluation `z_lookup(z * omega)`
        PairingsBn254.Fr grand_product_lookup_at_z_omega;
        /// evaluation `table(z * omega)`
        PairingsBn254.Fr table_at_z_omega;
        /// evaluation `w2(z * omega)`
        PairingsBn254.Fr wire2_at_z_omega;
        /// evaluation `z_substring(z * omega)`
        PairingsBn254.Fr z_substring_at_z_omega;
        /// opening proof for all polynomial openings at `z`
        PairingsBn254.G1Point opening_at_z_proof;
        /// opening proof for all polynomial openings at `z * omega`
        PairingsBn254.G1Point opening_at_z_omega_proof;
    }

    struct PartialVerifierState {
        /// challenge s
        PairingsBn254.Fr eta;
        /// `beta` and `gamma` for grand product
        PairingsBn254.Fr beta;
        PairingsBn254.Fr gamma;
        /// `beta_1` and `gamma_1` for grand product of lookup
        PairingsBn254.Fr beta_1;
        PairingsBn254.Fr gamma_1;
        /// combinator
        PairingsBn254.Fr alpha;
        /// `z` marks where the polynomial commitments should be opened
        PairingsBn254.Fr z;
        /// `v` for batched polynomial commitment opening a same location
        PairingsBn254.Fr v;
        /// `u` for combination of polynomial commitment opening proofs at `z` and `z * omega`
        PairingsBn254.Fr u;
        /// for constructing public inputs `pi(X)`
        PairingsBn254.Fr[] cached_lagrange_evals;
        /// Ln(z)
        // PairingsBn254.Fr cached_lagrange_eval_Ln;
    }

    /// Evaluate one of the Lagrange polynomials associated with the FFT domain with `domain_size`
    /// `poly_num` marks which Lagrange polynomial to evaluate, ranging [0, `domain_size`)
    /// `omega` marks the domain generator
    /// `at` marks the location where the polynomial is evaluated, restricted to lie outside of the domain
    /**
     *            X^n - 1         1            w^i * (X^n - 1)
     * L_i(X) = ----------- * ------------ = -------------------
     *            X - w^i      n * w^{-i}       n * (X - w^i)
     */
    function evaluate_lagrange_poly_out_of_domain(
        uint256 poly_num,
        uint256 domain_size,
        PairingsBn254.Fr memory omega,
        PairingsBn254.Fr memory at
    ) internal view returns (PairingsBn254.Fr memory res) {
        require(poly_num < domain_size);
        PairingsBn254.Fr memory one = PairingsBn254.new_fr(1);
        PairingsBn254.Fr memory omega_power = omega.pow(poly_num);
        /// numerator: (X^n - 1) * w^i
        res = at.pow(domain_size);
        res.sub_assign(one);
        require(res.value != 0); // Vanishing polynomial can not be zero at point `at`
        res.mul_assign(omega_power);
        /// denumerator: (X - w^i) * n
        PairingsBn254.Fr memory den = PairingsBn254.copy(at);
        den.sub_assign(omega_power);
        den.mul_assign(PairingsBn254.new_fr(domain_size));

        den = den.inverse();

        res.mul_assign(den);
    }

    /// Evaluate a batch of the Lagrange polynomials associated with the FFT domain.
    /// Presumably, n Lagrange polynomial evaluations involves n inversion,
    /// whereas Montgomery batch inversion reduce it to only one.
    function batch_evaluate_lagrange_poly_out_of_domain(
        uint256 poly_nums_len, //just [0,n)
        uint256 domain_size,
        PairingsBn254.Fr memory omega,
        PairingsBn254.Fr memory at
    )
        internal
        view
        returns (
            PairingsBn254.Fr[] memory res,
            // PairingsBn254.Fr memory res_Ln,
            PairingsBn254.Fr memory return_zeta_pow_n
        )
    {
        PairingsBn254.Fr memory one = PairingsBn254.new_fr(1);
        PairingsBn254.Fr memory tmp_1 = PairingsBn254.copy(one);
        PairingsBn254.Fr memory tmp_2 = PairingsBn254.new_fr(domain_size);
        PairingsBn254.Fr memory vanishing_at_z = at.pow(domain_size);
        return_zeta_pow_n = PairingsBn254.copy(vanishing_at_z);
        vanishing_at_z.sub_assign(one);

        // we can not have random point z be in domain
        require(vanishing_at_z.value != 0);
        PairingsBn254.Fr[] memory nums = new PairingsBn254.Fr[](poly_nums_len);
        PairingsBn254.Fr[] memory dens = new PairingsBn254.Fr[](poly_nums_len);

        uint256 dens_len = dens.length;
        /// compute numerators `nums` and denumerators `dens`, both of `poly_nums.length`
        // numerators in a form omega^i * (z^n - 1)
        // denoms in a form (z - omega^i) * N
        // tmp_1 = omega.pow(poly_nums[0]); // power of omega
        for (uint256 i = 0; i < poly_nums_len; ++i) {
            //  = omega.pow(poly_nums[i]); // power of omega
            nums[i].assign(vanishing_at_z);
            nums[i].mul_assign(tmp_1);

            dens[i].assign(at); // (X - omega^i) * N
            dens[i].sub_assign(tmp_1);
            dens[i].mul_assign(tmp_2); // mul by domain size

            tmp_1.mul_assign(omega);
        }
        // add Ln = (z^n - 1)/(n(w*z - 1))
        // res_Ln = PairingsBn254.copy(vanishing_at_z);
        // tmp_1.assign(omega);
        // tmp_1.mul_assign(at);
        // tmp_1.sub_assign(one);
        // tmp_1.mul_assign(tmp_2);
        // dens[dens_len - 1].assign(tmp_1); // Ln

        /// batch inversion of `dens`
        PairingsBn254.Fr[] memory partial_products = new PairingsBn254.Fr[](
            dens_len
        ); // Ln
        partial_products[0].assign(PairingsBn254.copy(one));
        for (uint256 i = 1; i < dens_len; ++i) {
            partial_products[i].assign(partial_products[i - 1]);
            partial_products[i].mul_assign(dens[i - 1]);
        }

        tmp_2.assign(partial_products[partial_products.length - 1]);
        tmp_2.mul_assign(dens[dens_len - 1]);

        tmp_2 = tmp_2.inverse(); // tmp_2 contains a^-1 * b^-1 (with! the last one)

        PairingsBn254.Fr memory tmp3;
        for (uint256 i = dens_len - 1; ; i--) {
            tmp3.assign(dens[i]);
            dens[i].assign(tmp_2); // all inversed
            dens[i].mul_assign(partial_products[i]); // clear lowest terms
            tmp_2.mul_assign(tmp3);
            if (i == 0) break;
        }

        /// `nums[i] / dens[i]`
        uint256 nums_len = nums.length;
        for (uint256 i = 0; i < nums_len; ++i) {
            nums[i].mul_assign(dens[i]);
        }

        // Ln
        // res_Ln.mul_assign(dens[dens_len - 1]);
        // return nums;
        return (nums, return_zeta_pow_n);
    }

    function evaluate_vanishing(
        uint256 domain_size,
        PairingsBn254.Fr memory at
    ) internal view returns (PairingsBn254.Fr memory res) {
        res = at.pow(domain_size);
        res.sub_assign(PairingsBn254.new_fr(1));
    }

    /// `verify_at_z` is called by `verify_initial`.
    /// It performs the finite field part of the verification.
    function verify_at_z(
        PairingsBn254.Fr memory zeta_n,
        PartialVerifierState memory state,
        Proof memory proof
    ) internal pure returns (bool) {
        /// lhs = t(z) * v(z)
        PairingsBn254.Fr memory lhs = PairingsBn254.copy(zeta_n);
        PairingsBn254.Fr memory one = PairingsBn254.new_fr(1);
        lhs.sub_assign(one);
        require(lhs.value != 0); // we can not check a polynomial relationship if point `z` is in the domain
        lhs.mul_assign(proof.quotient_polynomial_at_z);

        /** rhs = r(z) - pi(z) - (r_permu + r_lookup + r_substring)
         *
         *      alpha * (                                   |
         *          (w_0(z) + beta * sigma_0(z) + gamma)    |
         *          * (w_1(z) + beta * sigma_1(z) + gamma)  |  "r_permu"
         *          * (w_2(z) + beta * sigma_2(z) + gamma)  |
         *          * (w_3(z) + gamma) * z(zw)              |
         *          + alpha * L1(z)                         |
         *      )                                           |
         *
         *      alpha^3 * (                                 |
         *          zlookup(zw) * gamma1                    |
         *              * (beta1 * s(zw) + (beta1+1)gamma1)    |  "r_lookup"
         *          + alpha * L1(z)                         |
         *      )                                           |
         *      alpha^5 * (                                 |
         *          - z_substring(zw)                       |  "r_substring"
         *      )                                           |
         */

        /// rhs = r(z)
        PairingsBn254.Fr memory rhs = PairingsBn254.copy(
            proof.linearization_polynomial_at_z
        );
        // public inputs
        PairingsBn254.Fr memory inputs_term = PairingsBn254.new_fr(0);
        PairingsBn254.Fr memory tmp;
        uint256 inputs_len = proof.input_values.length;
        for (uint256 i = 0; i < inputs_len; ++i) {
            tmp.assign(state.cached_lagrange_evals[i]);
            tmp.mul_assign(PairingsBn254.new_fr(proof.input_values[i]));
            inputs_term.add_assign(tmp);
        }

        /// rhs -= pi(x)
        rhs.sub_assign(inputs_term);

        /// rhs -= "r_complement"
        PairingsBn254.Fr memory quotient_challenge = PairingsBn254.copy(
            state.alpha
        );

        PairingsBn254.Fr memory r_permu = PairingsBn254.copy(
            proof.grand_product_at_z_omega
        );
        //"r_permu"
        for (uint256 i = 0; i < STATE_WIDTH - 1; ++i) {
            tmp.assign(proof.permutation_polynomials_at_z[i]);
            tmp.mul_assign(state.beta);
            tmp.add_assign(state.gamma);
            tmp.add_assign(proof.wire_values_at_z[i]);

            r_permu.mul_assign(tmp);
        }
        //(w_4(z) + gamma)
        tmp.assign(state.gamma);
        tmp.add_assign(proof.wire_values_at_z[STATE_WIDTH - 1]);
        r_permu.mul_assign(tmp);

        //alpha * L1(z) (reuse var inputs_term)
        inputs_term.assign(state.cached_lagrange_evals[0]);
        inputs_term.mul_assign(state.alpha);
        r_permu.add_assign(inputs_term);

        r_permu.mul_assign(state.alpha);
        rhs.sub_assign(r_permu);

        //alpha^2
        quotient_challenge.mul_assign(state.alpha);
        //r_lookup (reuse var r_permu)
        r_permu.assign(proof.sorted_lookup_at_z_omega);
        r_permu.mul_assign(state.beta_1);

        tmp.assign(state.beta_1);
        tmp.add_assign(one);
        tmp.mul_assign(state.gamma_1);
        r_permu.add_assign(tmp);

        r_permu.mul_assign(proof.grand_product_lookup_at_z_omega);
        r_permu.mul_assign(state.gamma_1);

        // + alpha * L1(z)
        r_permu.add_assign(inputs_term);

        //alpha^3
        quotient_challenge.mul_assign(state.alpha);
        // r_lookup * alpha^3
        r_permu.mul_assign(quotient_challenge);

        rhs.sub_assign(r_permu);

        //alpha^5
        quotient_challenge.mul_assign(state.alpha);
        quotient_challenge.mul_assign(state.alpha);
        // "r_substring" (reuse var)
        // alpha^5 * z_substring(zw)
        quotient_challenge.mul_assign(proof.z_substring_at_z_omega);

        rhs.add_assign(quotient_challenge); //over

        return lhs.value == rhs.value;
    }

    /**
     * [D] = v[r] + v*u[z] + v2*u[s] + v3*u[zlookup]
     * where 
     * [r] = ([q_c] + w_0[q_0] + w_1[q_1] + w_2[q_2] + w_3[q_3] + w_0*w_1[q_m] )
     *       + alpha * ( (w_0(z) + bata * z + gamma)(w_1(z) + K_1 * bata * z + gamma)
     *              *(w_2(z) + k_2 * bata * z + gamma)(w_3(z) + k_3 * bata * z + gamma)
     *          + alpha * L_0(z) ) * [z]
     *       - alpha
     *          * (w_0(z) + beta * sigma_0(z) + gamma)
     *          * (w_1(z) + beta * sigma_1(z) + gamma)
     *          * (w_2(z) + beta * sigma_2(z) + gamma)
     *          * beta * z(z*omega) * [sigma_3]
     *       + alpha^3 * (
                (qlookup(w0+ eta*w1 + ... + eta4*qtable) + gamma1) * (table + beta1*table_zw + gamma1(1+beta1))
                + alpha * L_0(z)
                ) *[zlookup]
             - alpha^3 * (gamma1 * zlookup_zw) * [s]

     *       + alpha^5 * (w2[z]*w3[z] -w0[z]*w1[z]) *[q_substring]
     *       + alpha^5 * (  
     *          + alpha * ( w0[zw]*w3[z]*(w2[z] +w0[zw] -w0[z]) -w2[zw] )  
     *         ) *[q_substring_r]
     *       + v * alpha^5 * (alpha^2 * L1[z] - 1) *[z_substring]
                
     */
    function reconstruct_d(
        PartialVerifierState memory state,
        Proof memory proof,
        VerificationKey memory vk
    )
        internal
        view
        returns (
            PairingsBn254.G1Point memory res,
            PairingsBn254.Fr memory out_vu
        )
    {
        PairingsBn254.Fr memory one = PairingsBn254.new_fr(1);
        /// [q_c]
        res = PairingsBn254.copy_g1(vk.selector_commitments[STATE_WIDTH + 1]);

        // v[q_c]
        res.point_mul_assign(state.v);

        // v*w0
        PairingsBn254.Fr memory tmp_fr1 = PairingsBn254.copy(state.v);
        tmp_fr1.mul_assign(proof.wire_values_at_z[0]);

        PairingsBn254.G1Point memory tmp_g1 = PairingsBn254.P1();
        PairingsBn254.Fr memory tmp_fr;

        // v*w0 [q0]
        tmp_g1 = vk.selector_commitments[0].point_mul(tmp_fr1);
        res.point_add_assign(tmp_g1);

        // v*w0*w1
        tmp_fr1.mul_assign(proof.wire_values_at_z[1]);
        // v*w0*w1 [qm]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH].point_mul(tmp_fr1);
        res.point_add_assign(tmp_g1);

        for (uint256 i = 1; i < STATE_WIDTH; ++i) {
            // v*wi [qi]
            tmp_fr1.assign(state.v);
            tmp_fr1.mul_assign(proof.wire_values_at_z[i]);
            tmp_g1 = vk.selector_commitments[i].point_mul(tmp_fr1);
            res.point_add_assign(tmp_g1);
        }

        // v*alpha
        PairingsBn254.Fr memory tmp_fr0 = PairingsBn254.copy(state.v);
        tmp_fr0.mul_assign(state.alpha);

        // beta*z
        tmp_fr.assign(state.z);
        tmp_fr.mul_assign(state.beta);

        //(w_0(z) + bata * z + gamma)
        PairingsBn254.Fr memory grand_product_part_at_z = PairingsBn254.copy(
            tmp_fr
        );
        grand_product_part_at_z.add_assign(proof.wire_values_at_z[0]);
        grand_product_part_at_z.add_assign(state.gamma);
        // *(w_1(z) + K_1 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(7));
        tmp_fr1.add_assign(proof.wire_values_at_z[1]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);
        // *(w_2(z) + k_2 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(13));
        tmp_fr1.add_assign(proof.wire_values_at_z[2]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);
        // *(w_3(z) + k_3 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(17));
        tmp_fr1.add_assign(proof.wire_values_at_z[3]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);
        // *(w_4(z) + k_4 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(23));
        tmp_fr1.add_assign(proof.wire_values_at_z[4]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);

        // + alpha * L_0(z)
        tmp_fr1.assign(state.cached_lagrange_evals[0]);
        tmp_fr1.mul_assign(state.alpha);
        grand_product_part_at_z.add_assign(tmp_fr1);
        // * v*alpha
        grand_product_part_at_z.mul_assign(tmp_fr0);

        // v*u
        out_vu = PairingsBn254.copy(state.u);
        out_vu.mul_assign(state.v);

        // + v*u
        grand_product_part_at_z.add_assign(out_vu);
        // * [z]
        tmp_g1 = proof.grand_product_commitment.point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // (w_0(z) + beta * sigma_0(z) + gamma) (reuse var grand_product_part_at_z)
        grand_product_part_at_z.assign(proof.permutation_polynomials_at_z[0]);
        grand_product_part_at_z.mul_assign(state.beta);
        grand_product_part_at_z.add_assign(proof.wire_values_at_z[0]);
        grand_product_part_at_z.add_assign(state.gamma);
        for (uint256 i = 1; i < STATE_WIDTH - 1; ++i) {
            // *(w_i(z) + beta * sigma_i(z) + gamma)
            tmp_fr.assign(proof.permutation_polynomials_at_z[i]);
            tmp_fr.mul_assign(state.beta);
            tmp_fr.add_assign(proof.wire_values_at_z[i]);
            tmp_fr.add_assign(state.gamma);
            grand_product_part_at_z.mul_assign(tmp_fr);
        }
        // *beta * z(z*omega) * v*alpha * [sigma_last]
        grand_product_part_at_z.mul_assign(state.beta);
        grand_product_part_at_z.mul_assign(proof.grand_product_at_z_omega);
        grand_product_part_at_z.mul_assign(tmp_fr0);
        tmp_g1 = vk.permutation_commitments[STATE_WIDTH - 1].point_mul(
            grand_product_part_at_z
        );
        res.point_sub_assign(tmp_g1);

        // v*alpha^3
        tmp_fr0.mul_assign(state.alpha);
        tmp_fr0.mul_assign(state.alpha);

        // v2*u
        out_vu.mul_assign(state.v);

        // cal [s] first
        //(gamma * zlookup_zw)
        tmp_fr.assign(proof.grand_product_lookup_at_z_omega);
        tmp_fr.mul_assign(state.gamma_1);
        // * v*alpha^3
        tmp_fr.mul_assign(tmp_fr0);
        // - v2*u
        tmp_fr.sub_assign(out_vu);
        // * [s]
        tmp_g1 = proof.sorted_lookup_commitment.point_mul(tmp_fr);
        res.point_sub_assign(tmp_g1);

        // v3*u
        out_vu.mul_assign(state.v);

        // combinator eta
        PairingsBn254.Fr memory tmp_fr2 = PairingsBn254.copy(state.eta);

        // [zlookup]
        // w0+ eta*w1 + ... + eta5*qtable
        grand_product_part_at_z.assign(proof.wire_values_at_z[0]);
        for (uint256 i = 1; i < STATE_WIDTH; ++i) {
            tmp_fr.assign(proof.wire_values_at_z[i]);
            tmp_fr.mul_assign(tmp_fr2);
            grand_product_part_at_z.add_assign(tmp_fr);

            tmp_fr2.mul_assign(state.eta);
        }
        // eta^5 * qtable
        tmp_fr.assign(proof.q_table_at_z);
        tmp_fr.mul_assign(tmp_fr2);
        grand_product_part_at_z.add_assign(tmp_fr);
        // *qlookup + gamma
        grand_product_part_at_z.mul_assign(proof.q_lookup_at_z);
        grand_product_part_at_z.add_assign(state.gamma_1);

        // * (table + beta*table_zw + gamma(1+beta))
        // gamma(1+beta)
        tmp_fr.assign(state.beta_1);
        tmp_fr.add_assign(one);
        tmp_fr.mul_assign(state.gamma_1);
        // + beta*table_zw + table
        tmp_fr1.assign(proof.table_at_z_omega);
        tmp_fr1.mul_assign(state.beta_1);
        tmp_fr.add_assign(tmp_fr1);
        tmp_fr.add_assign(proof.table_at_z);
        // *
        grand_product_part_at_z.mul_assign(tmp_fr);

        //+ alpha * L_0(z)
        tmp_fr1.assign(state.cached_lagrange_evals[0]);
        tmp_fr1.mul_assign(state.alpha);
        grand_product_part_at_z.add_assign(tmp_fr1);

        // * v*alpha^3
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // + v3*u
        grand_product_part_at_z.add_assign(out_vu);
        // * [zlookup]
        tmp_g1 = proof.grand_product_lookup_commitment.point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // "substring"
        // first [q_substring_r] alpha * ( w0[zw]*w3[z]*(w2[z] +w0[zw] -w0[z]) -w2[zw] )
        // comb alpha
        tmp_fr.assign(state.alpha);
        // w2[z] +w0[zw] -w0[z] (reuse var)
        grand_product_part_at_z.assign(proof.wire_values_at_z[2]);
        grand_product_part_at_z.add_assign(proof.wire0_at_z_omega);
        grand_product_part_at_z.sub_assign(proof.wire_values_at_z[0]);
        // w0[zw]*w3[z]*(w2[z] +w0[zw] -w0[z]) -w2[zw]
        grand_product_part_at_z.mul_assign(proof.wire_values_at_z[3]);
        grand_product_part_at_z.mul_assign(proof.wire0_at_z_omega);
        grand_product_part_at_z.sub_assign(proof.wire2_at_z_omega);
        // *alpha
        grand_product_part_at_z.mul_assign(tmp_fr);
        tmp_fr.mul_assign(state.alpha);

        // (alpha^2 * L1[z] - 1)
        tmp_fr1.assign(state.cached_lagrange_evals[0]);
        tmp_fr1.mul_assign(tmp_fr);
        tmp_fr1.sub_assign(one);

        // v*alpha^5
        tmp_fr0.mul_assign(tmp_fr);

        // * v*alpha^5
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // * [q_substring_r]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 2 + 2 + 1].point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // (alpha^2 * L1[z] - 1) *[z_substring]
        // * v*alpha^5
        tmp_fr1.mul_assign(tmp_fr0);
        // * [z_substring]
        tmp_g1 = proof.z_substring_commitment.point_mul(tmp_fr1);
        res.point_add_assign(tmp_g1);

        // (w2[z]*w3[z] -w0[z]*w1[z]) *[q_substring]
        grand_product_part_at_z.assign(proof.wire_values_at_z[2]);
        grand_product_part_at_z.mul_assign(proof.wire_values_at_z[3]);
        tmp_fr1.assign(proof.wire_values_at_z[0]);
        tmp_fr1.mul_assign(proof.wire_values_at_z[1]);
        grand_product_part_at_z.sub_assign(tmp_fr1);
        // * v*alpha^5
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // * [q_substring]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 2 + 2].point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        return (res, out_vu);
    }

    /// The function `verify_commitments` batch verifies the evaluations constained in the proof of
    /// their corresponding commitments
    /**
     * 1. the proof element `r(z)`
     *    should be checked against polynomial commitment [r]
     *
     * All polynomial commitments are aggregated into [F], whereas evaluations are aggregated into aggregated value e.
     * Two opening proof is required, `[W_z]` for openings at `z`, and `[W_z_omega]` for openings at `z * omega`.
     * The polynomial commitments are finally checked by two pairing operations
     * Pairing([F] - e * [1] + z * [W_z] + u * z * omega * [W_z_omega], [1]_2) - Pairing([W_z] + u * [W_z_omega], x * [1]_2) ?= 0.

     // e( Σ[(u^i * ζi) * πi + u^i * commi)] - Σ[u^i * evali]*G0)], H0) = e(Σ[u^i * πi], H1).
     *
     * `reconstruct_d` computes [D] which is an aggregation of step 1 and 5,
     * both of which involves commitment [z].
     */
    function verify_commitments(
        PairingsBn254.Fr memory zeta_n,
        PartialVerifierState memory state,
        Proof memory proof,
        VerificationKey memory vk
    ) internal view returns (bool) {
        /** [F] = [t_0] + z^n * [t_1] + z^{2n} * [t_2] + z^{3n} * [t_3]
         *      + v * [r]
         *      + v^2 * [w_0] + v^3 * [w_1] + v^4 * [w_2] + v^5 * [w_3] + v^6 * [w_4]
         *      + v^7 * [sigma_0] + v^8 * [sigma_1] + v^9 * [sigma_2] + v^10 * [sigma_3]
         *      + v^11[qtable] + v^12[qlookup]
         *      + v^13 * ([table0] +eta[table1] +eta2[]... +eta4[])
         *      + u[w_0] + uv[z] + uv2[s] + uv3[zlookup]
         *      + uv4 * ([table0] +eta[table1] +eta2[]... +eta4[])
         *      + uv5 * [w_2] + uv6 [z_substring]
         */
        /// [D] = v[r] + v*u[z] + v2*u[s] + v3*u[zlookup] . v3*u
        (
            PairingsBn254.G1Point memory commitment_aggregation,
            PairingsBn254.Fr memory out_vu
        ) = reconstruct_d(state, proof, vk);

        /// [F] += [t_0] + z^n * [t_1] + z^{2n} * [t_2] + z^{3n} * [t_3] ...
        PairingsBn254.G1Point memory tmp_g1 = PairingsBn254.P1();

        commitment_aggregation.point_add_assign(
            proof.quotient_poly_commitments[0]
        );
        PairingsBn254.Fr memory tmp_fr = PairingsBn254.new_fr(1);
        for (uint256 i = 1; i < STATE_WIDTH; ++i) {
            tmp_fr.mul_assign(zeta_n);
            tmp_g1 = proof.quotient_poly_commitments[i].point_mul(tmp_fr);
            commitment_aggregation.point_add_assign(tmp_g1);
        }

        PairingsBn254.Fr memory aggregation_challenge = PairingsBn254.copy(
            state.v
        );

        /// [F] += (v^2 +u)[w_0] + v^3[w_1] + (v^4 + uv5)[w_2] + v^5[w_3] + v^6[w_4]
        aggregation_challenge.mul_assign(state.v);
        PairingsBn254.Fr memory tmp_fr0 = PairingsBn254.copy(
            aggregation_challenge
        );
        tmp_fr0.add_assign(state.u);
        tmp_g1 = proof.wire_commitments[0].point_mul(tmp_fr0);
        commitment_aggregation.point_add_assign(tmp_g1);

        // (v^4 + uv5)
        tmp_fr.assign(out_vu);
        tmp_fr0.assign(aggregation_challenge);
        tmp_fr.add_assign(tmp_fr0);
        tmp_fr.mul_assign(tmp_fr0);

        // v^3
        aggregation_challenge.mul_assign(state.v);
        tmp_g1 = proof.wire_commitments[1].point_mul(aggregation_challenge);
        commitment_aggregation.point_add_assign(tmp_g1);

        tmp_g1 = proof.wire_commitments[2].point_mul(tmp_fr);
        commitment_aggregation.point_add_assign(tmp_g1);
        tmp_fr.assign(aggregation_challenge);

        // v^5
        aggregation_challenge.mul_assign(tmp_fr0);
        for (uint256 i = 3; i < STATE_WIDTH; ++i) {
            tmp_g1 = proof.wire_commitments[i].point_mul(aggregation_challenge);
            commitment_aggregation.point_add_assign(tmp_g1);
            aggregation_challenge.mul_assign(state.v);
        }

        /// [F] += v^7 * [sigma_0] + v^8 * [sigma_1] + v^9 * [sigma_2] + v^10 * [sigma_3]
        for (uint256 i = 0; i < STATE_WIDTH - 1; ++i) {
            tmp_g1 = vk.permutation_commitments[i].point_mul(
                aggregation_challenge
            );
            commitment_aggregation.point_add_assign(tmp_g1);
            aggregation_challenge.mul_assign(state.v);
        }

        /// [F] += v^11[qtable] + v^12[qlookup]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 3].point_mul(
            aggregation_challenge
        );
        commitment_aggregation.point_add_assign(tmp_g1);
        aggregation_challenge.mul_assign(state.v);
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 2].point_mul(
            aggregation_challenge
        );
        commitment_aggregation.point_add_assign(tmp_g1);

        //([table0] +eta[table1] +eta2[]... +eta5[])
        PairingsBn254.G1Point memory tables_comms_combine = PairingsBn254
            .copy_g1(vk.tables_commitments[0]);
        tmp_fr0.assign(state.eta);
        for (uint256 i = 0; i < STATE_WIDTH; ++i) {
            tmp_g1 = vk.tables_commitments[i + 1].point_mul(tmp_fr0);
            tables_comms_combine.point_add_assign(tmp_g1);

            tmp_fr0.mul_assign(state.eta);
        }
        // [F] += (v^13 +uv4) * ([table0] +eta[table1] +eta2[]... +eta5[])
        aggregation_challenge.add_assign(out_vu);
        aggregation_challenge.mul_assign(state.v);
        tmp_g1 = tables_comms_combine.point_mul(aggregation_challenge);
        commitment_aggregation.point_add_assign(tmp_g1);

        // [F] += uv6 [z_substring]
        tmp_fr.mul_assign(out_vu);
        tmp_g1 = proof.z_substring_commitment.point_mul(tmp_fr);
        commitment_aggregation.point_add_assign(tmp_g1);

        /// Done with [F]. Then compute aggregated value.
        /** e = t(z)
         *      + v * r(z)
         *      + v^2 * w_0(z) + v^3 * w_1(z) * v^4 * w_2(z) + v^5 * w_3(z) + v^6 * w_4(z)
         *      + v^7 * sigma_0(z) + v^8 * sigma_1(z) + v^9 * sigma_2(z) + v^10 * sigma_3(z)
         *      + v^11 qtable(z) + v^12 qlookup(z) + v^13 table(z)
         *      + u* w0(zomega) + u*v z(zomega) + u*v2 s(zomega) + u*v3 zlookup(zomega)
         *      + u*v4 table(zomega)
         *      + uv5 * w2(zomega) + uv6 * z_substring(zomega)
         */
        // collect opening values
        aggregation_challenge.assign(state.v);

        PairingsBn254.Fr memory aggregated_value = PairingsBn254.copy(
            proof.quotient_polynomial_at_z
        );

        tmp_fr.assign(proof.linearization_polynomial_at_z);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);
        // + v2*w0 + ... + v5*w3 ...
        for (uint256 i = 0; i < STATE_WIDTH; ++i) {
            aggregation_challenge.mul_assign(state.v);
            tmp_fr.assign(proof.wire_values_at_z[i]);
            tmp_fr.mul_assign(aggregation_challenge);
            aggregated_value.add_assign(tmp_fr);
        }
        // + v7*sigma0 + ... + v8*sigma2 ...
        for (uint256 i = 0; i < STATE_WIDTH - 1; ++i) {
            aggregation_challenge.mul_assign(state.v);
            tmp_fr.assign(proof.permutation_polynomials_at_z[i]);
            tmp_fr.mul_assign(aggregation_challenge);
            aggregated_value.add_assign(tmp_fr);
        }
        // + v^11 qtable(z) + v^12 qlookup(z) + v^13 table(z)
        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.q_table_at_z);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.q_lookup_at_z);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.table_at_z);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        // + u* w0(zomega) + u*v z(zomega) + u*v2 s(zomega) + u*v3 zlookup(zomega)
        aggregation_challenge.assign(state.u);
        tmp_fr.assign(proof.wire0_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.grand_product_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.sorted_lookup_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.grand_product_lookup_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);
        // + u*v4 table(zomega)
        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.table_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        // + uv5 * w2(zomega) + uv6 * z_substring(zomega)
        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.wire2_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.z_substring_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        // e(z[Wz] +uzw[Wzw] +[F] -e[1], g2) = e([Wz] +u[Wzw], g2_x)
        commitment_aggregation.point_sub_assign(
            PairingsBn254.P1().point_mul(aggregated_value)
        );

        commitment_aggregation.point_add_assign(
            proof.opening_at_z_proof.point_mul(state.z)
        );

        tmp_fr.assign(state.z);
        tmp_fr.mul_assign(vk.omega);
        tmp_fr.mul_assign(state.u);
        commitment_aggregation.point_add_assign(
            proof.opening_at_z_omega_proof.point_mul(tmp_fr)
        );

        PairingsBn254.G1Point memory pair_with_x = proof
            .opening_at_z_omega_proof
            .point_mul(state.u);
        pair_with_x.point_add_assign(proof.opening_at_z_proof);
        pair_with_x.negate();

        return
            PairingsBn254.pairingProd2(
                commitment_aggregation,
                PairingsBn254.P2(),
                pair_with_x,
                vk.g2_x
            );
    }

    /** `verify_initial` prepares the verifier state (by reading the proof,
     *   generating the challenges along the way, and batch evaluating largange polynomials),
     *   and calls `verify_at_z` which performs the finite-field part of the verification*/
    function verify_initial(
        PartialVerifierState memory state,
        Proof memory proof,
        VerificationKey memory vk,
        bytes32 vkhash
    ) internal view returns (bool, PairingsBn254.Fr memory return_zeta_pow_n) {
        require(proof.input_values.length == vk.num_inputs);
        // require(vk.num_inputs >= 1);
        TranscriptLibrary.Transcript memory transcript = TranscriptLibrary
            .new_transcript();

        // add srshash first
        transcript.update_with_u256(uint256(srshash));

        // add circuit
        transcript.update_with_u256(uint256(vkhash));

        for (uint256 i = 0; i < vk.num_inputs; ++i) {
            transcript.update_with_u256(proof.input_values[i]);
        }

        //step 1
        for (uint256 i = 0; i < STATE_WIDTH; ++i) {
            transcript.update_with_g1(proof.wire_commitments[i]);
        }
        state.eta = transcript.get_challenge();

        //step 2
        transcript.update_with_g1(proof.sorted_lookup_commitment);
        state.beta = transcript.get_challenge();
        state.gamma = transcript.get_challenge();

        //step 3
        transcript.update_with_g1(proof.grand_product_commitment);
        transcript.update_with_g1(proof.z_substring_commitment);
        state.beta_1 = transcript.get_challenge();
        state.gamma_1 = transcript.get_challenge();
        transcript.update_with_g1(proof.grand_product_lookup_commitment);
        state.alpha = transcript.get_challenge();

        //step 4
        for (uint256 i = 0; i < STATE_WIDTH; ++i) {
            transcript.update_with_g1(proof.quotient_poly_commitments[i]);
        }
        state.z = transcript.get_challenge();

        // we need L0 even there's no pubinput
        uint256 tmp = 0;
        if (vk.num_inputs == 0) {
            tmp = 1;
        }

        uint256[] memory lagrange_poly_numbers = new uint256[](
            vk.num_inputs + tmp
        );
        uint256 lagrange_poly_len = lagrange_poly_numbers.length;
        for (uint256 i = 0; i < lagrange_poly_len; ++i) {
            lagrange_poly_numbers[i] = i;
        }

        (
            state.cached_lagrange_evals,
            // state.cached_lagrange_eval_Ln,
            return_zeta_pow_n
        ) = batch_evaluate_lagrange_poly_out_of_domain(
            lagrange_poly_numbers.length,
            vk.domain_size,
            vk.omega,
            state.z
        );

        bool valid = verify_at_z(return_zeta_pow_n, state, proof);
        if (valid == false) {
            return (false, return_zeta_pow_n);
        }

        //add evaluations z
        transcript.update_with_fr(proof.quotient_polynomial_at_z);
        transcript.update_with_fr(proof.linearization_polynomial_at_z);
        for (uint256 i = 0; i < STATE_WIDTH; ++i) {
            transcript.update_with_fr(proof.wire_values_at_z[i]);
        }
        for (uint256 i = 0; i < STATE_WIDTH - 1; ++i) {
            transcript.update_with_fr(proof.permutation_polynomials_at_z[i]);
        }
        transcript.update_with_fr(proof.q_table_at_z);
        transcript.update_with_fr(proof.q_lookup_at_z);
        transcript.update_with_fr(proof.table_at_z);

        //add evaluations zw
        transcript.update_with_fr(proof.wire0_at_z_omega);
        transcript.update_with_fr(proof.grand_product_at_z_omega);
        transcript.update_with_fr(proof.sorted_lookup_at_z_omega);
        transcript.update_with_fr(proof.grand_product_lookup_at_z_omega);
        transcript.update_with_fr(proof.table_at_z_omega);
        transcript.update_with_fr(proof.wire2_at_z_omega);
        transcript.update_with_fr(proof.z_substring_at_z_omega);

        state.v = transcript.get_challenge();

        //add Wz, Wzw
        transcript.update_with_g1(proof.opening_at_z_proof);
        transcript.update_with_g1(proof.opening_at_z_omega_proof);
        state.u = transcript.get_challenge();

        return (true, return_zeta_pow_n);
    }

    // This verifier is for a PLONK with a state width 5
    /**
     * A plonk verifier does two kinds of verifications:
     * 1. target identity holds in Fr, handled by `verify_initial`
     * 2. polynomial commitment openings are correct, handled by `verify_commitments`
     */
    function verify(
        Proof memory proof,
        VerificationKey memory vk,
        bytes32 vkhash
    ) internal view returns (bool) {
        PartialVerifierState memory state;

        (
            bool valid,
            PairingsBn254.Fr memory return_zeta_pow_n
        ) = verify_initial(state, proof, vk, vkhash);

        if (valid == false) {
            return false;
        }

        valid = verify_commitments(return_zeta_pow_n, state, proof, vk);

        return valid;
    }
}
