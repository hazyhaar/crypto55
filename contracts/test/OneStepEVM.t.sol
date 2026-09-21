// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import "../OneStepEVM.sol";

/// @dev Standalone test suite (without forge-std) for OneStepEVM.
///      Any assertion failure reverts via require, which Foundry interprets
///      as a failing test case.
contract OneStepEVMTest {
    OneStepEVM internal evm;

    // ------------------------------------------------------------------
    // Witness construction helpers
    // ------------------------------------------------------------------

    /// @dev Exact replica of OneStepEVM._hashState.
    function _h(
        uint32 pc,
        uint64 gas,
        uint256[4] memory stack,
        uint32 memOffset,
        bytes32 memData,
        uint256 storageKey,
        uint256 storageVal
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(pc, gas, stack, memOffset, memData, storageKey, storageVal));
    }

    /// @dev Assemble a raw witness from explicitly provided roots.
    function _build(
        bytes32 preRoot,
        bytes32 postRoot,
        uint32 pc,
        uint8 op,
        uint64 gas,
        uint256[4] memory sin,
        uint256[4] memory sout,
        uint32 memOffset,
        bytes32 memData,
        uint256 storageKey,
        uint256 storageVal
    ) internal pure returns (OneStepEVM.StepWitness memory w) {
        w.preStateRoot = preRoot;
        w.postStateRoot = postRoot;
        w.pc = pc;
        w.opcode = op;
        w.gas = gas;
        w.stackIn = sin;
        w.stackOut = sout;
        w.memOffset = memOffset;
        w.memData = memData;
        w.storageKey = storageKey;
        w.storageVal = storageVal;
    }

    /// @dev Assemble a witness whose pre/post roots are computed from
    ///      the provided state (pre = input, post = expected output).
    function _buildValid(
        uint32 pc,
        uint8 op,
        uint64 gas,
        uint256[4] memory sin,
        uint256[4] memory sout,
        uint32 memOffset,
        bytes32 memData,
        uint256 storageKey,
        uint256 storageVal,
        uint32 newPc,
        uint64 newGas,
        bytes32 newMem
    ) internal pure returns (OneStepEVM.StepWitness memory w) {
        bytes32 pre = _h(pc, gas, sin, memOffset, memData, storageKey, storageVal);
        bytes32 post = _h(newPc, newGas, sout, memOffset, newMem, storageKey, storageVal);
        return _build(
            pre, post, pc, op, gas, sin, sout, memOffset, memData, storageKey, storageVal
        );
    }

    function _expectSuccess(OneStepEVM.StepWitness memory w, bytes32 expRoot, uint64 expGas)
        internal
        view
    {
        (bool ok, bytes32 root, uint64 g) = evm.executeOneStep(w);
        require(ok, "attendu: succes");
        require(root == expRoot, "racine post incorrecte");
        require(g == expGas, "gas restant incorrect");
    }

    function _expectReject(OneStepEVM.StepWitness memory w) internal view {
        (bool ok, bytes32 root, uint64 g) = evm.executeOneStep(w);
        require(!ok, "attendu: rejet");
        require(root == bytes32(0), "racine de rejet non nulle");
        require(g == 0, "gas de rejet non nul");
    }

    function setUp() public {
        evm = new OneStepEVM();
    }

    // ------------------------------------------------------------------
    // Arithmetique
    // ------------------------------------------------------------------

    function test_Add() public {
        uint256[4] memory sin;
        sin[0] = 2;
        sin[1] = 3;
        uint256[4] memory sout;
        sout[0] = 5;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x01, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Add_OverflowWraps() public {
        uint256[4] memory sin;
        sin[0] = type(uint256).max;
        sin[1] = 1;
        uint256[4] memory sout;
        sout[0] = 0;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x01, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Mul() public {
        uint256[4] memory sin;
        sin[0] = 6;
        sin[1] = 7;
        uint256[4] memory sout;
        sout[0] = 42;
        bytes32 post = _h(1, 95, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x02, 100, sin, sout, 0, 0, 0, 0, 1, 95, bytes32(0)), post, 95
        );
    }

    function test_Sub() public {
        uint256[4] memory sin;
        sin[0] = 10;
        sin[1] = 3;
        uint256[4] memory sout;
        sout[0] = 7;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x03, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Sub_UnderflowWraps() public {
        uint256[4] memory sin;
        sin[0] = 3;
        sin[1] = 10;
        uint256[4] memory sout;
        sout[0] = type(uint256).max - 6; // 3 - 10 en mod 2^256
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x03, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Div() public {
        uint256[4] memory sin;
        sin[0] = 10;
        sin[1] = 3;
        uint256[4] memory sout;
        sout[0] = 3;
        bytes32 post = _h(1, 95, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x04, 100, sin, sout, 0, 0, 0, 0, 1, 95, bytes32(0)), post, 95
        );
    }

    function test_Div_ByZeroIsZero() public {
        uint256[4] memory sin;
        sin[0] = 10;
        sin[1] = 0;
        uint256[4] memory sout;
        sout[0] = 0;
        bytes32 post = _h(1, 95, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x04, 100, sin, sout, 0, 0, 0, 0, 1, 95, bytes32(0)), post, 95
        );
    }

    // ------------------------------------------------------------------
    // Logique binaire
    // ------------------------------------------------------------------

    function test_And() public {
        uint256[4] memory sin;
        sin[0] = 0xff0f;
        sin[1] = 0x0ff0;
        uint256[4] memory sout;
        sout[0] = 0x0f00;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x16, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Or() public {
        uint256[4] memory sin;
        sin[0] = 0xff0f;
        sin[1] = 0x0ff0;
        uint256[4] memory sout;
        sout[0] = 0xffff;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x17, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Xor() public {
        uint256[4] memory sin;
        sin[0] = 0xff0f;
        sin[1] = 0x0ff0;
        uint256[4] memory sout;
        sout[0] = 0xf0ff;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x18, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Shl() public {
        // value = stackIn[0], shift = stackIn[1]
        uint256[4] memory sin;
        sin[0] = 1;
        sin[1] = 4;
        uint256[4] memory sout;
        sout[0] = 16;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x1b, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Shl_ShiftGe256IsZero() public {
        uint256[4] memory sin;
        sin[0] = type(uint256).max;
        sin[1] = 256;
        uint256[4] memory sout;
        sout[0] = 0;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x1b, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Shl_ShiftHugeIsZero() public {
        uint256[4] memory sin;
        sin[0] = type(uint256).max;
        sin[1] = type(uint256).max;
        uint256[4] memory sout;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x1b, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Shr() public {
        uint256[4] memory sin;
        sin[0] = 256;
        sin[1] = 4;
        uint256[4] memory sout;
        sout[0] = 16;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x1c, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Shr_ShiftGe256IsZero() public {
        uint256[4] memory sin;
        sin[0] = type(uint256).max;
        sin[1] = 256;
        uint256[4] memory sout;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x1c, 100, sin, sout, 0, 0, 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    // ------------------------------------------------------------------
    // Memoire
    // ------------------------------------------------------------------

    function test_Mload() public {
        bytes32 md = bytes32(uint256(0xdeadbeef));
        uint256[4] memory sin;
        sin[0] = 0; // offset attendu
        uint256[4] memory sout;
        sout[0] = uint256(md);
        bytes32 post = _h(1, 97, sout, 0, md, 0, 0);
        _expectSuccess(_buildValid(0, 0x51, 100, sin, sout, 0, md, 0, 0, 1, 97, md), post, 97);
    }

    function test_Mload_Offset32() public {
        bytes32 md = bytes32(uint256(0x1234));
        uint256[4] memory sin;
        sin[0] = 32;
        uint256[4] memory sout;
        sout[0] = uint256(md);
        bytes32 post = _h(1, 97, sout, 32, md, 0, 0);
        _expectSuccess(_buildValid(0, 0x51, 100, sin, sout, 32, md, 0, 0, 1, 97, md), post, 97);
    }

    function test_Mload_WrongOffsetRejected() public {
        bytes32 md = bytes32(uint256(0xdead));
        uint256[4] memory sin;
        sin[0] = 0; // ne correspond pas a memOffset = 32
        uint256[4] memory sout;
        sout[0] = uint256(md);
        _expectReject(
            _buildValid(0, 0x51, 100, sin, sout, 32, md, 0, 0, 1, 97, md)
        );
    }

    function test_Mstore() public {
        uint256 val = 0xabcdef;
        uint256[4] memory sin;
        sin[0] = val;
        sin[1] = 0; // offset attendu
        uint256[4] memory sout; // sortie vide
        bytes32 nmem = bytes32(val);
        bytes32 post = _h(1, 94, sout, 0, nmem, 0, 0);
        _expectSuccess(_buildValid(0, 0x52, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 94, nmem), post, 94);
    }

    function test_Mstore_Offset32() public {
        uint256 val = 0x99;
        uint256[4] memory sin;
        sin[0] = val;
        sin[1] = 32;
        uint256[4] memory sout;
        bytes32 nmem = bytes32(val);
        // base 3 + mem (2 mots => 6) = 9 ; 100 - 9 = 91
        bytes32 post = _h(1, 91, sout, 32, nmem, 0, 0);
        _expectSuccess(
            _buildValid(0, 0x52, 100, sin, sout, 32, bytes32(0), 0, 0, 1, 91, nmem), post, 91
        );
    }

    function test_Mstore_OutOfGasForMemoryRejected() public {
        uint256[4] memory sin;
        sin[0] = 0x55;
        sin[1] = 0;
        uint256[4] memory sout;
        // gas = 3 couvre juste le cout de base, la facturation memoire echoue
        _expectReject(_buildValid(0, 0x52, 3, sin, sout, 0, bytes32(0), 0, 0, 1, 0, bytes32(0)));
    }

    function test_Mstore_WrongOffsetRejected() public {
        uint256[4] memory sin;
        sin[0] = 0x55;
        sin[1] = 0; // ne correspond pas a memOffset = 32
        uint256[4] memory sout;
        _expectReject(
            _buildValid(0, 0x52, 100, sin, sout, 32, bytes32(0), 0, 0, 1, 91, bytes32(uint256(0x55)))
        );
    }

    // ------------------------------------------------------------------
    // Stockage
    // ------------------------------------------------------------------

    function test_Sload() public {
        uint256 sk = 7;
        uint256 sv = 0x123456;
        uint256[4] memory sin;
        sin[0] = sk;
        uint256[4] memory sout;
        sout[0] = sv;
        bytes32 post = _h(1, 200, sout, 0, bytes32(0), sk, sv);
        _expectSuccess(
            _buildValid(0, 0x54, 1000, sin, sout, 0, bytes32(0), sk, sv, 1, 200, bytes32(0)),
            post,
            200
        );
    }

    function test_Sload_WrongKeyRejected() public {
        uint256[4] memory sin;
        sin[0] = 5;
        uint256[4] memory sout;
        sout[0] = 0x123456;
        _expectReject(
            _buildValid(0, 0x54, 1000, sin, sout, 0, bytes32(0), 6, 0x123456, 1, 200, bytes32(0))
        );
    }

    function test_Sstore() public {
        uint256 sk = 9;
        uint256 sv = 0xfeed;
        uint256[4] memory sin;
        sin[0] = sv;
        sin[1] = sk;
        uint256[4] memory sout;
        bytes32 post = _h(1, 1000, sout, 0, bytes32(0), sk, sv);
        _expectSuccess(
            _buildValid(0, 0x55, 6000, sin, sout, 0, bytes32(0), sk, sv, 1, 1000, bytes32(0)),
            post,
            1000
        );
    }

    function test_Sstore_WrongKeyRejected() public {
        uint256 sk = 9;
        uint256 sv = 0xfeed;
        uint256[4] memory sin;
        sin[0] = sv;
        sin[1] = sk + 1; // cle erronee
        uint256[4] memory sout;
        _expectReject(
            _buildValid(0, 0x55, 6000, sin, sout, 0, bytes32(0), sk, sv, 1, 1000, bytes32(0))
        );
    }

    function test_Sstore_WrongValueRejected() public {
        uint256 sk = 9;
        uint256 sv = 0xfeed;
        uint256[4] memory sin;
        sin[0] = sv + 1; // valeur erronee
        sin[1] = sk;
        uint256[4] memory sout;
        _expectReject(
            _buildValid(0, 0x55, 6000, sin, sout, 0, bytes32(0), sk, sv, 1, 1000, bytes32(0))
        );
    }

    // ------------------------------------------------------------------
    // Controle de flux
    // ------------------------------------------------------------------

    function test_Jump() public {
        uint256 dest = 1234;
        uint256[4] memory sin;
        sin[0] = dest;
        uint256[4] memory sout;
        bytes32 post = _h(1234, 92, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x56, 100, sin, sout, 0, bytes32(0), 0, 0, 1234, 92, bytes32(0)),
            post,
            92
        );
    }

    function test_Jump_DestinationTooLargeRejected() public {
        uint256[4] memory sin;
        sin[0] = uint256(type(uint32).max) + 1;
        uint256[4] memory sout;
        _expectReject(_buildValid(0, 0x56, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 92, bytes32(0)));
    }

    function test_Jumpi_Taken() public {
        uint256 dest = 77;
        uint256[4] memory sin;
        sin[0] = 1; // condition non nulle
        sin[1] = dest;
        uint256[4] memory sout;
        bytes32 post = _h(77, 90, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x57, 100, sin, sout, 0, bytes32(0), 0, 0, 77, 90, bytes32(0)),
            post,
            90
        );
    }

    function test_Jumpi_NotTaken() public {
        uint256[4] memory sin;
        sin[0] = 0; // condition nulle
        sin[1] = 77;
        uint256[4] memory sout;
        bytes32 post = _h(1, 90, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x57, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 90, bytes32(0)),
            post,
            90
        );
    }

    function test_Jumpi_TakenOversizedRejected() public {
        uint256[4] memory sin;
        sin[0] = 1;
        sin[1] = uint256(type(uint32).max) + 1;
        uint256[4] memory sout;
        _expectReject(_buildValid(0, 0x57, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 90, bytes32(0)));
    }

    // ------------------------------------------------------------------
    // PUSH0..32
    // ------------------------------------------------------------------

    function test_Push0() public {
        bytes32 md = bytes32(uint256(0xaa));
        uint256[4] memory sin;
        uint256[4] memory sout;
        sout[0] = uint256(md);
        bytes32 post = _h(1, 98, sout, 0, md, 0, 0);
        _expectSuccess(_buildValid(0, 0x5f, 100, sin, sout, 0, md, 0, 0, 1, 98, md), post, 98);
    }

    function test_AllPushOpcodes() public {
        for (uint8 op = 0x5f; op <= 0x7f; op++) {
            uint8 n = op - 0x5f;
            bytes32 md = bytes32(uint256(0xabc) + n);
            uint64 cost = (op == 0x5f) ? 2 : 3;
            uint64 gas = 1000;
            uint32 npc = 5 + 1 + uint32(n);
            uint256[4] memory sin;
            uint256[4] memory sout;
            sout[0] = uint256(md);
            bytes32 post = _h(npc, gas - cost, sout, 0, md, 0, 0);
            _expectSuccess(
                _buildValid(5, op, gas, sin, sout, 0, md, 0, 0, npc, gas - cost, md), post, gas - cost
            );
        }
    }

    // ------------------------------------------------------------------
    // DUP1..3
    // ------------------------------------------------------------------

    function test_Dup1() public {
        uint256[4] memory sin;
        sin[0] = 7;
        sin[1] = 8;
        sin[2] = 9;
        sin[3] = 10;
        uint256[4] memory sout;
        sout[0] = 7;
        sout[1] = 7;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x80, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Dup2() public {
        uint256[4] memory sin;
        sin[0] = 7;
        sin[1] = 8;
        sin[2] = 9;
        sin[3] = 10;
        uint256[4] memory sout;
        sout[0] = 7;
        sout[1] = 8;
        sout[2] = 7;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x81, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Dup3() public {
        uint256[4] memory sin;
        sin[0] = 7;
        sin[1] = 8;
        sin[2] = 9;
        sin[3] = 10;
        uint256[4] memory sout;
        sout[0] = 7;
        sout[1] = 8;
        sout[2] = 9;
        sout[3] = 7;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x82, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    // ------------------------------------------------------------------
    // SWAP1..3
    // ------------------------------------------------------------------

    function test_Swap1() public {
        uint256[4] memory sin;
        sin[0] = 1;
        sin[1] = 2;
        sin[2] = 3;
        sin[3] = 4;
        uint256[4] memory sout;
        sout[0] = 2;
        sout[1] = 1;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x90, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Swap2() public {
        uint256[4] memory sin;
        sin[0] = 1;
        sin[1] = 2;
        sin[2] = 3;
        sin[3] = 4;
        uint256[4] memory sout;
        sout[0] = 3;
        sout[1] = 2;
        sout[2] = 1;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x91, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    function test_Swap3() public {
        uint256[4] memory sin;
        sin[0] = 1;
        sin[1] = 2;
        sin[2] = 3;
        sin[3] = 4;
        uint256[4] memory sout;
        sout[0] = 4;
        sout[1] = 2;
        sout[2] = 3;
        sout[3] = 1;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        _expectSuccess(
            _buildValid(0, 0x92, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 97, bytes32(0)), post, 97
        );
    }

    // ------------------------------------------------------------------
    // Rejets
    // ------------------------------------------------------------------

    function test_Reject_WrongPreStateRoot() public {
        uint256[4] memory sin;
        sin[0] = 2;
        sin[1] = 3;
        uint256[4] memory sout;
        sout[0] = 5;
        bytes32 post = _h(1, 97, sout, 0, bytes32(0), 0, 0);
        // preStateRoot volontairement faux, tout le reste valide
        _expectReject(
            _build(bytes32(uint256(0xdead)), post, 0, 0x01, 100, sin, sout, 0, bytes32(0), 0, 0)
        );
    }

    function test_Reject_WrongPostStateRoot() public {
        uint256[4] memory sin;
        sin[0] = 2;
        sin[1] = 3;
        uint256[4] memory sout;
        sout[0] = 5;
        bytes32 pre = _h(0, 100, sin, 0, bytes32(0), 0, 0);
        _expectReject(
            _build(pre, bytes32(uint256(0xbeef)), 0, 0x01, 100, sin, sout, 0, bytes32(0), 0, 0)
        );
    }

    function test_Reject_StackOutMismatch() public {
        uint256[4] memory sin;
        sin[0] = 2;
        sin[1] = 3;
        uint256[4] memory actualOut; // ADD(2,3) = 5
        actualOut[0] = 5;
        uint256[4] memory claimedOut;
        claimedOut[0] = 6; // revendication erronee
        bytes32 pre = _h(0, 100, sin, 0, bytes32(0), 0, 0);
        bytes32 post = _h(1, 97, claimedOut, 0, bytes32(0), 0, 0);
        _expectReject(_build(pre, post, 0, 0x01, 100, sin, claimedOut, 0, bytes32(0), 0, 0));
    }

    function test_Reject_InsufficientGas() public {
        uint256[4] memory sin;
        sin[0] = 2;
        sin[1] = 3;
        uint256[4] memory sout;
        sout[0] = 5;
        // gas = 2 < cout de base 3
        _expectReject(_buildValid(0, 0x01, 2, sin, sout, 0, bytes32(0), 0, 0, 1, 0, bytes32(0)));
    }

    function test_Reject_InsufficientGasSstore() public {
        uint256 sk = 1;
        uint256 sv = 2;
        uint256[4] memory sin;
        sin[0] = sv;
        sin[1] = sk;
        uint256[4] memory sout;
        // gas = 4999 < 5000
        _expectReject(
            _buildValid(0, 0x55, 4999, sin, sout, 0, bytes32(0), sk, sv, 1, 0, bytes32(0))
        );
    }

    function test_Reject_UnsupportedOpcode_0x00() public {
        uint256[4] memory sin;
        uint256[4] memory sout;
        _expectReject(_buildValid(0, 0x00, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 0, bytes32(0)));
    }

    function test_Reject_UnsupportedOpcode_0xfe() public {
        uint256[4] memory sin;
        uint256[4] memory sout;
        _expectReject(_buildValid(0, 0xfe, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 0, bytes32(0)));
    }

    function test_Reject_UnsupportedOpcode_0x05() public {
        // SDIV n'est pas implemente
        uint256[4] memory sin;
        uint256[4] memory sout;
        _expectReject(_buildValid(0, 0x05, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 0, bytes32(0)));
    }

    function test_Reject_UnsupportedOpcode_0x83() public {
        // DUP4 n'est pas implemente (plafond DUP3)
        uint256[4] memory sin;
        uint256[4] memory sout;
        _expectReject(_buildValid(0, 0x83, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 0, bytes32(0)));
    }

    function test_Reject_UnsupportedOpcode_0x93() public {
        // SWAP4 n'est pas implemente (plafond SWAP3)
        uint256[4] memory sin;
        uint256[4] memory sout;
        _expectReject(_buildValid(0, 0x93, 100, sin, sout, 0, bytes32(0), 0, 0, 1, 0, bytes32(0)));
    }
}
