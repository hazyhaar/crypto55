// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

contract OneStepEVM {
    struct StepWitness {
        bytes32 preStateRoot;
        bytes32 postStateRoot;
        uint32 pc;
        uint8 opcode;
        uint64 gas;
        uint256[4] stackIn;
        uint256[4] stackOut;
        uint32 memOffset;
        bytes32 memData;
        uint256 storageKey;
        uint256 storageVal;
    }

    function executeOneStep(StepWitness calldata w)
        external
        pure
        returns (bool success, bytes32 newRoot, uint64 gasRemaining)
    {
        if (
            w.preStateRoot
                != _hashState(
                    w.pc, w.gas, w.stackIn, w.memOffset, w.memData, w.storageKey, w.storageVal
                )
        ) {
            return (false, bytes32(0), 0);
        }

        (bool ok, uint32 newPc, uint64 newGas, uint256[4] memory outStack, bytes32 outMem) =
            _exec(w);
        if (!ok) {
            return (false, bytes32(0), 0);
        }
        for (uint256 i = 0; i < 4; i++) {
            if (outStack[i] != w.stackOut[i]) {
                return (false, bytes32(0), 0);
            }
        }
        bytes32 root = _hashState(
            newPc, newGas, outStack, w.memOffset, outMem, w.storageKey, w.storageVal
        );
        if (root != w.postStateRoot) {
            return (false, bytes32(0), 0);
        }
        return (true, root, newGas);
    }

    function _hashState(
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

    function _exec(StepWitness calldata w)
        internal
        pure
        returns (bool ok, uint32 newPc, uint64 newGas, uint256[4] memory outStack, bytes32 outMem)
    {
        uint64 cost = _baseCost(w.opcode);
        if (cost == type(uint64).max || w.gas < cost) {
            return (false, 0, 0, outStack, w.memData);
        }
        newGas = w.gas - cost;
        newPc = w.pc + 1;
        outMem = w.memData;
        uint8 op = w.opcode;

        if (op == 0x01) {
            outStack[0] = _add(w.stackIn[0], w.stackIn[1]);
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x02) {
            outStack[0] = _mul(w.stackIn[0], w.stackIn[1]);
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x03) {
            outStack[0] = _sub(w.stackIn[0], w.stackIn[1]);
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x04) {
            outStack[0] = w.stackIn[1] == 0 ? 0 : w.stackIn[0] / w.stackIn[1];
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x16) {
            outStack[0] = w.stackIn[0] & w.stackIn[1];
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x17) {
            outStack[0] = w.stackIn[0] | w.stackIn[1];
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x18) {
            outStack[0] = w.stackIn[0] ^ w.stackIn[1];
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x1b) {
            outStack[0] = _shl(w.stackIn[1], w.stackIn[0]);
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x1c) {
            outStack[0] = _shr(w.stackIn[1], w.stackIn[0]);
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x51) {
            (uint64 g2, bool mok) = _chargeMem(newGas, w.memOffset + 32, w.memOffset);
            if (!mok) {
                return (false, 0, 0, outStack, outMem);
            }
            if (uint256(w.memOffset) != w.stackIn[0]) {
                return (false, 0, 0, outStack, outMem);
            }
            outStack[0] = uint256(w.memData);
            return (true, newPc, g2, outStack, outMem);
        }
        if (op == 0x52) {
            (uint64 g2, bool mok) = _chargeMem(newGas, 0, w.memOffset);
            if (!mok) {
                return (false, 0, 0, outStack, outMem);
            }
            if (uint256(w.memOffset) != w.stackIn[1]) {
                return (false, 0, 0, outStack, outMem);
            }
            outMem = bytes32(w.stackIn[0]);
            return (true, newPc, g2, outStack, outMem);
        }
        if (op == 0x54) {
            if (w.stackIn[0] != w.storageKey) {
                return (false, 0, 0, outStack, outMem);
            }
            outStack[0] = w.storageVal;
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x55) {
            if (w.stackIn[1] != w.storageKey || w.stackIn[0] != w.storageVal) {
                return (false, 0, 0, outStack, outMem);
            }
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op == 0x56) {
            if (w.stackIn[0] > type(uint32).max) {
                return (false, 0, 0, outStack, outMem);
            }
            return (true, uint32(w.stackIn[0]), newGas, outStack, outMem);
        }
        if (op == 0x57) {
            if (w.stackIn[0] != 0) {
                if (w.stackIn[1] > type(uint32).max) {
                    return (false, 0, 0, outStack, outMem);
                }
                return (true, uint32(w.stackIn[1]), newGas, outStack, outMem);
            }
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op >= 0x5f && op <= 0x7f) {
            uint8 n = op - 0x5f;
            newPc = w.pc + 1 + uint32(n);
            outStack[0] = uint256(w.memData);
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op >= 0x80 && op <= 0x82) {
            uint8 n = op - 0x80 + 1;
            for (uint8 i = 0; i < n; i++) {
                outStack[i] = w.stackIn[i];
            }
            outStack[n] = w.stackIn[0];
            return (true, newPc, newGas, outStack, outMem);
        }
        if (op >= 0x90 && op <= 0x92) {
            uint8 n = op - 0x90 + 1;
            uint8 arity = n + 1;
            for (uint8 i = 0; i < arity; i++) {
                outStack[i] = w.stackIn[i];
            }
            uint256 t = outStack[arity - 1];
            outStack[arity - 1] = outStack[arity - 1 - n];
            outStack[arity - 1 - n] = t;
            return (true, newPc, newGas, outStack, outMem);
        }
        return (false, 0, 0, outStack, outMem);
    }

    function _baseCost(uint8 op) internal pure returns (uint64) {
        if (op == 0x01 || op == 0x03) return 3;
        if (op == 0x02 || op == 0x04) return 5;
        if (op == 0x16 || op == 0x17 || op == 0x18 || op == 0x1b || op == 0x1c) return 3;
        if (op == 0x51 || op == 0x52) return 3;
        if (op == 0x54) return 800;
        if (op == 0x55) return 5000;
        if (op == 0x56) return 8;
        if (op == 0x57) return 10;
        if (op == 0x5f) return 2;
        if (op >= 0x60 && op <= 0x7f) return 3;
        if (op >= 0x80 && op <= 0x82) return 3;
        if (op >= 0x90 && op <= 0x92) return 3;
        return type(uint64).max;
    }

    function _add(uint256 a, uint256 b) internal pure returns (uint256 r) {
        unchecked {
            r = a + b;
        }
    }

    function _sub(uint256 a, uint256 b) internal pure returns (uint256 r) {
        unchecked {
            r = a - b;
        }
    }

    function _mul(uint256 a, uint256 b) internal pure returns (uint256 r) {
        unchecked {
            r = a * b;
        }
    }

    function _shl(uint256 shift, uint256 value) internal pure returns (uint256) {
        if (shift >= 256) {
            return 0;
        }
        return value << shift;
    }

    function _shr(uint256 shift, uint256 value) internal pure returns (uint256) {
        if (shift >= 256) {
            return 0;
        }
        return value >> shift;
    }

    function _memGas(uint256 words) internal pure returns (uint256) {
        return 3 * words + (words * words) / 512;
    }

    function _chargeMem(uint64 gas, uint32 memSize, uint32 offset)
        internal
        pure
        returns (uint64 newGas, bool ok)
    {
        uint256 end = uint256(offset) + 32;
        uint256 words = (end + 31) / 32;
        uint256 newSize = words * 32;
        if (newSize <= memSize) {
            return (gas, true);
        }
        uint256 oldWords = (uint256(memSize) + 31) / 32;
        uint256 oldCost = _memGas(oldWords);
        uint256 newCost = _memGas(words);
        if (newCost < oldCost) {
            return (0, false);
        }
        uint256 delta = newCost - oldCost;
        if (gas < delta) {
            return (0, false);
        }
        return (gas - uint64(delta), true);
    }
}
