// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;
import {Vault} from "./Vault.sol";
import {DHC} from "./DHC.sol";

contract Setup {
    Vault public vault;
    DHC public dhc;
    address public solver;
    bool public minted;

    constructor() {
        dhc = new DHC("");
        
        vault = new Vault(1e18);
        vault.registerToken(address(dhc));
    }

    function free(uint256 tokenId) external {
        require(!minted, "already minted");
        minted = true;
        solver = msg.sender;
        dhc.mint(msg.sender, tokenId, 1e10, "");
    }

    function isSolved() public view returns (bool) {
        if (vault.balanceOf(solver) < 5e17) {
            return false;
        }
        return true;
    }
}
