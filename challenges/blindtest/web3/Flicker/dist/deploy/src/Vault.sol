// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ERC20} from "../lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC1155} from "../lib/openzeppelin-contracts/contracts/token/ERC1155/IERC1155.sol";

contract Vault is ERC20 {
    enum TokenStorageOffset {
        NO_OP,
        TOKEN_ADDRESS
    }

    enum TokenStorageOffset2 {
        NO_OP,
        TOKEN_ID
    }

    address public owner;
    mapping(address token => bool registered) public registers;

    event Deposit(address indexed user, address indexed token, uint256 id, uint256 value);
    event Withdraw(address indexed user, address indexed token, uint256 id, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier onlyRegisterdToken(address token) {
        require(registers[token]);
        _;
    }

    constructor(uint256 initialSupply) ERC20("Wrapped .Hack Coin", "WDHC") {
        _mint(address(this), initialSupply);
        owner = msg.sender;
    }

    function deposit(address token, uint256 id, uint256 value) external onlyRegisterdToken(token) {
        uint8 slotNumber = uint8(TokenStorageOffset.TOKEN_ADDRESS);

        assembly {
            tstore(slotNumber, token) // store token address in order to use it in callback function
        }

        uint256 oldValue = IERC1155(token).balanceOf(address(this), id);
        IERC1155(token).safeTransferFrom(msg.sender, address(this), id, value, "");

        uint256 id_;
        slotNumber = uint8(TokenStorageOffset2.TOKEN_ID);
        assembly {
            id_ := tload(slotNumber)
        }

        // check if the id specified by the user has been successfully transferred to the vault
        require(
            IERC1155(token).balanceOf(address(this), id_) == oldValue + value,
            "Token transfer to Vault failed"
        );
        emit Deposit(msg.sender, token, id, value);
    }

    function withdraw(address token, uint256 id, uint256 value) external onlyRegisterdToken(token) {
        require(value <= IERC1155(token).balanceOf(address(this), id), "Insufficient token balance in contract");
        require(balanceOf(msg.sender) >= value, "Insufficient WMC");

        _burn(msg.sender, value);

        uint256 oldValue = IERC1155(token).balanceOf(address(this), id);
        IERC1155(token).safeTransferFrom(address(this), msg.sender, id, value, "");
        require(
            IERC1155(token).balanceOf(address(this), id) == oldValue - value,
            "Token transfer to user failed"
        );

        emit Withdraw(msg.sender, token, id, value);
    }

    function registerToken(address token) external onlyOwner {
        registers[token] = true;
    }

    function onERC1155Received(
        address,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata
    ) external returns (bytes4) {
        address token_;
        uint8 slotNumber = uint8(TokenStorageOffset.TOKEN_ADDRESS);
        assembly {
            token_ := tload(slotNumber)
        }
        require(msg.sender == token_, "Unauthorized token");

        // 1:1 mapping between DHC, WDHC
        _mint(from, value);

        uint256 id_ = id;
        slotNumber = uint8(TokenStorageOffset2.TOKEN_ID);
        assembly {
            tstore(slotNumber, id_) // store tokenId in order to use it in depoist function after calling callback function
        }

        return this.onERC1155Received.selector;
    }
}