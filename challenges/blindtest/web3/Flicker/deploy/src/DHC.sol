// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "../lib/openzeppelin-contracts/contracts/token/ERC1155/ERC1155.sol";
import "../lib/openzeppelin-contracts/contracts/access/Ownable.sol";

contract DHC is ERC1155, Ownable {
    string public baseURI;

    constructor(string memory uri_) 
        ERC1155(uri_) 
        Ownable(msg.sender) 
    {
        baseURI = uri_;
    }

    function mint(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) external onlyOwner {
        _mint(to, id, amount, data);
    }

    function mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) external onlyOwner {
        _mintBatch(to, ids, amounts, data);
    }

    function setURI(string memory newURI) external onlyOwner {
        baseURI = newURI;
        _setURI(newURI);
    }

    function uri(uint256) public view virtual override returns (string memory) {
        return baseURI;
    }
}
