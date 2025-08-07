// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "../interface/IVerifyProofAggregation.sol";

contract DarkMint is ERC20, Ownable {
    bytes32 public constant PROVING_SYSTEM_ID =
        keccak256(abi.encodePacked("sp1"));
    bytes32 public constant VERSION_HASH =
        sha256(abi.encodePacked(""));

    // zkVerify contract
    address public zkVerify;

    constructor(address _zkVerify)
        ERC20("DarkMint", "DMT")
        Ownable(msg.sender)
    {
        zkVerify = _zkVerify;
    }

    // Mapping to track used nullifiers to prevent double spending
    mapping(uint256 => bool) public nullifiers;
    mapping(bytes32 => bool) public publicInputHashesUsed; // Track used public input hashes)

    // Events
    event TokenMinted(
        address indexed recipient,
        uint256 amount,
        uint256 nullifier
    );
    event AggregationSubmitted(
        uint256 domainId,
        uint256 aggregationId,
        bytes32 proofsAggregation
    );

    function checkHash(
        bytes memory _hash,
        uint256 _aggregationId,
        uint256 _domainId,
        bytes32[] calldata _merklePath,
        uint256 _leafCount,
        uint256 _index,
        bytes32 _vkey
    ) public {
        bytes32 leaf = keccak256(
            abi.encodePacked(
                PROVING_SYSTEM_ID,
                _vkey,
                VERSION_HASH,
                keccak256(abi.encodePacked(_hash))
            )
        );

        require(
            IVerifyProofAggregation(zkVerify).verifyProofAggregation(
                _domainId,
                _aggregationId,
                leaf,
                _merklePath,
                _leafCount,
                _index
            ),
            "Invalid proof"
        );
        emit AggregationSubmitted(
            _domainId,
            _aggregationId,
            keccak256(abi.encodePacked(_hash))
        );
    }

    function mint(
        address recipient,
        uint256 amount,
        uint256 nullifier,
        bytes32[] memory publicInputHashes
    ) external {
        require(recipient != address(0), "Invalid recipient address");
        require(amount > 0, "Amount must be greater than 0");
        require(!nullifiers[nullifier], "Nullifier already used");
        require(
            !publicInputHashesUsed[
                keccak256(abi.encodePacked(publicInputHashes))
            ],
            "Public input hash already used"
        );

        // Mark nullifier as used
        nullifiers[nullifier] = true;

        // Mark public input hashes as used
        publicInputHashesUsed[
            keccak256(abi.encodePacked(publicInputHashes))
        ] = true;

        // Mint tokens to recipient
        _mint(recipient, amount);

        emit TokenMinted(recipient, amount, nullifier);
    }
}
