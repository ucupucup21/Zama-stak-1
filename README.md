# Zama-stak-1// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title EncryptedStaking
 * @notice Encrypted staking contract example for Zama integration.
 *         Stores encrypted data on-chain, with controlled decryption.
 */
contract EncryptedStaking is AccessControl {
    bytes32 public constant DECRYPTOR_ROLE = keccak256("DECRYPTOR_ROLE");

    struct Stake {
        address owner;
        bytes encryptedAmount;
        bytes encryptedMetadata;
        bool publicDecrypt;
        uint64 createdAt;
    }

    uint256 public stakeCounter;
    mapping(uint256 => Stake) public stakes;

    event StakeSubmitted(uint256 indexed stakeId, address indexed owner);
    event PublicDecryptToggled(uint256 indexed stakeId, bool enabled);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin == address(0) ? msg.sender : admin);
        _grantRole(DECRYPTOR_ROLE, admin == address(0) ? msg.sender : admin);
    }

    function submitStake(
        bytes calldata encryptedAmount,
        bytes calldata encryptedMetadata
    ) external returns (uint256) {
        stakeCounter++;
        stakes[stakeCounter] = Stake({
            owner: msg.sender,
            encryptedAmount: encryptedAmount,
            encryptedMetadata: encryptedMetadata,
            publicDecrypt: false,
            createdAt: uint64(block.timestamp)
        });

        emit StakeSubmitted(stakeCounter, msg.sender);
        return stakeCounter;
    }

    function setPublicDecrypt(uint256 stakeId, bool enabled) external {
        Stake storage s = stakes[stakeId];
        require(s.owner == msg.sender || hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Not authorized");
        s.publicDecrypt = enabled;
        emit PublicDecryptToggled(stakeId, enabled);
    }

    function getEncryptedStake(uint256 stakeId)
        external
        view
        returns (
            bytes memory encryptedAmount,
            bytes memory encryptedMetadata,
            address owner,
            bool publicDecrypt,
            uint64 createdAt
        )
    {
        Stake storage s = stakes[stakeId];
        require(
            msg.sender == s.owner || hasRole(DECRYPTOR_ROLE, msg.sender) || s.publicDecrypt,
            "Decryption not allowed"
        );
        return (s.encryptedAmount, s.encryptedMetadata, s.owner, s.publicDecrypt, s.createdAt);
    }

    function grantDecryptor(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(DECRYPTOR_ROLE, account);
    }

    function revokeDecryptor(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _revokeRole(DECRYPTOR_ROLE, account);
    }
}
