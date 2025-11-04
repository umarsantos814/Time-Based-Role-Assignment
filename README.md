# ⏰ Time-Based Role Assignment Contract

A Clarity smart contract that implements temporary role assignments with automatic expiration. Perfect for learning about time-based permissions and role management in blockchain applications! 🚀

## 🌟 Features

- ⏳ **Temporary Roles**: Assign roles that automatically expire after a set duration
- 🔐 **Permission System**: Different roles have different capabilities
- 👥 **Multiple Role Types**: Admin, Moderator, Member, and Viewer roles
- 🔄 **Role Extension**: Extend role duration before expiration
- 🧹 **Cleanup Function**: Remove expired roles to keep the contract clean
- 📊 **Role Tracking**: Monitor active roles and permissions

## 🎯 Role Types & Permissions

| Role | Can Assign | Can Revoke | Can View Users | Can Moderate |
|------|------------|------------|----------------|--------------|
| 👑 **Admin** | ✅ | ✅ | ✅ | ✅ |
| 🛡️ **Moderator** | ❌ | ❌ | ✅ | ✅ |
| 👤 **Member** | ❌ | ❌ | ✅ | ❌ |
| 👁️ **Viewer** | ❌ | ❌ | ❌ | ❌ |

## 🚀 Quick Start

### Deploy the Contract

```bash
clarinet deploy
```

### Basic Usage Examples

#### Assign a Role
```clarity
(contract-call? .time-based-role-assignment assign-role 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM u2 u1000)
```

#### Check if Role is Active
```clarity
(contract-call? .time-based-role-assignment is-user-role-active 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM u2)
```

#### Get Time Remaining
```clarity
(contract-call? .time-based-role-assignment get-role-time-remaining 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM u2)
```

## 📋 Public Functions

### 🔧 Core Functions

- **`assign-role`** - Assign a temporary role to a user
- **`revoke-role`** - Immediately revoke a user's role
- **`extend-role`** - Extend the duration of an existing role
- **`cleanup-expired-role`** - Remove an expired role from storage

### 📖 Read-Only Functions

- **`get-user-role`** - Get role details for a specific user
- **`is-user-role-active`** - Check if a user's role is currently active
- **`get-role-permissions`** - Get permissions for a specific role type
- **`can-user-perform-action`** - Check if user can perform a specific action
- **`get-role-time-remaining`** - Get blocks remaining until role expires
- **`get-total-active-roles`** - Get count of all active roles
- **`get-contract-info`** - Get general contract information

## 🔢 Role Constants

- **Admin**: `u1` 👑
- **Moderator**: `u2` 🛡️
- **Member**: `u3` 👤
- **Viewer**: `u4` 👁️

## ⚡ Duration Limits

- **Minimum Duration**: 1 block
- **Maximum Duration**: 52,560,000 blocks (~10 years)

## 🎓 Learning Objectives

This contract teaches:
- ⏰ Time-based logic in smart contracts
- 🔐 Role-based access control (RBAC)
- 📊 Data structure management with maps
- 🔄 State management and cleanup patterns
- 🛡️ Permission validation systems

## 🧪 Testing

Run the test suite:

```bash
clarinet test
```

## 🤝 Contributing

Feel free to submit issues and enhancement requests! 

## 📄 License

This project is open source and available under the MIT License.

---

Built with ❤️ using Clarity and Clarinet
```

**Git Commit Message:**
```
feat: implement time-based role assignment MVP with expiring permissions
```

**GitHub Pull Request Title:**
```
🚀 Add Time-Based Role Assignment Contract MVP
```

**GitHub Pull Request Description:**
```
## 🎯 Overview
Added a complete Time-Based Role Assignment smart contract that demonstrates temporary role management with automatic expiration.

## ✨ What's Added
- **Core Contract**: Complete Clarity implementation with role assignment, revocation, and extension
- **Permission System**: 4 role types (Admin, Moderator, Member, Viewer) with different capabilities  
- **Time Management**: Roles expire automatically after set duration
- **Cleanup Functions**: Remove expired roles to maintain contract efficiency
- **Comprehensive README**: Full documentation with usage examples and emojis

## 🔧 Key Features
- ⏳ Temporary role assignments (1 block to ~10 years)
- 🔐 Permission-based access control
- 🧹 Expired role cleanup functionality
- 📊 Role tracking and monitoring
- 🛡️ Authorization validation

## 📚 Learning Value
Perfect for understanding time-based smart contract logic, role-based access control, and state management patterns in Clarity.

Ready for immediate deployment and testing! 🚀

