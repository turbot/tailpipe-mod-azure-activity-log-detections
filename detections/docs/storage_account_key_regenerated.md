## Overview

Detect when an access key for an Azure Storage account was regenerated. Regenerating storage account keys can impact applications and services relying on the old key, potentially causing downtime or unauthorized access if the new key is not securely distributed. Monitoring these events ensures operational continuity and strengthens security by detecting unauthorized or unplanned changes.

**References**:
- [Azure Storage Account Access Keys](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage)
- [Azure CLI Command: az storage account keys renew](https://learn.microsoft.com/en-us/cli/azure/storage/account/keys#az-storage-account-keys-renew)
- [Azure Storage Security Guide](https://learn.microsoft.com/en-us/azure/storage/blobs/security-recommendations#identity-and-access-management)
