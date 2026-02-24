# **Internet-exposed breach paths to S3 and RDS from CLI in minutes**

- Reason through security boundaries across encryption, access, and network layers to see break points an adversary can exploit to exfiltrate data
- Every step of the path is validated via KMS eval + IAM sim + network eval

## Algorithm

Crown Jewels <-- IAM Permissions <-- Internet Entry Points:

S3 exposure
1. **Auto-identify crown jewels**: Detect critical DBs per tags, encryption heuristics and regex
2. **Check Direct Exposure of DBs**: Determine DB exposure per policies, ACLs and PABs
3. **Split DBs into KMS vs non-KMS DBs**: Collect CMKs of KMS-encrypted buckets
4. **Find KMS-decrypting roles**: Filter KMS roles that can directly decrypt and indirectly decrypt CMKs. Indirect decryption refers to ability to generate data keys that can decrypt a CMK. Check for bucket-specifc access as well to satisfy KMS and IAM authorization. All authorization for CMK decryption and DB access is verified via AWS SimulatePrincipalPolicy.
5. **Find IAM roles for non-KMS DBs**: Filter IAM roles with wildcard DB access and ARN-specific actions. Bucket-level authorization is verified via AWS SimulatePrincipalPolicy.
6. **Form seed of risky roles**: Merge roles from prior 2 steps
7. **Check lateral movement**: Include roles that can sts:AssumeRole or iam:PassRole seed of risky roles. Authorization is verified AWS SimulatePrincipalPolicy.
8. **Check privilege escalation**: Include roles with permissions management actions.
9. **Form breach surface of principals**: Merge roles from prior 3 steps
10. **Map roles to compute workloads**: Map roles to EC2 instances and Lambda functions
11. **Check exposure of workloads**: Check if workloads are Internet-exposed based on public IP and 0.0.0.0/0 security group for EC2 instances and unauthenticated function URL for Lambdas
12. **Filter denied VPCs**: Ignore workloads whose source VPCs are explicitly denied by corresponding bucket policies in the breach path
13. **Form breach path**: Stitch results into breach path 
e.g. Internet → 🌐 Public EC2 Instance (Private) → 🖥️ web-server (i-07d683993ec1ed6c9) → 🔐 Role (web-server-role) → 🔐 Role (data-access-role) → 💎 customer-data

RDS exposure

For RDS, we apply the same reverse traversal logic but disqualify paths with password-only auth (IAMAuthEnabled=false) because that requires the adversary to compromise database credentials — SimulatePrincipalPolicy can only verify IAM-authenticated `rds-db:connect` access. Additionally, for Internet exposure, we model network boundaries accordingly:
- **NR-001**: Security group ingress — does the RDS SG allow inbound from the compute resource's SG or IP on the DB port?
- **NR-002**: VPC connectivity — are compute and RDS in different VPCs with no verified peering/transit gateway?
- **NR-003**: Private RDS + external compute — is `PubliclyAccessible=false` with compute outside the RDS VPC?
- Directly publicly accessible databases (`PubliclyAccessible=true`) are surfaced as standalone breach paths without requiring a compute intermediary.


## Outcome

Our traversal logic and heuristics are portable for teams to build exposure, lateral movement and privilege escalation detection without relying on vendor limitations or blindspots to tribal knowledge of critical DBs

## Functions to run (go v1.23.0)

`go run ./cmd/breachsurfacer`

## Crown Jewel Customization

If you already know which resources are sensitive, add their ARNs to `internal/crownjewels/arn_jewels.yaml`:

```yaml
arn_jewels:
  - arn:aws:s3:::my-sensitive-data-bucket
  - arn:aws:rds:::my-sensitive-data-db
```

Any resource whose ARN appears here is classified as a crown jewel unconditionally — bypassing the tag, encryption, and regex heuristics in `crown_jewels.yaml`. This is useful for resources that don't follow naming conventions or lack KMS encryption but are still critical.
