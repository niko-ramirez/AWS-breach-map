
/*
=============================================================================
RDS ATTACK VECTORS - End-to-End Test Scenarios
=============================================================================

This file documents all RDS attack vectors that the breach surfacer tool
aims to detect and protect against. These will be converted into actual
test cases.

=============================================================================
CATEGORY 1: DIRECT PUBLIC EXPOSURE
=============================================================================

1.1 PubliclyAccessible=true with permissive security group
    - Database has PubliclyAccessible=true
    - Security group allows 0.0.0.0/0 on port 3306/5432
    - Attacker can directly connect from internet
    - SEVERITY: CRITICAL

1.2 PubliclyAccessible=true with restrictive security group
    - Database has PubliclyAccessible=true
    - Security group restricts source IPs
    - Still risky if SG changes or IPs are compromised
    - SEVERITY: HIGH

1.3 PubliclyAccessible=false but in public subnet
    - Database not publicly accessible
    - But VPC has internet gateway and DB in public subnet
    - Misconfiguration could expose it
    - SEVERITY: MEDIUM

=============================================================================
CATEGORY 2: IAM AUTHENTICATION VECTORS
=============================================================================

2.1 IAM auth enabled with wildcard rds-db:connect
    - IAMDatabaseAuthenticationEnabled=true
    - Role has policy: rds-db:connect on Resource: "*"
    - Any compromised role can connect
    - SEVERITY: CRITICAL

2.2 IAM auth enabled with specific database access
    - IAMDatabaseAuthenticationEnabled=true
    - Role has policy: rds-db:connect on specific DB resource
    - Proper least-privilege but still a breach path if role compromised
    - SEVERITY: HIGH

2.3 IAM auth enabled with specific user access
    - IAMDatabaseAuthenticationEnabled=true
    - Role has policy: rds-db:connect on specific dbuser ARN
    - Most restrictive IAM auth config
    - SEVERITY: MEDIUM

2.4 IAM auth disabled (password-only)
    - IAMDatabaseAuthenticationEnabled=false
    - Access depends on database credentials
    - Cannot verify via IAM SimulatePrincipalPolicy
    - Breach path depends on credential discovery
    - SEVERITY: VARIES (depends on credential management)

=============================================================================
CATEGORY 3: ENCRYPTION VECTORS
=============================================================================

3.1 No encryption at rest
    - StorageEncrypted=false
    - Data stored in plaintext
    - Snapshots are unencrypted
    - SEVERITY: HIGH

3.2 Default AWS-managed encryption
    - StorageEncrypted=true
    - Using AWS-managed key (aws/rds)
    - AWS controls the key
    - SEVERITY: LOW

3.3 Customer-managed KMS key with permissive policy
    - StorageEncrypted=true
    - Customer CMK with Principal: "*" in key policy
    - Any AWS principal can use the key
    - SEVERITY: HIGH

3.4 Customer-managed KMS key with proper restrictions
    - StorageEncrypted=true
    - Customer CMK with specific principals
    - Proper key policy
    - SEVERITY: LOW

3.5 KMS key policy allows kms:CreateGrant
    - Role can create grants to access the key
    - Can escalate to decrypt permissions
    - SEVERITY: HIGH

=============================================================================
CATEGORY 4: LATERAL MOVEMENT VECTORS
=============================================================================

4.1 Role assumption chain to RDS access
    - Role A (attached to EC2) can sts:AssumeRole to Role B
    - Role B has rds-db:connect permission
    - Attacker compromises EC2 → assumes Role B → connects to RDS
    - SEVERITY: CRITICAL

4.2 iam:PassRole to RDS-connected role
    - Role A can iam:PassRole to Role B
    - Role B has rds-db:connect permission
    - Attacker can launch compute with Role B
    - SEVERITY: HIGH

4.3 Cross-account role assumption
    - Role in Account A can assume role in Account B
    - Role in Account B has RDS access
    - SEVERITY: HIGH

4.4 Service-linked role exploitation
    - Attacker can trigger AWS service that uses service-linked role
    - Service-linked role has RDS access
    - SEVERITY: MEDIUM

=============================================================================
CATEGORY 5: PRIVILEGE ESCALATION VECTORS
=============================================================================

5.1 iam:CreatePolicy / iam:AttachRolePolicy
    - Role can create new policies
    - Can grant itself rds-db:connect
    - SEVERITY: CRITICAL

5.2 iam:PutRolePolicy
    - Role can add inline policies
    - Can grant itself rds-db:connect
    - SEVERITY: CRITICAL

5.3 iam:CreateUser / iam:CreateAccessKey
    - Role can create new IAM users
    - Can create user with RDS access
    - SEVERITY: HIGH

5.4 iam:UpdateAssumeRolePolicy
    - Role can modify trust policies
    - Can allow itself to assume RDS-connected roles
    - SEVERITY: HIGH

5.5 kms:PutKeyPolicy
    - Role can modify KMS key policies
    - Can grant itself decrypt permissions
    - SEVERITY: HIGH

5.6 rds:ModifyDBInstance
    - Role can modify DB instance settings
    - Can enable PubliclyAccessible, change security groups
    - SEVERITY: CRITICAL

=============================================================================
CATEGORY 6: CREDENTIAL DISCOVERY VECTORS
=============================================================================

6.1 Secrets Manager access
    - Role has secretsmanager:GetSecretValue
    - Secret contains database credentials
    - Attacker retrieves credentials and connects
    - SEVERITY: CRITICAL

6.2 SSM Parameter Store access
    - Role has ssm:GetParameter / ssm:GetParameters
    - Parameter contains database credentials (SecureString)
    - Attacker retrieves credentials
    - SEVERITY: CRITICAL

6.3 Environment variables in Lambda
    - Lambda function has DB credentials in env vars
    - Attacker with lambda:GetFunction can read config
    - SEVERITY: HIGH

6.4 ECS task definition with credentials
    - ECS task definition has DB credentials
    - Attacker with ecs:DescribeTaskDefinition can read
    - SEVERITY: HIGH

6.5 CloudFormation stack parameters
    - Stack has DB credentials as parameters
    - Attacker with cloudformation:DescribeStacks
    - SEVERITY: HIGH

6.6 EC2 user data with credentials
    - EC2 instance has credentials in user data
    - Attacker with ec2:DescribeInstanceAttribute
    - SEVERITY: HIGH

=============================================================================
CATEGORY 7: NETWORK-BASED VECTORS
=============================================================================

7.1 Security group allows all inbound on DB port
    - SG allows 0.0.0.0/0 on port 3306/5432
    - Combined with PubliclyAccessible=true = direct access
    - SEVERITY: CRITICAL

7.2 Security group allows wide CIDR range
    - SG allows 10.0.0.0/8 or similar wide range
    - Any compromised host in range can connect
    - SEVERITY: MEDIUM

7.3 VPC peering to exposed VPC
    - DB VPC peered with VPC that has internet access
    - Route tables allow traffic flow
    - SEVERITY: MEDIUM

7.4 Transit gateway exposure
    - DB VPC connected via transit gateway
    - TGW routes allow access from untrusted VPCs
    - SEVERITY: MEDIUM

7.5 VPC endpoint policy too permissive
    - RDS VPC endpoint with Principal: "*"
    - Any principal can use the endpoint
    - SEVERITY: MEDIUM

=============================================================================
CATEGORY 8: COMPUTE-TO-RDS BREACH PATHS
=============================================================================

8.1 Internet-exposed EC2 → IAM role → rds-db:connect
    - EC2 instance with public IP and 0.0.0.0/0 SG
    - Instance profile with rds-db:connect permission
    - DB has IAM auth enabled
    - SEVERITY: CRITICAL

8.2 Internet-exposed Lambda → IAM role → rds-db:connect
    - Lambda with public function URL (AuthType=NONE)
    - Execution role with rds-db:connect permission
    - DB has IAM auth enabled
    - SEVERITY: CRITICAL

8.3 Internet-exposed Lambda via API Gateway → rds-db:connect
    - Lambda behind API Gateway (no auth)
    - Execution role with rds-db:connect permission
    - DB has IAM auth enabled
    - SEVERITY: CRITICAL

8.4 Internet-exposed EC2 → credential discovery → DB access
    - EC2 instance publicly exposed
    - Instance profile can read Secrets Manager
    - Secret contains DB password
    - DB uses password auth
    - SEVERITY: CRITICAL

8.5 Internet-exposed Lambda → credential discovery → DB access
    - Lambda publicly exposed
    - Execution role can read SSM parameters
    - Parameter contains DB password
    - SEVERITY: CRITICAL

8.6 ECS Fargate → rds-db:connect
    - ECS service with public load balancer
    - Task role with rds-db:connect permission
    - SEVERITY: HIGH

=============================================================================
CATEGORY 9: SNAPSHOT AND BACKUP VECTORS
=============================================================================

9.1 Public snapshot
    - RDS snapshot shared publicly
    - Anyone can restore and access data
    - SEVERITY: CRITICAL

9.2 Snapshot shared with untrusted account
    - Snapshot shared with specific account
    - That account is compromised or untrusted
    - SEVERITY: HIGH

9.3 Unencrypted snapshot
    - Encrypted DB but unencrypted snapshot
    - Snapshot can be copied and accessed
    - SEVERITY: HIGH

9.4 rds:CopyDBSnapshot permission
    - Role can copy snapshots
    - Can copy to unencrypted or to another account
    - SEVERITY: MEDIUM

9.5 rds:RestoreDBInstanceFromDBSnapshot
    - Role can restore from snapshot
    - Can restore with different security settings
    - SEVERITY: HIGH

=============================================================================
CATEGORY 10: AURORA-SPECIFIC VECTORS
=============================================================================

10.1 Aurora Serverless Data API
    - Data API enabled
    - Role has rds-data:ExecuteStatement
    - Can execute SQL without network access
    - SEVERITY: HIGH (if publicly callable)

10.2 Aurora global database
    - Primary in secure region
    - Secondary in less secure region
    - Cross-region access path
    - SEVERITY: MEDIUM

10.3 Aurora clone
    - Role can rds:CreateDBCluster with clone
    - Can clone production database
    - SEVERITY: HIGH

=============================================================================
TEST PRIORITY MATRIX
=============================================================================

CRITICAL (Must test first):
- 1.1: Public + open security group
- 2.1: IAM auth with wildcard
- 4.1: Lateral movement via role assumption
- 5.1, 5.2: Privilege escalation via IAM
- 6.1, 6.2: Credential discovery
- 8.1, 8.2: Compute-to-RDS breach paths

HIGH (Test next):
- 1.2: Public + restrictive SG
- 2.2: IAM auth with specific DB
- 3.1: No encryption
- 3.3: Permissive KMS policy
- 4.2, 4.3: Other lateral movement
- 8.4, 8.5: Credential discovery paths
- 9.1, 9.2: Snapshot exposure

MEDIUM (Test later):
- 1.3: Public subnet misconfiguration
- 2.3: Specific user IAM auth
- 7.2-7.5: Network vectors
- 9.4, 9.5: Snapshot operations
- 10.1-10.3: Aurora-specific

LOW (Optional):
- 3.2, 3.4: Proper encryption configs (verify not flagged)
- 2.4: Password-only (different threat model)

=============================================================================
*/

// TestRDSAttackVectors will contain the actual test implementations
// For now, this file serves as documentation of all attack vectors
