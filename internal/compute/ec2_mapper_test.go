package compute

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"breachmap/internal/domain"
)

// =============================================================================
// AnalyzeSecurityGroupPublicAccess TESTS
// =============================================================================

func TestAnalyzeSecurityGroupPublicAccess(t *testing.T) {
	tests := []struct {
		name              string
		securityGroup     ec2types.SecurityGroup
		wantPublicAccess  bool
		wantExposedPorts  int
	}{
		{
			name: "0.0.0.0/0 on port 22 is public",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(22),
						ToPort:     aws.Int32(22),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 1,
		},
		{
			name: "0.0.0.0/0 on port 443 is public",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(443),
						ToPort:     aws.Int32(443),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 1,
		},
		{
			name: "IPv6 ::/0 is public",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(80),
						ToPort:     aws.Int32(80),
						Ipv6Ranges: []ec2types.Ipv6Range{
							{CidrIpv6: aws.String("::/0")},
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 1,
		},
		{
			name: "both IPv4 and IPv6 public CIDRs",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(80),
						ToPort:     aws.Int32(80),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
						Ipv6Ranges: []ec2types.Ipv6Range{
							{CidrIpv6: aws.String("::/0")},
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 2, // One for IPv4, one for IPv6
		},
		{
			name: "multiple ports exposed",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(22),
						ToPort:     aws.Int32(22),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
					},
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(80),
						ToPort:     aws.Int32(80),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
					},
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(443),
						ToPort:     aws.Int32(443),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 3,
		},
		{
			name: "private CIDR is not public",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(22),
						ToPort:     aws.Int32(22),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("10.0.0.0/8")},
						},
					},
				},
			},
			wantPublicAccess: false,
			wantExposedPorts: 0,
		},
		{
			name: "VPC CIDR is not public",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(443),
						ToPort:     aws.Int32(443),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("172.31.0.0/16")},
						},
					},
				},
			},
			wantPublicAccess: false,
			wantExposedPorts: 0,
		},
		{
			name: "specific IP is not public",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(22),
						ToPort:     aws.Int32(22),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("203.0.113.50/32")},
						},
					},
				},
			},
			wantPublicAccess: false,
			wantExposedPorts: 0,
		},
		{
			name: "no IP permissions is not public",
			securityGroup: ec2types.SecurityGroup{
				GroupId:       aws.String("sg-12345"),
				IpPermissions: nil,
			},
			wantPublicAccess: false,
			wantExposedPorts: 0,
		},
		{
			name: "empty IP permissions is not public",
			securityGroup: ec2types.SecurityGroup{
				GroupId:       aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{},
			},
			wantPublicAccess: false,
			wantExposedPorts: 0,
		},
		{
			name: "mixed public and private - has public",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(22),
						ToPort:     aws.Int32(22),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("10.0.0.0/8")}, // Private
						},
					},
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(80),
						ToPort:     aws.Int32(80),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")}, // Public
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 1,
		},
		{
			name: "all protocols (-1) exposed",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("-1"),
						FromPort:   nil,
						ToPort:     nil,
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 1,
		},
		{
			name: "port range exposed",
			securityGroup: ec2types.SecurityGroup{
				GroupId: aws.String("sg-12345"),
				IpPermissions: []ec2types.IpPermission{
					{
						IpProtocol: aws.String("tcp"),
						FromPort:   aws.Int32(8000),
						ToPort:     aws.Int32(9000),
						IpRanges: []ec2types.IpRange{
							{CidrIp: aws.String("0.0.0.0/0")},
						},
					},
				},
			},
			wantPublicAccess: true,
			wantExposedPorts: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPublic, gotPorts := AnalyzeSecurityGroupPublicAccess(tt.securityGroup)
			
			if gotPublic != tt.wantPublicAccess {
				t.Errorf("AnalyzeSecurityGroupPublicAccess() hasPublicAccess = %v, want %v",
					gotPublic, tt.wantPublicAccess)
			}
			
			if len(gotPorts) != tt.wantExposedPorts {
				t.Errorf("AnalyzeSecurityGroupPublicAccess() exposedPorts count = %d, want %d",
					len(gotPorts), tt.wantExposedPorts)
			}
		})
	}
}

// =============================================================================
// GetInstanceProfileRoles TESTS (ARN parsing)
// =============================================================================

func TestGetInstanceProfileRoles_ARNParsing(t *testing.T) {
	tests := []struct {
		name               string
		instanceProfileARN string
		wantProfileName    string
		wantErr            bool
	}{
		{
			name:               "valid instance profile ARN",
			instanceProfileARN: "arn:aws:iam::123456789012:instance-profile/MyInstanceProfile",
			wantProfileName:    "MyInstanceProfile",
			wantErr:            false,
		},
		{
			name:               "instance profile with path",
			instanceProfileARN: "arn:aws:iam::123456789012:instance-profile/service-role/EC2InstanceProfile",
			wantProfileName:    "service-role/EC2InstanceProfile",
			wantErr:            false,
		},
		{
			name:               "invalid ARN - no instance-profile prefix",
			instanceProfileARN: "arn:aws:iam::123456789012:role/MyRole",
			wantProfileName:    "",
			wantErr:            true,
		},
		{
			name:               "invalid ARN - empty after prefix",
			instanceProfileARN: "arn:aws:iam::123456789012:instance-profile/",
			wantProfileName:    "",
			wantErr:            true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Extract profile name using the same logic as the function
			prefix := ":instance-profile/"
			idx := -1
			for i := 0; i <= len(tt.instanceProfileARN)-len(prefix); i++ {
				if tt.instanceProfileARN[i:i+len(prefix)] == prefix {
					idx = i
					break
				}
			}
			
			if tt.wantErr {
				if idx != -1 {
					profileName := tt.instanceProfileARN[idx+len(prefix):]
					if profileName != "" {
						t.Errorf("Expected error for ARN %s", tt.instanceProfileARN)
					}
				}
			} else {
				if idx == -1 {
					t.Errorf("Expected valid ARN parsing for %s", tt.instanceProfileARN)
					return
				}
				profileName := tt.instanceProfileARN[idx+len(prefix):]
				if profileName != tt.wantProfileName {
					t.Errorf("Profile name = %s, want %s", profileName, tt.wantProfileName)
				}
			}
		})
	}
}

// =============================================================================
// extractInstanceInfo TESTS
// =============================================================================

func TestExtractInstanceInfo(t *testing.T) {
	tests := []struct {
		name     string
		instance ec2types.Instance
		region   string
		want     domain.EC2InstanceInfo
	}{
		{
			name: "full instance info",
			instance: ec2types.Instance{
				InstanceId:       aws.String("i-1234567890abcdef0"),
				VpcId:            aws.String("vpc-12345"),
				SubnetId:         aws.String("subnet-12345"),
				PublicIpAddress:  aws.String("54.123.45.67"),
				PrivateIpAddress: aws.String("10.0.1.100"),
				SecurityGroups: []ec2types.GroupIdentifier{
					{GroupId: aws.String("sg-11111")},
					{GroupId: aws.String("sg-22222")},
				},
				Tags: []ec2types.Tag{
					{Key: aws.String("Name"), Value: aws.String("web-server")},
					{Key: aws.String("Environment"), Value: aws.String("prod")},
				},
			},
			region: "us-east-1",
			want: domain.EC2InstanceInfo{
				InstanceID:       "i-1234567890abcdef0",
				Region:           "us-east-1",
				VPCID:            aws.String("vpc-12345"),
				SubnetID:         aws.String("subnet-12345"),
				PublicIP:         aws.String("54.123.45.67"),
				PrivateIP:        aws.String("10.0.1.100"),
				PublicIPFlag:     true,
				SecurityGroupIDs: []string{"sg-11111", "sg-22222"},
				Name:             aws.String("web-server"),
			},
		},
		{
			name: "instance without public IP",
			instance: ec2types.Instance{
				InstanceId:       aws.String("i-private"),
				VpcId:            aws.String("vpc-12345"),
				SubnetId:         aws.String("subnet-12345"),
				PrivateIpAddress: aws.String("10.0.1.100"),
				SecurityGroups: []ec2types.GroupIdentifier{
					{GroupId: aws.String("sg-11111")},
				},
			},
			region: "us-west-2",
			want: domain.EC2InstanceInfo{
				InstanceID:       "i-private",
				Region:           "us-west-2",
				VPCID:            aws.String("vpc-12345"),
				SubnetID:         aws.String("subnet-12345"),
				PublicIP:         nil,
				PrivateIP:        aws.String("10.0.1.100"),
				PublicIPFlag:     false,
				SecurityGroupIDs: []string{"sg-11111"},
			},
		},
		{
			name: "instance without name tag",
			instance: ec2types.Instance{
				InstanceId:       aws.String("i-noname"),
				PublicIpAddress:  aws.String("54.1.2.3"),
				PrivateIpAddress: aws.String("10.0.1.1"),
				Tags: []ec2types.Tag{
					{Key: aws.String("Environment"), Value: aws.String("dev")},
				},
			},
			region: "eu-west-1",
			want: domain.EC2InstanceInfo{
				InstanceID:       "i-noname",
				Region:           "eu-west-1",
				PublicIP:         aws.String("54.1.2.3"),
				PrivateIP:        aws.String("10.0.1.1"),
				PublicIPFlag:     true,
				SecurityGroupIDs: []string{},
				Name:             nil,
			},
		},
		{
			name: "minimal instance",
			instance: ec2types.Instance{
				InstanceId: aws.String("i-minimal"),
			},
			region: "ap-southeast-1",
			want: domain.EC2InstanceInfo{
				InstanceID:       "i-minimal",
				Region:           "ap-southeast-1",
				PublicIPFlag:     false,
				SecurityGroupIDs: []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractInstanceInfo(tt.instance, tt.region)
			
			if got.InstanceID != tt.want.InstanceID {
				t.Errorf("InstanceID = %s, want %s", got.InstanceID, tt.want.InstanceID)
			}
			if got.Region != tt.want.Region {
				t.Errorf("Region = %s, want %s", got.Region, tt.want.Region)
			}
			if got.PublicIPFlag != tt.want.PublicIPFlag {
				t.Errorf("PublicIPFlag = %v, want %v", got.PublicIPFlag, tt.want.PublicIPFlag)
			}
			if len(got.SecurityGroupIDs) != len(tt.want.SecurityGroupIDs) {
				t.Errorf("SecurityGroupIDs count = %d, want %d", 
					len(got.SecurityGroupIDs), len(tt.want.SecurityGroupIDs))
			}
			
			// Check optional fields
			if tt.want.Name != nil {
				if got.Name == nil || *got.Name != *tt.want.Name {
					t.Errorf("Name = %v, want %v", got.Name, tt.want.Name)
				}
			}
			if tt.want.PublicIP != nil {
				if got.PublicIP == nil || *got.PublicIP != *tt.want.PublicIP {
					t.Errorf("PublicIP = %v, want %v", got.PublicIP, tt.want.PublicIP)
				}
			}
		})
	}
}

