package compute

import (
	"context"
	"fmt"
	"strings"

	"breachmap/internal/domain"
)

// GetWorkloadsForRole aggregates all compute resources (EC2, Lambda, ECS, etc.)
// that assume a given IAM role.
func GetWorkloadsForRole(
	ctx context.Context,
	roleARNs []string,
	ec2Mapping domain.RoleToInstancesMapping,
	lambdaMapping domain.RoleToLambdasMapping,
) (domain.RoleToComputeResourcesMapping, error) {
	unifiedMapping := make(domain.RoleToComputeResourcesMapping)

	// Convert EC2 instances to ComputeResource
	for roleARN, instances := range ec2Mapping {
		for _, instance := range instances {
			if !instance.InternetExposed {
				continue
			}

			instanceARN := fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s",
				instance.Region, ExtractAccountIDFromARN(roleARN), instance.InstanceID)

			computeResource := domain.ComputeResource{
				RuntimeType:      "EC2",
				ResourceID:       instance.InstanceID,
				ResourceARN:      instanceARN,
				ResourceName:     instance.Name,
				Region:           instance.Region,
				RoleARN:          roleARN,
				InternetExposed:  instance.InternetExposed,
				VPCID:            instance.VPCID,
				SubnetIDs:        []string{},
				SecurityGroupIDs: instance.SecurityGroupIDs,
				PublicIP:         instance.PublicIP,
				PrivateIP:        instance.PrivateIP,
				PublicExposure:   instance.PublicExposure,
			}

			if instance.SubnetID != nil {
				computeResource.SubnetIDs = []string{*instance.SubnetID}
			}

			unifiedMapping[roleARN] = append(unifiedMapping[roleARN], computeResource)
		}
	}

	// Convert Lambda functions to ComputeResource
	for roleARN, lambdas := range lambdaMapping {
		for _, lambdaInfo := range lambdas {
			if !lambdaInfo.InternetReachable {
				continue
			}

			computeResource := domain.ComputeResource{
				RuntimeType:      "Lambda",
				ResourceID:       lambdaInfo.FunctionName,
				ResourceARN:      lambdaInfo.FunctionARN,
				ResourceName:     lambdaInfo.Name,
				Region:           lambdaInfo.Region,
				RoleARN:          roleARN,
				InternetExposed:  lambdaInfo.InternetReachable,
				VPCID:            lambdaInfo.VPCID,
				SubnetIDs:        lambdaInfo.SubnetIDs,
				SecurityGroupIDs: lambdaInfo.SecurityGroupIDs,
				ExposureDetails:  lambdaInfo.ExposureDetails,
			}

			unifiedMapping[roleARN] = append(unifiedMapping[roleARN], computeResource)
		}
	}

	return unifiedMapping, nil
}

// ExtractAccountIDFromARN extracts the account ID from an ARN
func ExtractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
