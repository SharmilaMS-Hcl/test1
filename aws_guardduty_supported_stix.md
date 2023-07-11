##### Updated on 07/07/23
## AWS GuardDuty
### Supported STIX Operators
*Comparison AND/OR operators are inside the observation while observation AND/OR operators are between observations (square brackets).*

| STIX Operator | Data Source Operator |
|--|--|
| AND (Comparison) | and |
| OR (Comparison) | or |
| > | GreaterThan |
| >= | GreaterThanOrEqual |
| < | LessThan |
| <= | LessThanOrEqual |
| = | Equals |
| != | NotEquals |
| IN | Equals |
| OR (Observation) | or |
| AND (Observation) | or |

### Searchable STIX objects and properties
| STIX Object and Property | Mapped Data Source Fields |
|--|--|
| **ipv4-addr**:value | Resource.InstanceDetails.NetworkInterfaces.privateIpAddresses.privateIpAddress,Resource.InstanceDetails.NetworkInterfaces.publicIp,Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4,Service.Action.kubernetesApiCallAction.RemoteIpDetails.IpAddressV4 |
| **ipv4-addr**:x_geo_ref.country_name |Service.Action.NetworkConnectionAction.RemoteIpDetails.country.countryName, Service.Action.AwsApiCallAction.RemoteIpDetails.country.countryName|
| **ipv4-addr**:belongs_to_refs[*].number |Service.Action.NetworkConnectionAction.RemoteIpDetails.organization.Asn,Service.Action.AwsApiCallAction.RemoteIpDetails.organization.Asn|
| **ipv6-addr**:value|Resource.InstanceDetails.NetworkInterfaces.Ipv6Addresses|
| **autonomous-system**:number | Service.Action.NetworkConnectionAction.RemoteIpDetails.organization.Asn,Service.Action.AwsApiCallAction.RemoteIpDetails.organization.Asn |
| **autonomous-system**:name | Service.Action.NetworkConnectionAction.RemoteIpDetails.organization.AsnOrg,Service.Action.AwsApiCallAction.RemoteIpDetails.organization.AsnOrg |
| **x-oca-geo**:country_name | Service.Action.NetworkConnectionAction.RemoteIpDetails.country.countryName,Service.Action.AwsApiCallAction.RemoteIpDetails.country.countryName |
| **x-oca-geo**:city_name | Service.Action.AwsApiCallAction.RemoteIpDetails.city.cityName,Service.Action.NetworkConnectionAction.RemoteIpDetails.city.cityName |
| **network-traffic**:src_port | Service.Action.NetworkConnectionAction.localPortDetails.port |
| **network-traffic**:dst_port | Service.Action.NetworkConnectionAction.remotePortDetails.port |
| **network-traffic**:protocols[*] | Service.Action.NetworkConnectionAction.protocol |
| **network-traffic**:src_ref.value | Resource.InstanceDetails.NetworkInterfaces.privateIpAddresses.privateIpAddress |
| **network-traffic**:dst_ref.value | Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4,Service.Action.kubernetesApiCallAction.RemoteIpDetails.IpAddressV4|
| **network-traffic**:x_is_target_port_blocked | Service.Action.NetworkConnectionAction.blocked |
| **network-traffic**:x_direction | Service.Action.NetworkConnectionAction.connectionDirection |
| **network-traffic**:extensions.'http-request-ext'.request_value | Service.Action.kubernetesApiCallAction.requestUri |
| **user-account**:user_id | Resource.accessKeyDetails.principalId |
| **user-account**:x_access_key_id | Resource.accessKeyDetails.accessKeyId |
| **user-account**:display_name | Resource.accessKeyDetails.userName,Resource.kubernetesDetails.kubernetesUserDetails.username |
| **user-account**:x_user_type | Resource.accessKeyDetails.userType |
| **domain-name**:value | Resource.InstanceDetails.NetworkInterfaces.publicDnsName,Service.Action.dnsRequestAction.domain |
| **process**:name | Service.runtimeDetails.process.name |
| **process**:binary_ref.hashes.'SHA-256' | Service.runtimeDetails.process.executableSha256 |
| **file**:hashes.'SHA-256' | Service.runtimeDetails.process.executableSha256, Service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **file**:x_path | Service.runtimeDetails.process.executablePath |
| **file**:hashes.'SHA-1' | Service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **file**:hashes.MD5 | Service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **file**:x_unknown_hash | Service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **x-aws-resource**:instance_ref.image_id | Resource.InstanceDetails.imageId |
| **x-aws-resource**:s3_bucket_refs[*].name | Resource.s3BucketDetails.name |
| **x-aws-resource**:rds_database_ref.instance_id | Resource.rdsDbInstanceDetails.dbInstanceIdentifier |
| **x-aws-resource**:rds_database_ref.cluster_id | Resource.rdsDbInstanceDetails.dbClusterIdentifier |
| **x-aws-resource**:access_key_ref.user_id | Resource.accessKeyDetails.principalId |
| **x-aws-resource**:lambda_details_ref.function_name | Resource.lambdaDetails.functionName |
| **x-aws-resource**:ecs_cluster_ref.name | Resource.ecsClusterDetails.name |
| **x-aws-resource**:eks_cluster_ref.name | Resource.eksClusterDetails.name |
| **x-aws-resource**:resource_type | Resource.resourceType |
| **x-aws-resource**:resource_role | Service.resourceRole |
| **x-aws-instance**:image_id | Resource.InstanceDetails.imageId |
| **x-aws-instance**:profile_id | Resource.InstanceDetails.iamInstanceProfile.id |
| **x-aws-instance**:instance | Resource.InstanceDetails.instanceId |
| **x-aws-instance**:tag_key | Resource.InstanceDetails.tags.key |
| **x-aws-instance**:tag_value | Resource.InstanceDetails.tags.value |
| **x-aws-instance**:outpost_arn |Resource.InstanceDetails.outpostArn |
| **x-aws-network-interface**:security_group_id | Resource.InstanceDetails.NetworkInterfaces.securityGroups.groupId |
| **x-aws-network-interface**:security_group_name | Resource.InstanceDetails.NetworkInterfaces.securityGroups.groupName |
| **x-aws-network-interface**:subnet_id | Resource.InstanceDetails.NetworkInterfaces.subnetId |
| **x-aws-network-interface**:vpc_id  | Resource.InstanceDetails.NetworkInterfaces.vpcId|
| **x-aws-s3-bucket**:name | Resource.s3BucketDetails.name |
| **x-aws-s3-bucket**:bucket_permission | Resource.s3BucketDetails.publicAccess.effectivePermission |
| **x-aws-s3-bucket**:tag_key | Resource.s3BucketDetails.tags.key |
| **x-aws-s3-bucket**:tag_value | Resource.s3BucketDetails.tags.value |
| **x-aws-s3-bucket**:bucket_type | Resource.s3BucketDetails.type |
| **x-aws-rds-db-instance**:cluster_id | Resource.rdsDbInstanceDetails.dbClusterIdentifier |
| **x-aws-rds-db-instance**:engine | Resource.rdsDbInstanceDetails.engine |
| **x-aws-rds-db-instance**:instance_id | Resource.rdsDbInstanceDetails.dbInstanceIdentifier |
| **x-aws-rds-db-instance**:tag_key | Resource.rdsDbInstanceDetails.tags.key |
| **x-aws-rds-db-instance**:tag_value| Resource.rdsDbInstanceDetails.tags.value |
| **x-aws-rds-db-instance**:anomalous_login_user_ref.user_name| Resource.rdsDbUserDetails.user |
| **x-aws-rds-db-user**:user_name | Resource.rdsDbUserDetails.user |
| **x-aws-lambda**:function_arn | Resource.lambdaDetails.functionArn |
| **x-aws-lambda**:function_name | Resource.lambdaDetails.functionName |
| **x-aws-lambda**:tag_key | Resource.lambdaDetails.tags.key |
| **x-aws-lambda**:tag_value | Resource.lambdaDetails.tags.value |
| **x-aws-ecs-cluster**:name | Resource.ecsClusterDetails.name |
| **x-aws-ecs-cluster**:task.definition_arn | Resource.ecsClusterDetails.taskDetails.definitionArn |
| **x-aws-container**:image | Resource.ecsClusterDetails.taskDetails.containers.image,Resource.kubernetesDetails.kubernetesWorkloadDetails.containers.image,Resource.containerDetails.image|
| **x-aws-container**:image_prefix | Resource.kubernetesDetails.kubernetesWorkloadDetails.containers.imagePrefix |
| **x-aws-kubernetes-workload**:workload_name | Resource.kubernetesDetails.kubernetesWorkloadDetails.name |
| **x-aws-kubernetes-workload**:workload_namespace | Resource.kubernetesDetails.kubernetesWorkloadDetails.namespace |
| **x-aws-eks-cluster**:name | Resource.eksClusterDetails.name |
| **x-aws-ebs-volume-malware-scan**:scan_id | Service.ebsVolumeScanDetails.scanId |
| **x-aws**:account_id | accountId |
| **x-aws**:region | region |
| **x-ibm-finding**:confidence | confidence |
| **x-ibm-finding**:alert_id | id |
| **x-ibm-finding**:x_archived | Service.archived |
| **x-ibm-finding**:severity | severity |
| **x-ibm-finding**:name | type |
| **x-ibm-finding**:x_resource_ref.resource_type | Resource.resourceType |
| **x-ibm-finding**:src_application_user_ref.display_name | Resource.kubernetesDetails.kubernetesUserDetails.username |
| **x-aws-finding-service**:action.action_type | Service.Action.actionType |
| **x-aws-finding-service**:action.api_called | Service.Action.AwsApiCallAction.api |
| **x-aws-finding-service**:action.caller_account_id | Service.Action.AwsApiCallAction.remoteAccountDetails.accountId |
| **x-aws-finding-service**:action.caller_type | Service.Action.AwsApiCallAction.callerType |
| **x-aws-finding-service**:action.service_name | Service.Action.AwsApiCallAction.serviceName |
| **x-aws-finding-service**:action.remote_ref.value | Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4 |
| **x-aws-finding-service**:action.error_code | Service.Action.AwsApiCallAction.errorCode |
| **x-aws-finding-service**:action.is_caller_account_affiliated_to_aws | Service.Action.AwsApiCallAction.RemoteAccountDetails.affiliated |
| **x-aws-finding-service**:additional_info | Service.additionalInfo.threatListName |
| **x-aws-threat**:threat_name | Service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.name |
| **x-aws-threat**:severity | Service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.severity |
| **x-aws-evidence**:threat_intelligence_list_name | Service.additionalInfo.threatListName |

### Supported STIX Objects and Properties for Query Results
| STIX Object | STIX Property | Data Source Field |
|--|--|--|
| ipv4-addr | value | Resource.InstanceDetails.NetworkInterfaces.PrivateIpAddresses.PrivateIpAddress |
| ipv4-addr | value | Resource.InstanceDetails.NetworkInterfaces.PublicIp |
| ipv4-addr | value | Service.NetworkConnectionAction.RemoteIpDetails.IpAddressV4 |
| ipv4-addr | value | Service.Action.PortProbeAction.PortProbeDetails.LocalIpDetails.IpAddressV4 |
| ipv4-addr | value | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.IpAddressV4 |
| ipv4-addr | value | Service.Action.NetworkConnectionAction.RemoteIpDetails.IpAddressV4 |
| ipv4-addr | value | Service.Action.KubernetesApiCallAction.RemoteIpDetails.IpAddressV4 |
| ipv4-addr | value | Service.Action.KubernetesApiCallAction.SourceIPs |
| ipv4-addr | value | Service.Action.AwsApiCallAction.RemoteIpDetails.IpAddressV4 |
| ipv4-addr | value | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.IpAddressV4 |
| ipv4-addr | belongs_to_refs | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Organization.Asn |
| ipv4-addr | belongs_to_refs | Service.Action.AwsApiCallAction.RemoteIpDetails.Organization.Asn|
| ipv4-addr | belongs_to_refs | Service.Action.NetworkConnectionAction.RemoteIpDetails.Organization.Asn|
| ipv4-addr | belongs_to_refs | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Organization.Asn |
| ipv4-addr | belongs_to_refs | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Organization.Asn|
| ipv4-addr | x_geo_ref | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Country.CountryName |
| ipv4-addr | x_geo_ref | Service.Action.AwsApiCallAction.RemoteIpDetails.Country.CountryName |
| ipv4-addr | x_geo_ref | Service.Action.NetworkConnectionAction.RemoteIpDetails.Country.CountryName |
| ipv4-addr | x_geo_ref | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Country.CountryName |
| ipv4-addr | x_geo_ref | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Country.CountryName |
| ipv4-addr | x_geo_ref | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.city.CityName |
| ipv4-addr | x_geo_ref | Service.Action.KubernetesApiCallAction.RemoteIpDetails.city.CityName |
| <br> | | |
| ipv6-addr | value | Resource.InstanceDetails.NetworkInterfaces.Ipv6Addresses |
| <br> | | |
| autonomous-system | number | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Organization.Asn |
| autonomous-system | number | Service.Action.AwsApiCallAction.RemoteIpDetails.Organization.Asn|
| autonomous-system | number | Service.Action.NetworkConnectionAction.RemoteIpDetails.Organization.Asn|
| autonomous-system | number | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Organization.Asn |
| autonomous-system | number | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Organization.Asn|
| autonomous-system | name | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Organization.AsnOrg |
| autonomous-system | name | Service.Action.AwsApiCallAction.RemoteIpDetails.Organization.AsnOrg |
| autonomous-system | name | Service.Action.NetworkConnectionAction.RemoteIpDetails.Organization.AsnOrg |
| autonomous-system | name | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Organization.AsnOrg |
| autonomous-system | name | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Organization.AsnOrg |
| autonomous-system | x_isp | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Organization.Isp |
| autonomous-system | x_isp | Service.Action.AwsApiCallAction.RemoteIpDetails.Organization.Isp |
| autonomous-system | x_isp |  Service.Action.NetworkConnectionAction.RemoteIpDetails.Organization.Isp |
| autonomous-system | x_isp | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Organization.Isp |
| autonomous-system | x_isp | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Organization.Isp |
| autonomous-system | x_organisation | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Organization.Org |
| autonomous-system | x_organisation | Service.Action.AwsApiCallAction.RemoteIpDetails.Organization.Org |
| autonomous-system | x_organisation | Service.Action.NetworkConnectionAction.RemoteIpDetails.Organization.Org |
| autonomous-system | x_organisation | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Organization.Org |
| autonomous-system | x_organisation | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Organization.Org |
| <br> | | |
| x-oca-geo| country_iso_code | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Country.CountryCode |
| x-oca-geo| country_iso_code | Service.Action.AwsApiCallAction.RemoteIpDetails.Country.CountryCode |
| x-oca-geo| country_iso_code | Service.Action.NetworkConnectionAction.RemoteIpDetails.Country.CountryCode |
| x-oca-geo| country_iso_code | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Country.CountryCode |
| x-oca-geo| country_iso_code | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Country.CountryCode |
| x-oca-geo| country_name | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.Country.CountryName |
| x-oca-geo| country_name | Service.Action.AwsApiCallAction.RemoteIpDetails.Country.CountryName |
| x-oca-geo| country_name | Service.Action.NetworkConnectionAction.RemoteIpDetails.Country.CountryName |
| x-oca-geo| country_name | Service.Action.KubernetesApiCallAction.RemoteIpDetails.Country.CountryName |
| x-oca-geo| country_name | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.Country.CountryName |
| x-oca-geo| city_name | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.city.CityName |
| x-oca-geo| city_name | Service.Action.AwsApiCallAction.RemoteIpDetails.city.CityName |
| x-oca-geo| city_name | Service.Action.NetworkConnectionAction.RemoteIpDetails.city.CityName |
| x-oca-geo| city_name | Service.Action.KubernetesApiCallAction.RemoteIpDetails.city.CityName |
| x-oca-geo| city_name | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.city.CityName |
| x-oca-geo| location | Service.Action.PortProbeAction.PortProbeDetails.RemoteIpDetails.GeoLocation |
| x-oca-geo| location | Service.Action.AwsApiCallAction.RemoteIpDetails.GeoLocation |
| x-oca-geo| location | Service.Action.NetworkConnectionAction.RemoteIpDetails.GeoLocation |
| x-oca-geo| location | Service.Action.KubernetesApiCallAction.RemoteIpDetails.GeoLocation |
| x-oca-geo| location | Service.Action.RdsLoginAttemptAction.RemoteIpDetails.GeoLocation |
| <br> | | |
| network-traffic | x_is_target_port_blocked | Service.Action.DnsRequestAction.Blocked |
| network-traffic | x_is_target_port_blocked | Service.Action.NetworkConnectionAction.Blocked |
| network-traffic | dst_port | Service.Action.NetworkConnectionAction.RemotePortDetails.Port |
| network-traffic | protocols | Service.Action.DnsRequestAction.Protocol |
| network-traffic | protocols | Service.Action.PortProbeAction.PortProbeDetails.LocalPortDetails.PortName |
| network-traffic | protocols | Service.Action.NetworkConnectionAction.Protocol |
| network-traffic | protocols | Service.Action.KubernetesApiCallAction.Protocol |
| network-traffic | src_port | Service.Action.PortProbeAction.PortProbeDetails.LocalPortDetails.Port |
| network-traffic | src_port | Service.Action.NetworkConnectionAction.LocalPortDetails.Port |
| network-traffic | dst_port | Service.Action.NetworkConnectionAction.RemotePortDetails.Port |
| network-traffic | x_direction | Service.Action.NetworkConnectionAction.ConnectionDirection |
| network-traffic | x_dst_port_name | Service.Action.NetworkConnectionAction.RemotePortDetails.PortName |
| network-traffic | x_src_port_name | Service.Action.NetworkConnectionAction.LocalPortDetails.PortName |
| network-traffic | x_parameters | Service.Action.KubernetesApiCallAction.Parameters |
| network-traffic | request_value | Service.Action.KubernetesApiCallAction.RequestUri |
| network-traffic | x_status_code | Service.Action.KubernetesApiCallAction.StatusCode |
| network-traffic | User-Agent | Service.Action.KubernetesApiCallAction.UserAgent |
| network-traffic | request_method | Service.Action.KubernetesApiCallAction.Verb |
| <br> | | |
| user-account | x_access_key_id | Resource.AccessKeyDetails.AccessKeyId |
| user-account | user_id | Resource.AccessKeyDetails.PrincipalId |
| user-account | user_id | Resource.KubernetesDetails.KubernetesUserDetails.Uid |
| user-account | user_id | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.UserId.PrincipalId |
| user-account | user_id | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.UserId |
| user-account | user_id | Service.RuntimeDetails.Context.TargetProcess.Lineage.UserId |
| user-account | user_id | Service.RuntimeDetails.Context.TargetProcess.UserId |
| user-account | user_id | Service.RuntimeDetails.Context.Process.Lineage.UserId |
| user-account | user_id | Service.RuntimeDetails.Context.Process.UserId|
| user-account | display_name | Resource.AccessKeyDetails.UserName |
| user-account | display_name | Resource.KubernetesDetails.KubernetesUserDetails.UserName |
| user-account | display_name | Service.RuntimeDetails.Context.ModifyingProcess.UserName |
| user-account | display_name | Service.RuntimeDetails.Context.TargetProcess.UserName |
| user-account | display_name | Service.RuntimeDetails.Process.UserName |
| user-account | x_user_type |  Resource.AccessKeyDetails.UserType |
| user-account | x_groups | Resource.KubernetesDetails.KubernetesUserDetails.Groups |
| user-account | x_session_name | Resource.KubernetesDetails.KubernetesUserDetails.SessionName |
| user-account | x_effective_user_id | Service.RuntimeDetails.Context.ModifyingProcess.Euid |
| user-account | x_effective_user_id | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.Euid |
| user-account | x_effective_user_id | Service.RuntimeDetails.Context.TargetProcess.Euid |
| user-account | x_effective_user_id | Service.RuntimeDetails.Context.TargetProcess.Lineage.Euid |
| user-account | x_effective_user_id | Service.RuntimeDetails.Process.Euid |
| user-account | x_effective_user_id | Service.RuntimeDetails.Process.Lineage.Euid |
| user-account | x_session_name | Resource.KubernetesDetails.KubernetesUserDetails.SessionName |
| <br> | | |
| domain-name | value | Resource.InstanceDetails.NetworkInterfaces.PublicDnsName |
| domain-name | value | Resource.InstanceDetails.NetworkInterfaces.PrivateIpAddresses.PrivateDnsName |
| domain-name | value | Service.Action.DnsRequestAction.Domain |
| domain-name | value |Service.Action.AwsApiCallAction.DomainDetails.Domain |
| <br> | | |
| process | x_absolute_path |  Service.RuntimeDetails.Context.ModifyingProcess.Lineage.ExecutablePath |
| process | x_absolute_path |  Service.RuntimeDetails.Context.TargetProcess.Lineage.ExecutablePath |
| process | x_absolute_path |  Service.RuntimeDetails.Process.Lineage.ExecutablePath |
| process | name | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.Name |
| process | name | Service.RuntimeDetails.Context.ModifyingProcess.Name |
| process | name | Service.RuntimeDetails.Context.TargetProcess.Lineage.Name |
| process | name | Service.RuntimeDetails.Context.TargetProcess.Name |
| process | name | Service.RuntimeDetails.Process.Lineage.Name |
| process | name | Service.RuntimeDetails.Process.Name |
| process | pid | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.NamespacePid |
| process | pid | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.Pid |
| process | pid | Service.RuntimeDetails.Context.ModifyingProcess.NamespacePid |
| process | pid | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.Pid |
| process | pid | Service.RuntimeDetails.Context.TargetProcess.Lineage.NamespacePid |
| process | pid | Service.RuntimeDetails.Context.TargetProcess.Lineage.Pid |
| process | pid | Service.RuntimeDetails.Context.TargetProcess.NamespacePid |
| process | pid | Service.RuntimeDetails.Context.TargetProcess.Pid |
| process | pid | Service.RuntimeDetails.Process.Lineage.NamespacePid |
| process | pid | Service.RuntimeDetails.Process.Lineage.Pid |
| process | pid | Service.RuntimeDetails.Process.NamespacePid |
| process | pid | Service.RuntimeDetails.Process.Pid |
| process | x_parent_unique_id | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.ParentUuid |
| process | x_parent_unique_id | Service.RuntimeDetails.Context.ModifyingProcess.ParentUuid |
| process | x_parent_unique_id | Service.RuntimeDetails.Context.TargetProcess.Lineage.ParentUuid |
| process | x_parent_unique_id | Service.RuntimeDetails.Context.TargetProcess.ParentUuid |
| process | x_parent_unique_id | Service.RuntimeDetails.Process.Lineage.ParentUuid |
| process | x_parent_unique_id | Service.RuntimeDetails.Process.ParentUuid |
| process | created | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.StartTime |
| process | created | Service.RuntimeDetails.Context.ModifyingProcess.StartTime |
| process | created | Service.RuntimeDetails.Context.TargetProcess.Lineage.StartTime |
| process | created | Service.RuntimeDetails.Context.TargetProcess.StartTime |
| process | created | Service.RuntimeDetails.Process.Lineage.StartTime |
| process | created | Service.RuntimeDetails.Process.StartTime |
| process | x_unique_id | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.Uuid |
| process | x_unique_id | Service.RuntimeDetails.Context.ModifyingProcess.Uuid |
| process | x_unique_id | Service.RuntimeDetails.Context.TargetProcess.Lineage.Uuid |
| process | x_unique_id | Service.RuntimeDetails.Context.TargetProcess.Uuid |
| process | x_unique_id | Service.RuntimeDetails.Process.Lineage.Uuid |
| process | x_unique_id | Service.RuntimeDetails.Process.Uuid |
| process | x_lineage_refs | Service.RuntimeDetails.Context.ModifyingProcess.Lineage.GroupModifyingProcessLineageReferences |
| process | x_lineage_refs | Service.RuntimeDetails.Context.TargetProcess.Lineage.GroupModifyingProcessLineageReferences |
| process | x_lineage_refs | Service.RuntimeDetails.Process.Lineage.GroupModifyingProcessLineageReferences |
| process | cwd | Service.RuntimeDetails.Context.ModifyingProcess.pwd |
| process | cwd | Service.RuntimeDetails.Context.TargetProcess.pwd |
| process | cwd |  Service.RuntimeDetails.Process.pwd |
| <br> | 
| file | name | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.FileName |
| file | name | Service.RuntimeDetails.Context.ModuleName |

| file | hashes.'SHA-256' | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.FileSha256 |
| file | hashes.'SHA-256' | Service.RuntimeDetails.Context.ModifyingProcess.ExecutableSha256 |
| file | hashes.'SHA-256' | Service.RuntimeDetails.Context.ModuleSha256 |
| file | hashes.'SHA-256' | Service.RuntimeDetails.Context.TargetProcess.ExecutableSha256 |
| file | hashes.'SHA-256' | Service.RuntimeDetails.Process.ExecutableSha256 |
| file | x_path |Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.FilePath |
| file | x_path |Service.RuntimeDetails.Context.ModifyingProcess.ExecutablePath |
| file | x_path |Service.RuntimeDetails.Context.ModuleFilePath |
| file | x_path | Service.RuntimeDetails.Context.TargetProcess.ExecutablePath|
| file | x_path | Service.RuntimeDetails.Context.Process.ExecutablePath|
| file | 'SHA-1' | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.FileSha1 |
| file | MD5 | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.FileMd5 |
| file | x_unknown_hash | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.UnknownHash |
| file | x_volume_arn | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.VolumeArn |
| file | x_unknown_hash | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.UnknownHash |
| <br> | | |
| x-aws-resource | resource_type | Resource.ResourceType |
| x-aws-resource | resource_role | Service.ResourceRole |
| <br> | | |
| x-aws-instance | availability_zone | Resource.InstanceDetails.AvailabilityZone |
| x-aws-instance | instance_arn | Resource.InstanceDetails.IamInstanceProfile.Arn |
| x-aws-instance | profile_id | Resource.InstanceDetails.IamInstanceProfile.Id |
| x-aws-instance | instance_id | Resource.InstanceDetails.InstanceId |
| x-aws-instance | state | Resource.InstanceDetails.InstanceState |
| x-aws-instance | instance_type | Resource.InstanceDetails.InstanceType |
| x-aws-instance | launch_time | Resource.InstanceDetails.LaunchTime |
| x-aws-instance | x_network_interface_refs | Resource.InstanceDetails.NetworkInterfaces.GroupNetworkInterfaceReferences |
| x-aws-instance | outpost_arn |  Resource.InstanceDetails.OutpostArn |
| x-aws-instance | product_codes | Resource.InstanceDetails.ProductCodes |
| x-aws-instance | tags | Resource.InstanceDetails.Tags |
| <br> | | |
| x-aws-network-interface | interface_id | Resource.InstanceDetails.NetworkInterfaces.NetworkInterfaceId |
| x-aws-network-interface | private_domain_refs | Resource.InstanceDetails.NetworkInterfaces.PrivateIpAddresses.GroupPrivateDomainReferences |
| x-aws-network-interface | security_groups | Resource.InstanceDetails.NetworkInterfaces.SecurityGroups |
| x-aws-network-interface | subnet_id  | Resource.InstanceDetails.NetworkInterfaces.SubnetId |
| x-aws-network-interface | vpc_id  | Resource.InstanceDetails.NetworkInterfaces.VpcId |
| <br> | | |
| x-aws-s3-bucket | arn | Resource.S3BucketDetails.Arn |
| x-aws-s3-bucket | created_at | Resource.S3BucketDetails.CreatedAt |
| x-aws-s3-bucket | server_side_encryption_type | Resource.S3BucketDetails.EncryptionType |
| x-aws-s3-bucket | kms_encryption_key_arn | Resource.S3BucketDetails.KmsMasterKeyArn |
| x-aws-s3-bucket | name | Resource.S3BucketDetails.Name |
| x-aws-s3-bucket | canonical_id_of_bucket_owner | Resource.S3BucketDetails.Owner |
| x-aws-s3-bucket | bucket_permission | Resource.S3BucketDetails.PublicAccess.EffectivePermission |
| x-aws-s3-bucket | block_public_acls | Resource.S3BucketDetails.PublicAccess.PermissionConfiguration.AccountLevelPermissions.BlockPublicAcls |
| x-aws-s3-bucket | block_public_policy | Resource.S3BucketDetails.PublicAccess.PermissionConfiguration.AccountLevelPermissions.BlockPublicPolicy |
| x-aws-s3-bucket | ignore_public_acls | Resource.S3BucketDetails.PublicAccess.PermissionConfiguration.AccountLevelPermissions.IgnorePublicAcls |
| x-aws-s3-bucket | restrict_public_buckets | Resource.S3BucketDetails.PublicAccess.PermissionConfiguration.AccountLevelPermissions.RestrictPublicBuckets |
| x-aws-s3-bucket | allows_public_read_access | Resource.S3BucketDetails.PublicAccess.PermissionConfiguration.BucketLevelPermissions.AccessControlList.AllowsPublicReadAccess |
| x-aws-s3-bucket | allows_public_write_access |Resource.S3BucketDetails.PublicAccess.PermissionConfiguration.BucketLevelPermissions.AccessControlList.AllowsPublicWriteAccess |
| x-aws-s3-bucket | tags | Resource.S3BucketDetails.Tag |
| x-aws-s3-bucket | bucket_type | Resource.S3BucketDetails.Type |
| <br> | | |
| x-aws-rds-db-instance | cluster_id | Resource.RdsDbInstanceDetails.dbClusterIdentifier |
| x-aws-rds-db-instance | instance_arn | Resource.RdsDbInstanceDetails.DbInstanceArn |
| x-aws-rds-db-instance | instance_id | Resource.RdsDbInstanceDetails.dbInstanceIdentifier |
| x-aws-rds-db-instance | engine | Resource.RdsDbInstanceDetails.Engine |
| x-aws-rds-db-instance | engine_version | Resource.RdsDbInstanceDetails.EngineVersion |
| x-aws-rds-db-instance | tags |  Resource.RdsDbInstanceDetails.Tags |
| <br> | | |
| x-aws-rds-db-user | application_name | Resource.RdsDbUserDetails.Application |
| x-aws-rds-db-user | authentication_method | Resource.RdsDbUserDetails.AuthMethod |
| x-aws-rds-db-user | database_name | Resource.RdsDbUserDetails.Database |
| x-aws-rds-db-user | ssl | Resource.RdsDbUserDetails.Ssl |
| x-aws-rds-db-user | user_name | Resource.RdsDbUserDetails.User |
| <br> | | |
| x-aws-lambda | description | Resource.LambdaDetails.Description |
| x-aws-lambda | function_arn | Resource.LambdaDetails.FunctionArn |
| x-aws-lambda | function_name | Resource.LambdaDetails.FunctionName |
| x-aws-lambda | function_version | Resource.LambdaDetails.FunctionVersion |
| x-aws-lambda | last_modified_at | Resource.LambdaDetails.LastModifiedAt |
| x-aws-lambda | execution_role | Resource.LambdaDetails.Role |
| x-aws-lambda | tags | Resource.LambdaDetails.Tags |
| x-aws-lambda | revision_id | Resource.LambdaDetails.RevisionId |
| x-aws-lambda | security_groups | Resource.LambdaDetails.securityGroups |
| x-aws-lambda | subnet_ids | Resource.LambdaDetails.SubnetIds |
| x-aws-lambda | amazon_vpc_id | Resource.LambdaDetails.VpcId |
| <br> | | |
| x-aws-ecs-cluster | active_services_count | Resource.EcsClusterDetails.ActiveServicesCount |
| x-aws-ecs-cluster | cluster_arn | Resource.EcsClusterDetails.Arn |
| x-aws-ecs-cluster | name | Resource.EcsClusterDetails.Name |
| x-aws-ecs-cluster | container_instances_registered_count | Resource.EcsClusterDetails.RegisteredContainerInstancesCount |
| x-aws-ecs-cluster | running_tasks_count | Resource.EcsClusterDetails.RunningTasksCount |
| x-aws-ecs-cluster | status | Resource.EcsClusterDetails.Status |
| x-aws-ecs-cluster | tags | Resource.EcsClusterDetails.Tags |
| x-aws-ecs-cluster | arn | Resource.EcsClusterDetails.TaskDetails.task.Arn |
| x-aws-ecs-cluster | container_refs | Resource.EcsClusterDetails.GroupClusterContainerReferences |
| x-aws-ecs-cluster | definition_arn | Resource.EcsClusterDetails.DefinitionArn |
| x-aws-ecs-cluster | group_name | Resource.EcsClusterDetails.Group |
| x-aws-ecs-cluster | started_at | Resource.EcsClusterDetails.StartedAt |
| x-aws-ecs-cluster | started_by | Resource.EcsClusterDetails.StartedBy |
| x-aws-ecs-cluster | tags | Resource.EcsClusterDetails.Tags |
| x-aws-ecs-cluster | created_at | Resource.EcsClusterDetails.CreatedAt |
| x-aws-ecs-cluster | version | Resource.EcsClusterDetails.Version |
| x-aws-ecs-cluster | volumes | Resource.EcsClusterDetails.Volumes |
| <br> | | |
| x-aws-container | container_runtime | Resource.ContainerDetails.ContainerRuntime |
| x-aws-container | container_runtime | Resource.EcsClusterDetails.TaskDetails.Containers.containerRuntime |
| x-aws-container | container_runtime | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.ContainerRuntime |
| x-aws-container | container_id | Resource.ContainerDetails.Id |
| x-aws-container | container_id | Resource.EcsClusterDetails.TaskDetails.Containers.Id |
| x-aws-container | container_id | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.Id |
| x-aws-container | image_name | Resource.ContainerDetails.Image |
| x-aws-container | image | Resource.EcsClusterDetails.TaskDetails.Containers.Image |
| x-aws-container | image | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.Image |
| x-aws-container | image_prefix | Resource.ContainerDetails.ImagePrefix |
| x-aws-container | image_prefix | Resource.EcsClusterDetails.TaskDetails.Containers.ImagePrefix |
| x-aws-container | image_prefix | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.ImagePrefix |
| x-aws-container | name | Resource.ContainerDetails.Name |
| x-aws-container | name | Resource.EcsClusterDetails.TaskDetails.Containers.Name |
| x-aws-container | name | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.Name |
| x-aws-container | is_container_privileged | Resource.ContainerDetails.SecurityContext.Privileged |
| x-aws-container | is_container_privileged | Resource.EcsClusterDetails.TaskDetails.Containers.SecurityContext.Privileged |
| x-aws-container | is_container_privileged | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.SecurityContext.Privileged |
| x-aws-container | volume_mount_refs | Resource.ContainerDetails.VolumeMounts.GroupContainerVolumeMountReferences |
| x-aws-container | volume_mount_refs | Resource.EcsClusterDetails.TaskDetails.Containers.VolumeMounts.GroupContainerVolumeMountReferences |
| x-aws-container | volume_mount_refs | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.VolumeMounts.GroupContainerVolumeMountReferences |
| <br> | | |
| x-aws-kubernetes | container_refs | Resource.KubernetesDetails.KubernetesWorkloadDetails.Containers.GroupKubernetesContainerReferences |
| x-aws-kubernetes | is_enabled_host_network_for_pods | Resource.KubernetesDetails.KubernetesWorkloadDetails.HostNetwork |
| x-aws-kubernetes | workload_name |  Resource.KubernetesDetails.KubernetesWorkloadDetails.Name |
| x-aws-kubernetes | workload_namespace |  Resource.KubernetesDetails.KubernetesWorkloadDetails..namespace |
| x-aws-kubernetes | workload_type |  Resource.KubernetesDetails.KubernetesWorkloadDetails.Type |
| x-aws-kubernetes | workload_id |  Resource.KubernetesDetails.KubernetesWorkloadDetails.Uid |
| x-aws-kubernetes | runtime_context_ref |  Resource.KubernetesDetails.KubernetesWorkloadDetails.Volumes |
| <br> | | |
| x-aws-eks-cluster | arn | Resource.EksClusterDetails.Arn |
| x-aws-eks-cluster | created_at | Resource.EksClusterDetails.CreatedAt |
| x-aws-eks-cluster | name | Resource.EksClusterDetails.Name |
| x-aws-eks-cluster | status | Resource.EksClusterDetails.Status |
| x-aws-eks-cluster | tags | Resource.EksClusterDetails.Tags |
| x-aws-eks-cluster | vpc_id | Resource.EksClusterDetails.VpcId |
| <br> | | |
| x-aws-ebs-volume-malware-scan | scan_completed_at | Service.EbsVolumeScanDetails.EbsVolumeScanDetails |
| x-aws-ebs-volume-malware-scan | total_infected_files | Service.EbsVolumeScanDetails.ScanDetections.HighestSeverityThreatDetails |
| x-aws-ebs-volume-malware-scan | severity | Service.EbsVolumeScanDetails.ScanDetections.HighestSeverityThreatDetails.Severity |
| x-aws-ebs-volume-malware-scan | total_infected_files | Service.EbsVolumeScanDetails.ScanDetections.HighestSeverityThreatDetails.Count |
| x-aws-ebs-volume-malware-scan | name | Service.EbsVolumeScanDetails.ScanDetections.HighestSeverityThreatDetails.ThreatName |
| x-aws-ebs-volume-malware-scan | total_scanned_files | Service.EbsVolumeScanDetails.ScanDetections.ScannedItemCount.Files |
| x-aws-ebs-volume-malware-scan | total_files_scanned_in_gb | Service.EbsVolumeScanDetails.ScanDetections.ScannedItemCount.TotalGb |
| x-aws-ebs-volume-malware-scan | total_volumes_scanned | Service.EbsVolumeScanDetails.ScanDetections.ScannedItemCount.Volumes |
| x-aws-ebs-volume-malware-scan | infected_files_count |  Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ItemCount |
| x-aws-ebs-volume-malware-scan | is_finding_shortened |  Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.Shortened |
| x-aws-ebs-volume-malware-scan | threat_refs | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.GroupThreatNamesReferences |
| x-aws-ebs-volume-malware-scan | unique_threats_count_based_on_name |  Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.UniqueThreatNameCount |
| x-aws-ebs-volume-malware-scan | total_infected_files |  Service.EbsVolumeScanDetails.ScanDetections.ThreatsDetectedItemCount.Files |
| x-aws-ebs-volume-malware-scan | scan_id | Service.EbsVolumeScanDetails.ScanId |
| x-aws-ebs-volume-malware-scan | scan_started_time | Service.EbsVolumeScanDetails.ScanStartedAt |
| x-aws-ebs-volume-malware-scan | scan_type | Service.EbsVolumeScanDetails.ScanType |
| x-aws-ebs-volume-malware-scan | sources | Service.EbsVolumeScanDetails.Sources |
| x-aws-ebs-volume-malware-scan | triggered_finding_id | Service.EbsVolumeScanDetails.TriggerFindingId |
| <br> | | |
| x-aws | account_id | AccountId |
| x-aws | partition | Partition |
| x-aws | region | Region |
| <br> | | |
| x-ibm-finding | finding_type | FindingType |
| x-ibm-finding | x_arn | Arn |
| x-ibm-finding | confidence | Confidence |
| x-ibm-finding | description | Description |
| x-ibm-finding | alert_id | Id |
| x-ibm-finding | x_schema_version | SchemaVersion |
| x-ibm-finding | severity | Severity |
| x-ibm-finding | x_title | Title |
| x-ibm-finding | name | Type |
| x-ibm-finding | time_observed | UpdatedAt |
| x-ibm-finding | x_archived | Service.Archived |
| x-ibm-finding | event_count | Service.Count |
| x-ibm-finding | x_detector_id | Service.DetectorId |
| x-ibm-finding | x_feature_name | Service.FeatureName |
| x-ibm-finding | x_finding_feedback | Service.UserFeedback |
| <br> | | |
| x-aws-finding-service | action_type | Service.Action.ActionType |
| x-aws-finding-service | is_port_probe_blocked | Service.Action.PortProbeAction.Blocked |
| x-aws-finding-service | network_refs | Service.Action.PortProbeAction.PortProbeDetails.GroupPortProbeDetailsReferences |
| x-aws-finding-service | affected_resources | Service.Action.AwsApiCallAction.AffectedResources |
| x-aws-finding-service | api_called |  Service.Action.AwsApiCallAction.Api |
| x-aws-finding-service | caller_type | Service.Action.AwsApiCallAction.CallerType |
| x-aws-finding-service | error_code | Service.Action.AwsApiCallAction.ErrorCode |
| x-aws-finding-service | service_name | Service.Action.AwsApiCallAction.ServiceName |
| x-aws-finding-service | caller_account_id | Service.Action.AwsApiCallAction.RemoteAccountDetails.AccountId |
| x-aws-finding-service | is_caller_account_affiliated_to_aws | Service.Action.AwsApiCallAction.RemoteAccountDetails.Affiliated |
| x-aws-finding-service | rds_login_refs | Service.Action.RdsLoginAttemptAction.LoginAttributes.GroupRdsLoginAttributes |
| x-aws-finding-service | additional_info | Service.AdditionalInfo |
| x-aws-finding-service | event_first_seen | Service.EventFirstSeen |
| x-aws-finding-service | event_last_seen | Service.EventLastSeen |
| x-aws-finding-service | evidence_refs | Service.Evidence.ThreatIntelligenceDetails.GroupEvidenceReferences |
| <br> | | |
| x-aws-threat | infected_file_refs | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.FilePaths.GroupThreatFileReferences |
| x-aws-threat | total_files_infected | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.ItemCount |
| x-aws-threat | threat_name | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.Name |
| x-aws-threat | severity | Service.EbsVolumeScanDetails.ScanDetections.ThreatDetectedByName.ThreatNames.Severity |
| <br> | | |
| x-aws-evidence | threat_intelligence_list_name | Service.Evidence.ThreatIntelligenceDetails.ThreatListName |
| x-aws-evidence | threat_names | Service.Evidence.ThreatIntelligenceDetails.ThreatNames |
| <br> | | |
