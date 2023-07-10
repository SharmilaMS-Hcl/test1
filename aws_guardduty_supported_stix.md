##### Updated on 07/07/23
## aws guardduty
### Supported STIX Operators
*Comparison AND/OR operators are inside the observation while observation AND/OR operators are between observations (square brackets).*

| STIX Operator | Data Source Operator |
|--|--|
| AND (Comparision) | and |
| OR (Comparision) | or |
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
| **ipv4-addr**:value | resource.instanceDetails.networkInterfaces.privateIpAddresses.privateIpAddress,resource.instanceDetails.networkInterfaces.publicIp,service.action.networkConnectionAction.remoteIpDetails.ipAddressV4,service.action.awsApiCallAction.remoteIpDetails.ipAddressV4,service.action.kubernetesApiCallAction.remoteIpDetails.ipAddressV4 |
| **ipv4-addr**:x_geo_ref.country_name |service.action.networkConnectionAction.remoteIpDetails.country.countryName, service.action.awsApiCallAction.remoteIpDetails.country.countryName|
| **ipv4-addr**:belongs_to_refs[*].number |service.action.networkConnectionAction.remoteIpDetails.organization.asn,service.action.awsApiCallAction.remoteIpDetails.organization.asn|
| **ipv6-addr**:value|resource.instanceDetails.networkInterfaces.ipv6Addresses|
| **autonomous-system**:number | service.action.networkConnectionAction.remoteIpDetails.organization.asn,service.action.awsApiCallAction.remoteIpDetails.organization.asn |
| **autonomous-system**:name | service.action.networkConnectionAction.remoteIpDetails.organization.asnOrg,service.action.awsApiCallAction.remoteIpDetails.organization.asnOrg |
| **x-oca-geo**:country_name | service.action.networkConnectionAction.remoteIpDetails.country.countryName,service.action.awsApiCallAction.remoteIpDetails.country.countryName |
| **x-oca-geo**:city_name | service.action.awsApiCallAction.remoteIpDetails.city.cityName,service.action.networkConnectionAction.remoteIpDetails.city.cityName |
| **network-traffic**:src_port | service.action.networkConnectionAction.localPortDetails.port |
| **network-traffic**:dst_port | service.action.networkConnectionAction.remotePortDetails.port |
| **network-traffic**:protocols[*] | service.action.networkConnectionAction.protocol |
| **network-traffic**:src_ref.value | resource.instanceDetails.networkInterfaces.privateIpAddresses.privateIpAddress |
| **network-traffic**:dst_ref.value | service.action.networkConnectionAction.remoteIpDetails.ipAddressV4,service.action.kubernetesApiCallAction.remoteIpDetails.ipAddressV4|
| **network-traffic**:x_is_target_port_blocked | service.action.networkConnectionAction.blocked |
| **network-traffic**:x_direction | service.action.networkConnectionAction.connectionDirection |
| **network-traffic**:extensions.'http-request-ext'.request_value | service.action.kubernetesApiCallAction.requestUri |
| **user-account**:user_id | resource.accessKeyDetails.principalId |
| **user-account**:x_access_key_id | resource.accessKeyDetails.accessKeyId |
| **user-account**:display_name | resource.accessKeyDetails.userName,resource.kubernetesDetails.kubernetesUserDetails.username |
| **user-account**:x_user_type | resource.accessKeyDetails.userType |
| **domain-name**:value | resource.instanceDetails.networkInterfaces.publicDnsName,service.action.dnsRequestAction.domain |
| **process**:name | service.runtimeDetails.process.name |
| **process**:binary_ref.hashes.'SHA-256' | service.runtimeDetails.process.executableSha256 |
| **file**:hashes.'SHA-256' | service.runtimeDetails.process.executableSha256, service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **file**:x_path | service.runtimeDetails.process.executablePath |
| **file**:hashes.'SHA-1' | service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **file**:hashes.MD5 | service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **file**:x_unknown_hash | service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.filePaths.hash |
| **x-aws-resource**:instance_ref.image_id | resource.instanceDetails.imageId |
| **x-aws-resource**:s3_bucket_refs[*].name | resource.s3BucketDetails.name |
| **x-aws-resource**:rds_database_ref.instance_id | resource.rdsDbInstanceDetails.dbInstanceIdentifier |
| **x-aws-resource**:rds_database_ref.cluster_id | resource.rdsDbInstanceDetails.dbClusterIdentifier |
| **x-aws-resource**:access_key_ref.user_id | resource.accessKeyDetails.principalId |
| **x-aws-resource**:lambda_details_ref.function_name | resource.lambdaDetails.functionName |
| **x-aws-resource**:ecs_cluster_ref.name | resource.ecsClusterDetails.name |
| **x-aws-resource**:eks_cluster_ref.name | resource.eksClusterDetails.name |
| **x-aws-resource**:resource_type | resource.resourceType |
| **x-aws-resource**:resource_role | service.resourceRole |
| **x-aws-instance**:image_id | resource.instanceDetails.imageId |
| **x-aws-instance**:profile_id | resource.instanceDetails.iamInstanceProfile.id |
| **x-aws-instance**:instance | resource.instanceDetails.instanceId |
| **x-aws-instance**:tag_key | resource.instanceDetails.tags.key |
| **x-aws-instance**:tag_value | resource.instanceDetails.tags.value |
| **x-aws-instance**:outpost_arn |resource.instanceDetails.outpostArn |
| **x-aws-network-interface**:security_group_id | resource.instanceDetails.networkInterfaces.securityGroups.groupId |
| **x-aws-network-interface**:security_group_name | resource.instanceDetails.networkInterfaces.securityGroups.groupName |
| **x-aws-network-interface**:subnet_id | resource.instanceDetails.networkInterfaces.subnetId |
| **x-aws-network-interface**:vpc_id  | resource.instanceDetails.networkInterfaces.vpcId|
| **x-aws-s3-bucket**:name | resource.s3BucketDetails.name |
| **x-aws-s3-bucket**:bucket_permission | resource.s3BucketDetails.publicAccess.effectivePermission |
| **x-aws-s3-bucket**:tag_key | resource.s3BucketDetails.tags.key |
| **x-aws-s3-bucket**:tag_value | resource.s3BucketDetails.tags.value |
| **x-aws-s3-bucket**:bucket_type | resource.s3BucketDetails.type |
| **x-aws-rds-db-instance**:cluster_id | resource.rdsDbInstanceDetails.dbClusterIdentifier |
| **x-aws-rds-db-instance**:engine | resource.rdsDbInstanceDetails.engine |
| **x-aws-rds-db-instance**:instance_id | resource.rdsDbInstanceDetails.dbInstanceIdentifier |
| **x-aws-rds-db-instance**:tag_key | resource.rdsDbInstanceDetails.tags.key |
| **x-aws-rds-db-instance**:tag_value| resource.rdsDbInstanceDetails.tags.value |
| **x-aws-rds-db-instance**:anomalous_login_user_ref.user_name| resource.rdsDbUserDetails.user |
| **x-aws-rds-db-user**:user_name | resource.rdsDbUserDetails.user |
| **x-aws-lambda**:function_arn | resource.lambdaDetails.functionArn |
| **x-aws-lambda**:function_name | resource.lambdaDetails.functionName |
| **x-aws-lambda**:tag_key | resource.lambdaDetails.tags.key |
| **x-aws-lambda**:tag_value | resource.lambdaDetails.tags.value |
| **x-aws-ecs-cluster**:name | resource.ecsClusterDetails.name |
| **x-aws-ecs-cluster**:task.definition_arn | resource.ecsClusterDetails.taskDetails.definitionArn |
| **x-aws-container**:image | resource.ecsClusterDetails.taskDetails.containers.image,resource.kubernetesDetails.kubernetesWorkloadDetails.containers.image,resource.containerDetails.image|
| **x-aws-container**:image_prefix | resource.kubernetesDetails.kubernetesWorkloadDetails.containers.imagePrefix |
| **x-aws-kubernetes-workload**:workload_name | resource.kubernetesDetails.kubernetesWorkloadDetails.name |
| **x-aws-kubernetes-workload**:workload_namespace | resource.kubernetesDetails.kubernetesWorkloadDetails.namespace |
| **x-aws-eks-cluster**:name | resource.eksClusterDetails.name |
| **x-aws-ebs-volume-malware-scan**:scan_id | service.ebsVolumeScanDetails.scanId |
| **x-aws**:account_id | accountId |
| **x-aws**:region | region |
| **x-ibm-finding**:confidence | confidence |
| **x-ibm-finding**:alert_id | id |
| **x-ibm-finding**:x_archived | service.archived |
| **x-ibm-finding**:severity | severity |
| **x-ibm-finding**:name | type |
| **x-ibm-finding**:x_resource_ref.resource_type | resource.resourceType |
| **x-ibm-finding**:src_application_user_ref.display_name | resource.kubernetesDetails.kubernetesUserDetails.username |
| **x-aws-finding-service**:action.action_type | service.action.actionType |
| **x-aws-finding-service**:action.api_called | service.action.awsApiCallAction.api |
| **x-aws-finding-service**:action.caller_account_id | service.action.awsApiCallAction.remoteAccountDetails.accountId |
| **x-aws-finding-service**:action.caller_type | service.action.awsApiCallAction.callerType |
| **x-aws-finding-service**:action.service_name | service.action.awsApiCallAction.serviceName |
| **x-aws-finding-service**:action.remote_ref.value | service.action.awsApiCallAction.remoteIpDetails.ipAddressV4 |
| **x-aws-finding-service**:action.error_code | service.action.awsApiCallAction.errorCode |
| **x-aws-finding-service**:action.is_caller_account_affiliated_to_aws | service.action.awsApiCallAction.RemoteAccountDetails.affiliated |
| **x-aws-finding-service**:additional_info | service.additionalInfo.threatListName |
| **x-aws-threat**:threat_name | service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.name |
| **x-aws-threat**:severity | service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.severity |
| **x-aws-evidence**:threat_intelligence_list_name | service.additionalInfo.threatListName |

### Supported STIX Objects and Properties for Query Results
| STIX Object | STIX Property | Data Source Field |
|--|--|--|
| ipv4-addr | value | PrivateIpAddress |
| ipv4-addr | value | PublicIp |
| ipv4-addr | value | IpAddressV4 |
| ipv4-addr | value | SourceIps |
| ipv4-addr | location | GeoLocation |
| <br> | | |
| ipv6-addr | value | Ipv6Addresses |
| <br> | | |
| autonomous-system | number | Asn |
| autonomous-system | name | AsnOrg |
| autonomous-system | x_isp | Isp |
| autonomous-system | x_organisation | Org |
| <br> | | |
| x-oca-geo| country_iso_code | CountryCode |
| x-oca-geo| country_name | CountryName |
| x-oca-geo| country_iso_code | CountryCode |
| x-oca-geo| city_name | CityName |
| x-oca-geo| location | GeoLocation |
| <br> | | |
| network-traffic | x_is_target_port_blocked | Blocked |
| network-traffic | dst_port | Port |
| network-traffic | protocols | Protocol |
| network-traffic | src_port | Port |
| network-traffic | dst_port | Port |
| network-traffic | protocols | PortName |
| network-traffic | x_direction | ConnectionDirection |
| network-traffic | x_dst_port_name | PortName |
| network-traffic | x_src_port_name | PortName |
| network-traffic | x_parameters | Parameters |
| network-traffic | request_value | RequestUri |
| network-traffic | x_status_code | StatusCode |
| network-traffic | User-Agent | UserAgent |
| network-traffic | request_method | Verb |
| <br> | | |
| user-account | x_access_key_id | AccessKeyId |
| user-account | user_id | PrincipalId |
| user-account | display_name | UserName |
| user-account | x_user_type | UserType |
| user-account | user_id | UserId |
| user-account | x_groups | Groups |
| user-account | x_session_name | SessionName |
| user-account | user_id | Uuid |
| user-account | x_effective_user_id | Euid |
| user-account | x_session_name | SessionName |
| <br> | | |
| domain-name | value | PublicDnsName |
| domain-name | value | PrivateDnsName |
| domain-name | value | Domain |
| <br> | | |
| process | x_absolute_path | ExecutablePath |
| process | name | Name |
| process | pid | NamespacePid |
| process | x_parent_unique_id | ParentUuid |
| process | created | StartTime |
| process | x_unique_id | Uuid |
| process | x_lineage_refs | GroupModifyingProcessLineageReferences |
| process | x_unique_id  | Uuid |
| process | x_parent_unique_id| ParentUuid |
| process | cwd | pwd |

| <br> | | |
| file | name | FileName |
| file | hashes.'SHA-256' | FileSha256 |
| file | x_path | FilePath |
| file | 'SHA-1' | FileSha1 |
| file | MD5 | FileMd5 |
| file | x_unknown_hash | UnknownHash |
| file | x_volume_arn | VolumeArn |
| file | x_unknown_hash | UnknownHash |
| file | name | ModuleName |
| file | x_path | ExecutablePath |
| file | SHA-256 | ExecutableSha256 |
| <br> | | |
| x-aws-resource | resource_type | ResourceType |
| x-aws-resource | resource_role | ResourceRole |
| <br> | | |
| x-aws-instance | availability_zone | AvailabilityZone |
| x-aws-instance | instance_arn | Arn |
| x-aws-instance | profile_id | Id |
| x-aws-instance | instance_id | InstanceId |
| x-aws-instance | state | InstanceState |
| x-aws-instance | instance_type | InstanceType |
| x-aws-instance | launch_time | LaunchTime |
| x-aws-instance | x_network_interface_refs | GroupNetworkInterfaceReferences |
| x-aws-instance | outpost_arn | OutpostArn |
| x-aws-instance | product_codes | ProductCodes |
| x-aws-instance | tags | Tags |
| <br> | | |
| x-aws-network-interface | interface_id | NetworkInterfaceId |
| x-aws-network-interface | private_domain_refs | GroupPrivateDomainReferences |
| x-aws-network-interface | security_groups | SecurityGroups |
| x-aws-network-interface | subnet_id  | SubnetId |
| x-aws-network-interface | vpc_id  | VpcId |
| <br> | | |
| x-aws-s3-bucket | arn | Arn |
| x-aws-s3-bucket | created_at | CreatedAt |
| x-aws-s3-bucket | server_side_encryption_type | EncryptionType |
| x-aws-s3-bucket | kms_encryption_key_arn | KmsMasterKeyArn |
| x-aws-s3-bucket | name | Name |
| x-aws-s3-bucket | canonical_id_of_bucket_owner | Owner |
| x-aws-s3-bucket | bucket_permission | EffectivePermission |
| x-aws-s3-bucket | block_public_acls | BlockPublicAcls |
| x-aws-s3-bucket | block_public_policy | BlockPublicPolicy |
| x-aws-s3-bucket | ignore_public_acls | IgnorePublicAcls |
| x-aws-s3-bucket | restrict_public_buckets | RestrictPublicBuckets |
| x-aws-s3-bucket | allows_public_read_access | AllowsPublicReadAccess |
| x-aws-s3-bucket | allows_public_write_access | AllowsPublicWriteAccess |
| x-aws-s3-bucket | block_public_ | Name |
| x-aws-s3-bucket | tags | Tag |
| x-aws-s3-bucket | bucket_type | Type |
| <br> | | |
| x-aws-rds-db-instance | cluster_id | dbClusterIdentifier |
| x-aws-rds-db-instance | instance_arn | DbInstanceArn |
| x-aws-rds-db-instance | instance_id | dbInstanceIdentifier |
| x-aws-rds-db-instance | engine | Engine |
| x-aws-rds-db-instance | engine_version | EngineVersion |
| x-aws-rds-db-instance | tags | Tags |
| <br> | | |
| x-aws-rds-db-user | application_name | Application |
| x-aws-rds-db-user | authentication_method | AuthMethod |
| x-aws-rds-db-user | database_name | Database |
| x-aws-rds-db-user | ssl | Ssl |
| x-aws-rds-db-user | user_name | User |
| <br> | | |
| x-aws-lambda | description | Description |
| x-aws-lambda | function_arn | FunctionArn |
| x-aws-lambda | function_name | FunctionName |
| x-aws-lambda | function_version | FunctionVersion |
| x-aws-lambda | last_modified_at | LastModifiedAt |
| x-aws-lambda | execution_role | Role |
| x-aws-lambda | tags | Tags |
| x-aws-lambda | security_groups | securityGroups |
| x-aws-lambda | subnet_ids | SubnetIds |
| x-aws-lambda | amazon_vpc_id | VpcId |
| <br> | | |
| x-aws-ecs-cluster | active_services_count | ActiveServicesCount |
| x-aws-ecs-cluster | cluster_arn | Arn |
| x-aws-ecs-cluster | name | Name |
| x-aws-ecs-cluster | container_instances_registered_count | RegisteredContainerInstancesCount |
| x-aws-ecs-cluster | running_tasks_count | RunningTasksCount |
| x-aws-ecs-cluster | status | Status |
| x-aws-ecs-cluster | tags | Tags |
| x-aws-ecs-cluster | arn | Arn |
| x-aws-ecs-cluster | container_refs | GroupClusterContainerReferences |
| x-aws-ecs-cluster | definition_arn | DefinitionArn |
| x-aws-ecs-cluster | group_name | Group |
| x-aws-ecs-cluster | started_at | StartedAt |
| x-aws-ecs-cluster | started_by | StartedBy |
| x-aws-ecs-cluster | tags | Tags |
| x-aws-ecs-cluster | created_at | CreatedAt |
| x-aws-ecs-cluster | version | Version |
| x-aws-ecs-cluster | volumes | Volumes |
| x-aws-ecs-cluster | tags | Tags |
| <br> | | |
| x-aws-container | container_runtime | ContainerRuntime |
| x-aws-container | container_id | Id |
| x-aws-container | image_name | Image |
| x-aws-container | image_prefix | ImagePrefix |
| x-aws-container | name | Name |
| x-aws-container | is_container_privileged | Privileged |
| x-aws-container | volume_mount_refs | GroupContainerVolumeMountReferences |
| x-aws-container | path | MountPath |
| <br> | | |
| x-aws-kubernetes | container_refs | GroupKubernetesContainerReferences |
| x-aws-kubernetes | is_enabled_host_network_for_pods | HostNetwork |
| x-aws-kubernetes | workload_name | Name |
| x-aws-kubernetes | workload_namespace | namespace |
| x-aws-kubernetes | workload_type | Type |
| x-aws-kubernetes | workload_id | Uid |
| x-aws-kubernetes | runtime_context_ref | Volumes |
| <br> | | |
| x-aws-eks-cluster | arn | Arn |
| x-aws-eks-cluster | created_at | CreatedAt |
| x-aws-eks-cluster | name | Name |
| x-aws-eks-cluster | status | Status |
| x-aws-eks-cluster | tags | Tags |
| x-aws-eks-cluster | vpc_id | VpcId |
| x-aws-eks-cluster | arn | Arn |
| x-aws-eks-cluster | arn | Arn |
| <br> | | |
| x-aws-ebs-volume-malware-scan | scan_completed_at | EbsVolumeScanDetails |
| x-aws-ebs-volume-malware-scan | total_infected_files | HighestSeverityThreatDetails |
| x-aws-ebs-volume-malware-scan | severity | Severity |
| x-aws-ebs-volume-malware-scan | name | ThreatName |
| x-aws-ebs-volume-malware-scan | total_scanned_files | Files |
| x-aws-ebs-volume-malware-scan | total_files_scanned_in_gb | TotalGb |
| x-aws-ebs-volume-malware-scan | total_volumes_scanned | Volumes |
| x-aws-ebs-volume-malware-scan | infected_files_count | ItemCount |
| x-aws-ebs-volume-malware-scan | is_finding_shortened | Shortened |
| x-aws-ebs-volume-malware-scan | threat_refs | GroupThreatNamesReferences |
| x-aws-ebs-volume-malware-scan | unique_threats_count_based_on_name | UniqueThreatNameCount |
| x-aws-ebs-volume-malware-scan | total_infected_files | Files |
| x-aws-ebs-volume-malware-scan | scan_id | ScanId |
| x-aws-ebs-volume-malware-scan | scan_started_time | ScanStartedAt |
| x-aws-ebs-volume-malware-scan | scan_type | ScanType |
| x-aws-ebs-volume-malware-scan | sources | Sources |
| x-aws-ebs-volume-malware-scan | triggered_finding_id | TriggerFindingId |
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
| x-ibm-finding | x_archived | Archived |
| x-ibm-finding | event_count | Count |
| x-ibm-finding | x_detector_id | DetectorId |
| x-ibm-finding | x_feature_name | FeatureName |
| x-ibm-finding | x_finding_feedback | UserFeedback |
| <br> | | |
| x-aws-finding-service | action_type | ActionType |
| x-aws-finding-service | is_port_probe_blocked | Blocked |
| x-aws-finding-service | network_refs | GroupPortProbeDetailsReferences |
| x-aws-finding-service | affected_resources | AffectedResources |
| x-aws-finding-service | api_called | Api |
| x-aws-finding-service | caller_type | CallerType |
| x-aws-finding-service | error_code | ErrorCode |
| x-aws-finding-service | service_name | ServiceName |
| x-aws-finding-service | caller_account_id | AccountId |
| x-aws-finding-service | is_caller_account_affiliated_to_aws | Affiliated |
| x-aws-finding-service | rds_login_refs | GroupRdsLoginAttributes |
| x-aws-finding-service | additional_info | AdditionalInfo |
| x-aws-finding-service | event_first_seen | EventFirstSeen |
| x-aws-finding-service | event_last_seen | EventLastSeen |
| x-aws-finding-service | evidence_refs | GroupEvidenceReferences |
| <br> | | |
| x-aws-threat | infected_file_refs | GroupThreatFileReferences |
| x-aws-threat | total_files_infected | ItemCount |
| x-aws-threat | threat_name | Name |
| x-aws-threat | severity | Severity |
| <br> | | |
| x-aws-evidence | threat_intelligence_list_name | ThreatListName |
| x-aws-evidence | threat_names | ThreatNames |
| <br> | | |
