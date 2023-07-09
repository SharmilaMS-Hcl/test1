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
| **x-aws-finding-service**:action.aws_api_call.api_called | service.action.awsApiCallAction.api |
| **x-aws-finding-service**:action.aws_api_call.caller_account_id | service.action.awsApiCallAction.remoteAccountDetails.accountId |
| **x-aws-finding-service**:action.aws_api_call.caller_type | service.action.awsApiCallAction.callerType |
| **x-aws-finding-service**:action.aws_api_call.service_name | service.action.awsApiCallAction.serviceName |
| **x-aws-finding-service**:action.aws_api_call.remote_ref.value | service.action.awsApiCallAction.remoteIpDetails.ipAddressV4 |
| **x-aws-finding-service**:action.aws_api_call.error_code | service.action.awsApiCallAction.errorCode |
| **x-aws-finding-service**:action.aws_api_call.is_caller_account_affiliated_to_aws | service.action.awsApiCallAction.RemoteAccountDetails.affiliated |
| **x-aws-finding-service**:additional_info | service.additionalInfo.threatListName |
| **x-aws-threat**:threat_name | service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.name |
| **x-aws-threat**:severity | service.ebsVolumeScanDetails.scanDetections.threatDetectedByName.threatNames.severity |
| **x-aws-evidence**:threat_intelligence_list_name | service.additionalInfo.threatListName |

### Supported STIX Objects and Properties for Query Results
| STIX Object | STIX Property | Data Source Field |
|--|--|--|
| ipv4-addr | value | privateIpAddress,publicIp,ipAddressV4 |
| ipv4-addr | x_geo_ref.country_name | countryName |
| ipv4-addr | belongs_to_refs[*].number | asn |
| <br> | | |
| ipv6-addr | value | ipv6Addresses |
| <br> | | |
| autonomous-system | number | asn |
| autonomous-system | name | asnOrg |
| <br> | | |
| x-oca-geo| country_name | countryName |
| x-oca-geo| city_name | cityName |
| <br> | | |
| network-traffic | src_port | port |
| network-traffic | dst_port | port |
| network-traffic | protocols[*] | protocol |
| network-traffic | src_ref.value | privateIpAddress |
| network-traffic | dst_ref.value | ipAddressV4 |
| network-traffic | x_is_target_port_blocked | blocked |
| network-traffic | x_direction | connectionDirection |
| network-traffic | extensions.'http-request-ext'.request_value | requestUri |
| <br> | | |
| user-account | user_id | principalId |
| user-account | x_access_key_id | accessKeyId |
| user-account | display_name | userName |
| user-account | x_user_type | userType |
| <br> | | |
| domain-name | value | publicDnsName, domain |
| <br> | | |
| process | name | name |
| <br> | | |
| file | hashes.'SHA-256' | executableSha256, hash |
| file | x_path | executablePath |
| file | hashes.'SHA-1' | hash |
| file | hashes.MD5 | hash |
| file | x_unknown_hash | hash |

| <br> | | |
| x-aws-resource | instance_ref.image_id | imageId |
| x-aws-resource | s3_bucket_refs[*].name | name |
| x-aws-resource | rds_database_ref.instance_id | dbInstanceIdentifier |
| x-aws-resource | rds_database_ref.cluster_id | dbClusterIdentifier |
| x-aws-resource | access_key_ref.user_id | principalId |
| x-aws-resource | lambda_details_ref.function_name | resource.lambdaDetails.functionName |
| x-aws-resource | ecs_cluster_ref.name | name |
| x-aws-resource | eks_cluster_ref.name | name |
| x-aws-resource | resource.resourceType | resourceType |
| x-aws-resource | resource_role | resourceRole |

| <br> | | |
| x-aws-instance | image_id | imageId |
| x-aws-instance | profile_id | id |
| x-aws-instance | instance | instanceId |
| x-aws-instance | tag_key | key |
| x-aws-instance | tag_value | value |
| x-aws-instance | outpost_arn | outpostArn |
| <br> | | |
| x-aws-network-interface | security_group_id | groupId |
| x-aws-network-interface | security_group_name | groupName |
| x-aws-network-interface | subnet_id | subnetId |
| x-aws-network-interface | vpc_id  | vpcId|
| <br> | | |
| x-aws-s3-bucket | name | name |
| x-aws-s3-bucket | bucket_permission | effectivePermission |
| x-aws-s3-bucket | tag_key | key |
| x-aws-s3-bucket | tag_value | value |
| x-aws-s3-bucket | bucket_type | type |
| <br> | | |
| x-aws-s3-bucket | name | name |
| x-aws-s3-bucket | bucket_permission | effectivePermission |
| x-aws-s3-bucket | tag_key | key |
| x-aws-s3-bucket | tag_value | value |
| x-aws-s3-bucket | bucket_type | type |
| <br> | | |
| x-aws-rds-db-instance | cluster_id | dbClusterIdentifier |
| x-aws-rds-db-instance | engine | engine |
| x-aws-rds-db-instance | instance_id | dbInstanceIdentifier |
| x-aws-rds-db-instance | tag_key | key |
| x-aws-rds-db-instance | tag_value| value |
| x-aws-rds-db-instance | anomalous_login_user_ref.user_name | user |
| <br> | | |
| x-aws-rds-db-user | user_name | user |
| <br> | | |
| x-aws-lambda | function_arn | functionArn |
| x-aws-lambda | function_name | functionName |
| x-aws-lambda | tag_key | key |
| x-aws-lambda | tag_value | value |
| <br> | | |
| x-aws-ecs-cluster | name | name |
| x-aws-ecs-cluster | task.definition_arn | definitionArn |
| <br> | | |
| x-aws-container | image | image |
| x-aws-container | image_prefix | imagePrefix |
| <br> | | |
| x-aws-kubernetes | workload_name | name |
| x-aws-kubernetes | workload_namespace | namespace |
| <br> | | |
| x-aws-eks-cluster | name | name |
| <br> | | |
| x-aws-ebs-volume-malware-scan | scan_id | scanId |
| <br> | | |
| x-aws | account_id | accountId |
| x-aws | region | region |
| <br> | | |
| x-ibm-finding | confidence | confidence |
| x-ibm-finding | alert_id | id |
| x-ibm-finding | x_archived | archived |
| x-ibm-finding | severity | severity |
| x-ibm-finding | name | type |
| x-ibm-finding | x_resource_ref.resource_type | resourceType |
| <br> | | |
| x-aws-finding-service | action.action_type | actionType |
| x-aws-finding-service | action.aws_api_call.api_called | api |
| x-aws-finding-service | action.aws_api_call.caller_account_id | accountId |
| x-aws-finding-service | action.aws_api_call.caller_type | callerType |
| x-aws-finding-service | action.aws_api_call.service_name | serviceName |
| x-aws-finding-service | action.aws_api_call.remote_ref.value | ipAddressV4 |
| x-aws-finding-service | action.aws_api_call.error_code | errorCode |
| x-aws-finding-service | action.aws_api_call.is_caller_account_affiliated_to_aws | affiliated |
| x-aws-finding-service | additional_info | threatListName |
| <br> | | |
| x-aws-threat | threat_name | name |
| x-aws-threat | severity | severity |
| <br> | | |
| x-aws-evidence | threat_intelligence_list_name | threatListName |
| <br> | | |
