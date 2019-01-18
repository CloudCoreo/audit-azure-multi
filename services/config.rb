coreo_aws_rule "azure-security-monitoring-agent-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-monitoring-agent-on.html"
  display_name "Monitoring Agent On"
  description "When Automatic provisioning of monitoring agent is turned on, Azure Security Center provisions the Microsoft Monitoring Agent on all existing supported Azure virtual machines and any new ones that are created. The Microsoft Monitoring agent scans for various security-related configurations and events such as system updates, OS vulnerabilities, and endpoint protection and provides alerts."
  category "Security"
  suggested_action "Enable Automatic provisioning of monitoring agent to collect security data."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.02"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0", "requirement" => "2.02" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as is_os_agent_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['is_os_agent_enabled']
  })
end

coreo_aws_rule "azure-security-system-update-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-system-update-on.html"
  display_name "System Update On"
  description "When this setting is enabled, it retrieves a daily list of available security and critical updates from Windows Update or Windows Server Update Services. The retrieved list depends on the service that's configured for that virtual machine and recommends that the missing updates be applied. For Linux systems, the policy uses the distro-provided package management system to determine packages that have available updates. It also checks for security and critical updates from Azure Cloud Services virtual machines."
  category "Security"
  suggested_action "Enable system updates recommendations for virtual machines."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.03"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.03" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as is_os_update_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['is_os_update_enabled']
  })
end

coreo_aws_rule "azure-security-security-configuration-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-security-configuration-on.html"
  display_name "Security Configuration On"
  description "When this setting is enabled, it analyzes operating system configurations daily to determine issues that could make the virtual machine vulnerable to attack. The policy also recommends configuration changes to address these vulnerabilities."
  category "Security"
  suggested_action "Enable OS vulnerabilities recommendations for virtual machines."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.04"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.04" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as security_baselines
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['security_baselines']
  })
end

coreo_aws_rule "azure-security-endpoint-protection-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-endpoint-protection-on.html"
  display_name "Endpoint Protection On"
  description "When this setting is enabled, it recommends endpoint protection be provisioned for all Windows virtual machines to help identify and remove viruses, spyware, and other malicious software."
  category "Security"
  suggested_action "Enable Endpoint protection recommendations for virtual machines."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.05"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.05" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as endpoint_protection
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['endpoint_protection']
  })
end

coreo_aws_rule "azure-security-disk-encrpytion-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-disk-encryption-on.html"
  display_name "Disk Encrpytion On"
  description "When this setting is enabled, it recommends enabling disk encryption in all virtual machines to enhance data protection at rest."
  category "Security"
  suggested_action "Enable Disk encryption recommendations for virtual machines."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.06"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.06" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as disk_encryption
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['disk_encryption']
  })
end

coreo_aws_rule "azure-security-network-security-groups-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-network-security-groups-on.html"
  display_name "Network Security Groups On"
  description "When this setting is enabled, it recommends that network security groups be configured to control inbound and outbound traffic to VMs that have public endpoints. Network security groups that are configured for a subnet is inherited by all virtual machine network interfaces unless otherwise specified. In addition to checking that a network security group has been configured, this policy assesses inbound security rules to identify rules that allow incoming traffic."
  category "Security"
  suggested_action "Enable Network security groups recommendations for virtual machines."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.07"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.07" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as network_security_group
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['network_security_group']
  })
end

coreo_aws_rule "azure-security-web-application-firewall-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-web-application-firewall-on.html"
  display_name "Web Application Firewall On"
  description "When this setting is enabled, it recommends that a web application firewall is provisioned on virtual machines when either of the following is true: (1) Instance-level public IP (ILPIP) is used and the inbound security rules for the associated network security group are configured to allow access to port 80/443. (2) Load-balanced IP is used and the associated load balancing and inbound network address translation (NAT) rules are configured to allow access to port 80/443."
  category "Security"
  suggested_action "Enable Web application firewall recommendations for virtual machines."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.08"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.08" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as provision_waf
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['provision_waf']
  })
end

coreo_aws_rule "azure-security-next-generation-firewall-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-next-generation-firewall-on.html"
  display_name "Next Generation Firewall On"
  description "When this setting is enabled, it extends network protections beyond network security groups, which are built into Azure. Security Center will discover deployments for which a next generation firewall is recommended and enable you to provision a virtual appliance."
  category "SEcurity"
  suggested_action "Enable Next generation firewall recommendations for virtual machines."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.09"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.09" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as enable_ngfw
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['enable_ngfw']
  })
end

coreo_aws_rule "azure-security-vulnerability-assessment-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-vulnerability-assessment-on.html"
  display_name "Vulnerability Assessment On"
  description "When this setting is enabled, it recommends that you install a vulnerability assessment solution on your VM."
  category "Security"
  suggested_action "Enable Vulnerability assessment recommendations for virtual machines."
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as vulnerability_assessments
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['vulnerability_assessments']
  })
end

coreo_aws_rule "azure-security-storage-encryption-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-storage-encryption-on.html"
  display_name "Storage Encryption On"
  description "When this setting is enabled, any new data in Azure Blobs and Files will be encrypted."
  category "Security"
  suggested_action "Enable Storage Encryption recommendations."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.11"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.11" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as blob_encryption_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['blob_encryption_enabled']
  })
end

coreo_aws_rule "azure-security-jit-network-access-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-jit-network-access-on.html"
  display_name "Jit Network Access On"
  description "When this setting is enabled, it Security Center locks down inbound traffic to your Azure VMs by creating an NSG rule. You select the ports on the VM to which inbound traffic should be locked down. Just in time virtual machine (VM) access can be used to lock down inbound traffic to your Azure VMs, reducing exposure to attacks while providing easy access to connect to VMs when needed."
  category "Security"
  suggested_action "Enable JIT Network Access for virtual machines."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.12" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as jit_network_access
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['jit_network_access']
  })
end

coreo_aws_rule "azure-security-adaptive-application-controls-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-adaptive-application-controls-on.html"
  display_name "Adaptive Application Controls On"
  description "Adaptive application controls help control which applications can run on your VMs located in Azure, which among other benefits helps harden your VMs against malware. Security Center uses machine learning to analyze the processes running in the VM and helps you apply whitelisting rules using this intelligence."
  category "Security"
  suggested_action "Enable adaptive application controls."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.13" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as os_mac_provisioning
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['os_mac_provisioning']
  })
end

coreo_aws_rule "azure-security-sql-auditing-threat-detection-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-sql-auditing-threat-detection-on.html"
  display_name "Sql Auditing Threat Detection On"
  description "When this setting is enabled, it recommends that auditing of access to Azure Database be enabled for compliance and also advanced threat detection, for investigation purposes."
  category "Security"
  suggested_action "Enable SQL auditing & Threat detection recommendations."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.14"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.14" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as sql_auditing
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['sql_auditing']
  })
end

coreo_aws_rule "azure-security-sql-encryption-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-sql-encryption-on.html"
  display_name "Sql Encryption On"
  description "When this setting is enabled, it recommends that encryption at rest be enabled for your Azure SQL Database, associated backups, and transaction log files. Even if your data is breached, it will not be readable."
  category "Security"
  suggested_action "Enable SQL Encryption recommendations."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.15"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.15" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as sql_encryption
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['sql_encryption']
  })
end

coreo_aws_rule "azure-security-security-contact-emails-set" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-security-contact-emails-set.html"
  display_name "Security Contact Emails Set"
  description "Microsoft reaches out to the provided security contact in case its security team finds that your resources are compromised. This ensures that you are aware of any potential compromise and you can timely mitigate the risk."
  category "Security"
  suggested_action "Provide a security contact email address."
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.16"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.16" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    good_uids as var(func:has(<Microsoft.Security/policies>)) @cascade{
      relates @filter(has(email_address)){
        email_address
      }
    }
    query(func:has(<Microsoft.Security/policies>)) @filter(NOT uid(good_uids)) {
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => []
  })
end

coreo_aws_rule "azure-security-security-contact-phone-num-set" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-security-contact-phone-num-set.html"
  display_name "Security Contact Phone Num Set"
  description "Microsoft reaches out to the provided security contact in case its security team finds that your resources are compromised. This ensures that you are aware of any potential compromise and you can timely mitigate the risk."
  category "Security"
  suggested_action "Provide a security contact phone number."
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.17"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.17" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as security_phone_number
    }
    query(func:uid(blob_type)) @filter(eq(val(property), "")) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['security_phone_number']
  })
end

coreo_aws_rule "azure-security-send-email-alerts-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-send-email-alerts-on.html"
  display_name "Send Email Alerts On"
  description "Enabling security alerts emailing ensures that you receive the security alert emails from Microsoft. This ensures that you are aware of any potential security issues and you can timely mitigate the risk."
  category "Security"
  suggested_action "Enable security alerts emailing to security contact."
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.18"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.18" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as send_notifications
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['send_notifications']
  })
end

coreo_aws_rule "azure-security-send-email-to-subscription-owners-on" do
  action :define
  service :Microsoft_Security
  link "https://kb.securestate.vmware.com/azure-security-send-email-to-subscription-owners-on.html"
  display_name "Send Email To Subscription Owners On"
  description "Enabling security alerts emailing to subscription owners ensures that they receive the security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can timely mitigate the risk."
  category "Security"
  suggested_action "Enable security alerts emailing to subscription owners."
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "2.19"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "2.19" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Security/policies>)) @cascade{
      property as notify_admins
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      is_os_update_enabled sql_encryption sql_auditing notify_admins send_notifications os_mac_provisioning vulnerability_assessments blob_encryption_enabled endpoint_protection enable_ngfw disk_encryption is_os_agent_enabled network_security_group jit_network_access security_baselines
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Security/policies' => ['notify_admins']
  })
end

coreo_aws_rule "azure-storage-secure-transfer-required-enabled" do
  action :define
  service :Microsoft_Storage
  link "https://kb.securestate.vmware.com/azure-storage-secure-transfer-required-enabled.html"
  display_name "Secure Transfer Required Enabled"
  description "The secure transfer option enhances the security of your storage account by only allowing requests to the storage account by a secure connection."
  category "Security"
  suggested_action "Enable data encryption is transit."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "3.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "3.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Storage/storageAccounts>)) @cascade{
      property as https_only
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name file_encryption_enabled contains  storage_account blob_encryption_enabled https_only resource_group
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Storage/storageAccounts' => ['https_only']
  })
end

coreo_aws_rule "azure-storage-storage-encryption-blob-service-enabled" do
  action :define
  service :Microsoft_Storage
  link "https://kb.securestate.vmware.com/azure-storage-storage-encryption-blob-service-enabled.html"
  display_name "Storage Encryption Blob Service Enabled"
  description "Storage service encryption protects your data at rest. Azure Storage encrypts your data as it's written in its datacenters, and automatically decrypts it for you as you access it."
  category "Security"
  suggested_action "Enable data encryption at rest for blobs."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "3.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "3.2" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Storage/storageAccounts>)) @cascade{
      property as blob_encryption_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name file_encryption_enabled contains  storage_account blob_encryption_enabled https_only resource_group
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Storage/storageAccounts' => ['blob_encryption_enabled']
  })
end

coreo_aws_rule "azure-storage-storage-encryption-enabled-for-file-service" do
  action :define
  service :Microsoft_Storage
  link "https://kb.securestate.vmware.com/azure-storage-storage-encryption-enabled-for-file-service.html"
  display_name "Storage Encryption Enabled For File Service"
  description "Storage service encryption protects your data at rest. Azure Storage encrypts your data as it's written in its datacenters, and automatically decrypts it for you as you access it."
  category "Security"
  suggested_action "Enable data encryption at rest for file service."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "3.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "3.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Storage/storageAccounts>)) @cascade{
      property as file_encryption_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name file_encryption_enabled contains storage_account blob_encryption_enabled https_only resource_group
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Storage/storageAccounts' => ['file_encryption_enabled']
  })
end

coreo_aws_rule "azure-storage-public-access-level-set-private-for-blob-containers" do
  action :define
  service :Microsoft_Storage
  link "https://kb.securestate.vmware.com/azure-storage-public-access-level-set-private-for-blob-containers.html"
  display_name "Public Access Level Set Private For Blob Containers"
  description "You can enable anonymous, public read access to a container and its blobs in Azure Blob storage. By doing so, you can grant read-only access to these resources without sharing your account key, and without requiring a shared access signature. It is recommended to not provide anonymous access to blob containers until and unless it is strongly desired. You should use shared access signature token for providing controlled and timed access to blob containers."
  category "Security"
  suggested_action "Disable anonymous access to blob containers."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "3.7"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "3.7" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Storage/storageAccounts>)) @cascade{
      property as public_access
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name file_encryption_enabled contains storage_account blob_encryption_enabled https_only resource_group
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Storage/storageAccounts' => ['public_access']
  })
end

coreo_aws_rule "azure-sql-auditing-on-server" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-auditing-on-server.html"
  display_name "Auditing On"
  description "The Azure platform allows you to create a SQL server as a service. Enabling auditing at the server level ensures that all existing and newly created databases on the SQL server instance are audited. Auditing tracks database events and writes them to an audit log in your Azure storage account. It also helps you to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations."
  category "Security"
  suggested_action "Enable auditing on SQL Servers."
  level "Medium"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.1.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers>)) @cascade{
      property as is_audit_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name notify_admins contains audit_retention_days threat_retention_days is_audit_enabled
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => ['is_audit_enabled']
  })
end

coreo_aws_rule "azure-sql-threat-detection-on-server" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-threat-detection-on-server.html"
  display_name "Threat Detection On"
  description "SQL Threat Detection provides a new layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. Users will receive an alert upon suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access patterns. SQL Threat Detection alerts provide details of suspicious activity and recommend action on how to investigate and mitigate the threat."
  category "Security"
  suggested_action "Enable threat detection on SQL Servers."
  level "High"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.1.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.2" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers>)) @cascade{
      property as is_threat_detection_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name notify_admins contains audit_retention_days threat_retention_days is_audit_enabled
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => ['is_threat_detection_enabled']
  })
end

coreo_aws_rule "azure-sql-threat-detection-types-all-server" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-threat-detection-types-all-server.html"
  display_name "Threat Detection Types All"
  description "Enabling all threat detection types, you are protected against SQL injection, database vulnerabilities and any other anomalous activities."
  category "Security"
  suggested_action "Enable all types of threat detection on SQL Servers."
  level "High"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.1.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.3" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers>)) {}
    query(func:uid(blob_type)) @cascade{
      <%= default_predicates %>
      synthesises {
        <%= default_predicates %>
      }
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => []
  })
end

coreo_aws_rule "azure-sql-send-alerts-set-server" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-send-alerts-set-server.html"
  display_name "Send Alerts Set"
  description "Providing the email address to receive alerts ensures that any detection of anomalous activities is reported as soon as possible, making it more likely to mitigate any potential risk sooner."
  category "Security"
  suggested_action "Provide the email address to which alerts will be sent upon detection of anomalous activities on SQL Servers."
  level "Low"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.1.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    good_uids as var(func:has(<Microsoft.Sql/servers>)) @cascade{
      relates @filter(has(email_address)){
        email_address
      }
    }
    query(func:has(<Microsoft.Sql/servers>)) @filter(NOT uid(good_uids)) {
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => []
  })
end

coreo_aws_rule "azure-sql-email-service-co-administrators-enabled-server" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-email-service-co-administrators-enabled-server.html"
  display_name "Email Service Co Administrators Enabled"
  description "Providing the email address to receive alerts ensures that any detection of anomalous activities is reported as soon as possible, making it more likely to mitigate any potential risk sooner."
  category "Security"
  suggested_action "Enable service and co-administrators to receive security alerts from SQL Server."
  level "Low"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.1.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.5" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers>)) @cascade{
      property as notify_admins
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name notify_admins contains audit_retention_days threat_retention_days is_audit_enabled
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => ['notify_admins']
  })
end

coreo_aws_rule "azure-sql-auditing-retention-greater-than-90-days-server" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-auditing-retention-greater-than-90-days-server.html"
  display_name "Auditing Retention Greater Than 90 Days"
  description "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access."
  category "Security"
  suggested_action "SQL Server Audit Retention should be configured to be greater than 90 days."
  level "Low"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.1.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers>)) @cascade{
      property as audit_retention_days
    }
    query(func:uid(blob_type)) @filter(lt(val(property), 90)) {
      <%= default_predicates %>
      name notify_admins contains audit_retention_days threat_retention_days is_audit_enabled
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => ['audit_retention_days']
  })
end

coreo_aws_rule "azure-sql-threat-detection-retention-greater-than-90-days-server" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-threat-detection-retention-greater-than-90-days-server.html"
  display_name "Threat Detection Retention Greater Than 90 Days"
  description "Threat Detection Logs can be used to check for suspected attack attempts and breaches on a SQL server with known attack signatures."
  category "Security"
  suggested_action "SQL Server Threat Detection Retention should be configured to be greater than 90 days."
  level "Low"
  raise_when [true]
  operators [""]
  objectives [""]
  audit_objects [""]
  meta_cis_id "4.1.7"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.7" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers>)) @cascade{
      property as threat_retention_days
    }
    query(func:uid(blob_type)) @filter(lt(val(property), 90)) {
      <%= default_predicates %>
      name notify_admins contains audit_retention_days threat_retention_days is_audit_enabled
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => ['threat_retention_days']
  })
end

coreo_aws_rule "azure-sql-active-directory-admin-configured" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-active-directory-admin-configured.html"
  display_name "Active Directory Admin Configured"
  description "Azure Active Directory authentication is a mechanism of connecting to Microsoft Azure SQL Database and SQL Data Warehouse by using identities in Azure Active Directory (Azure AD). With Azure AD authentication, you can centrally manage the identities of database users and other Microsoft services in one central location."
  category "Security"
  suggested_action "Use Azure Active Directory Authentication for authentication with SQL Database"
  level "High"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.1.8"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.1.8" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers>)) @cascade{
      property as is_audit_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name notify_admins contains  audit_retention_days threat_retention_days is_audit_enabled
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers' => ['is_audit_enabled']
  })
end

coreo_aws_rule "azure-sql-auditing-on-database" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-auditing-on-database.html"
  display_name "Auditing On"
  description "Auditing tracks database events and writes them to an audit log in your Azure storage account. It also helps you to maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations."
  category "Security"
  suggested_action "Enable auditing on SQL databases."
  level "Medium"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers/databases>)) @cascade{
      property as is_audit_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/databases' => ['is_audit_enabled']
  })
end

coreo_aws_rule "azure-sql-threat-detection-on-database" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-threat-detection-on-database.html"
  display_name "Threat Detection On"
  description "SQL Threat Detection provides a new layer of security, which enables customers to detect and respond to potential threats as they occur by providing security alerts on anomalous activities. Users will receive an alert upon suspicious database activities, potential vulnerabilities, and SQL injection attacks, as well as anomalous database access patterns."
  category "Security"
  suggested_action "Enable threat detection on SQL databases."
  level "High"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.2" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers/databases>)) @cascade{
      property as is_threat_detection_enabled
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/databases' => ['is_threat_detection_enabled']
  })
end

coreo_aws_rule "azure-sql-threat-detection-types-all-database" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-threat-detection-types-all-database.html"
  display_name "Threat Detection Types All"
  description "Enabling all threat detection types, you are protected against SQL injection, database vulnerabilities and any other anomalous activities."
  category "Security"
  suggested_action "Enable all types of threat detection on SQL databases."
  level "High"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.3" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    query(func:has(<Microsoft.Sql/servers/databases>)) @cascade{
      <%= default_predicates %>
      synthesises {
        <%= default_predicates %>
      }
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/databases' => []
  })
end

coreo_aws_rule "azure-sql-send-alerts-set-database" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-send-alerts-set-database.html"
  display_name "Send Alerts Set"
  description "Providing the email address to receive alerts ensures that any detection of anomalous activities is reported as soon as possible, making it more likely to mitigate any potential risk sooner."
  category "Security"
  suggested_action "Provide the email address to which alerts will be sent upon detection of anomalous activities on SQL databases."
  level "Low"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    good_uids as var(func:has(<Microsoft.Sql/servers/databases>)) @cascade{
      relates @filter(has(email_address)){
        email_address
      }
    }
    query(func:has(<Microsoft.Sql/servers/databases>)) @filter(NOT uid(good_uids)) {
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/database' => []
  })
end

coreo_aws_rule "azure-sql-email-service-co-administrators-enabled-database" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-email-service-co-administrators-enabled-database.html"
  display_name "Email Service Co Administrators Enabled"
  description "Providing the email address to receive alerts ensures that any detection of anomalous activities is reported as soon as possible, making it more likely to mitigate any potential risk sooner."
  category "Security"
  suggested_action "Enable service and co-administrators to receive security alerts from SQL databases."
  level "Low"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.5" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers/databases>)) @cascade{
      property as notify_admins
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/databases' => ['notify_admins']
  })
end

coreo_aws_rule "azure-sql-data-encryption-on" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-data-encryption-on.html"
  display_name "Data Encryption On"
  description "Azure SQL Database transparent data encryption helps protect against the threat of malicious activity by performing real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application."
  category "Security"
  suggested_action "Encrypt database."
  level "High"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers/databases>)) @cascade{
      property as sql_encryption
    }
    query(func:uid(blob_type)) @filter(NOT eq(val(property), true)) {
      <%= default_predicates %>
      name
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/databases' => ['sql_encryption']
  })
end

coreo_aws_rule "azure-sql-auditing-retention-greater-than-90-days-database" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-auditing-retention-greater-than-90-days-database.html"
  display_name "Auditing Retention Greater Than 90 Days"
  description "Audit Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access."
  category "Security"
  suggested_action "SQL Database Audit Retention should be configured to be greater than 90 days."
  level "Low"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.7"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.7" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers/databases>)) @cascade{
      property as audit_retention_days
    }
    query(func:uid(blob_type)) @filter(lt(val(property), 90)) {
      <%= default_predicates %>
      name 
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/databases' => ['audit_retention_days']
  })
end

coreo_aws_rule "azure-sql-threat-detection-retention-greater-than-90-days-database" do
  action :define
  service :Microsoft_Sql
  link "https://kb.securestate.vmware.com/azure-sql-threat-detection-retention-greater-than-90-days-database.html"
  display_name "Threat Detection Retention Greater Than 90 Days"
  description "Threat Logs can be used to check for anomalies and give insight into suspected breaches or misuse of information and access."
  category "Security"
  suggested_action "SQL Database Threat Retention should be configured to be greater than 90 days."
  level "Low"
  audit_objects [""]
  raise_when [true]
  operators [""]
  objectives [""]
  meta_cis_id "4.2.8"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "4.2.8" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    blob_type as var(func: has(<Microsoft.Sql/servers/databases>)) @cascade{
      property as threat_retention_days
    }
    query(func:uid(blob_type)) @filter(lt(val(property), 90)) {
      <%= default_predicates %>
      name
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Sql/servers/databases' => ['threat_retention_days']
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-create-or-update-sql-server-firewall-rule" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-create-or-update-sql-server-firewall-rule.html"
  display_name "Activity Log Alert For Create Or Update Sql Server Firewall Rule"
  description "Monitoring for Create or Update SQL Server Firewall Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Create or Update SQL Server Firewall Rule event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.10"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.10" }
    ]
  )
  meta_rule_query <<~QUERY
  {   
    var(func:has(value)) {
    vals as value
  }
  var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
    guards{
      checks @filter(eq(val(vals), "Administrative")){
        checks @filter(eq(val(vals), "microsoft.sql/servers/firewallrules/write")){
          endorses{
            records{
              happyTarget as uid
            }
          }
        }
      }
    }
  }
  query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
    <%= default_predicates %>
  }
}
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-delete-sql-server-firewall-rule" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-delete-sql-server-firewall-rule.html"
  display_name "Activity Log Alert For Delete Sql Server Firewall Rule"
  description "Monitoring for Delete SQL Server Firewall Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Delete SQL Server Firewall Rule event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.11"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.11" }
    ]
  )
  meta_rule_query <<~QUERY
  { 
    var(func:has(value)) {
      vals as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(vals), "Administrative")){
          checks @filter(eq(val(vals), "microsoft.sql/servers/firewallrules/delete")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-update-security-policy" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-update-security-policy.html"
  display_name "Activity Log Alert For Update Security Policy"
  description "Monitoring for Update Security Policy events gives insight into changes to the Security Policy and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Update Security Policy event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.12" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)) {
      vals as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(vals), "Administrative")){
          checks @filter(eq(val(vals), "microsoft.security/policies/write")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-key-vault-logging-for-keyvault-enabled" do
  action :define
  service :Microsoft_KeyVault
  link "https://kb.securestate.vmware.com/azure-key-vault-logging-for-keyvault-enabled.html"
  display_name "Logging For Keyvault Enabled"
  description "Monitoring how and when your key vaults are accessed, and by whom enables an audit trail of interactions with your secrets, keys and certificates managed by Azure Keyvault. You can do this by enabling logging for Key Vault, which saves information in an Azure storage account that you provide. This creates a new container named insights-logs-auditevent automatically for your specified storage account, and you can use this same storage account for collecting logs for multiple key vaults."
  category "Logging"
  suggested_action "Enable AuditEvent logging for Key Vault instances to ensure interactions with key vaults are logged and available."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.13" }
    ]
  )
  meta_rule_query <<~QUERY
{
    var(func:has(is_retention_enabled)) @cascade{
      days as retention_days
    }
    subs as var(func:has(Microsoft.Subscription)) { }
    kvs as var(func: has(<Microsoft.KeyVault/vaults>)){ }
    vaults as var(func: has(Microsoft.KeyVault)){ }
    retention as var(func: has(is_retention_enabled)) @filter(ge(val(days), 180)) { }  
    var(func:uid(subs)) @cascade{
      contains @filter(uid(kvs)){
        synthesises @filter(uid(vaults)){
          synthesises @filter(uid(retention)) {
            observes {
              happySub as uid
            }
          }
        }
      }
    }
    query(func:uid(subs)) @filter(NOT uid(happySub)){
       <%= default_predicates %>
    }
}
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.KeyVault/vaults' => ['retention_days']
  })
end

coreo_aws_rule "azure-monitoring-log-profile-exists" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-log-profile-exists.html"
  display_name "Log Profile Exists"
  description "A Log Profile controls how your Activity Log is exported. By default, activity logs are retained only for 90 days. It is thus recommended to define a log profile using which you could export the logs and store them for a longer duration for analyzing security activities within your Azure subscription."
  category "Logging"
  suggested_action "Enable log profile for exporting activity logs."
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(Microsoft.Subscription)){
      contains @filter(has(microsoft.insights)){
        observes @filter(has(Microsoft.Subscription)){
          goodSub as uid
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(goodSub)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'microsoft.insights' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-retention-365-days-or-greater" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-retention-365-days-or-greater.html"
  display_name "Activity Log Retention 365 Days Or Greater"
  description "A Log Profile controls how your Activity Log is exported and retained. Since the average time to detect a breach is 210 days, it is recommended to retain your activity log for 365 days or more in order to have time to respond to any incidents."
  category "Logging"
  suggested_action "Ensure Activity Log Retention is set for 365 days or greater"
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.2" }
    ]
  )
  meta_rule_query <<~QUERY
{
  var(func:has(retention_days)){
    days as retention_days
  }
  subs as var(func:has(Microsoft.Subscription)) {}
  insights as var(func:has(microsoft.insights)) {}
  var(func:uid(subs)) @cascade{
    contains @filter(uid(insights) AND ge(val(days), 365)){
      goodProfile as uid
    }
  }
  query(func:has(microsoft.insights)) @filter(NOT uid(goodProfile)){
    <%= default_predicates %>
  }
}
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'microsoft.insights' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-create-polic-assignment" do
  action :define
  service :Microsoft_Insights
  link "azure-monitoring-activity-log-alert-for-create-polic-assignment.html"
  display_name "Activity Log Alert For Create Polic Assignment"
  description "Monitoring for Create Policy Assignment gives insight into privilege assignment and may reduce the time it takes to detect a breach or misuse of information."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Create Policy Assignment event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.3" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)){
      opValues as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(opValues), "Administrative")){
          checks @filter(eq(val(opValues), "microsoft.authorization/policyassignments/write")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-create-or-update-network-security-group" do
  action :define
  service :Microsoft_Insights
  link "azure-monitoring-activity-log-alert-for-create-or-update-network-security-group.html"
  display_name "Activity Log Alert For Create Or Update Network Security Group"
  description "Monitoring for Create or Update Network Security Group events gives insight network access changes and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Create or Update Network Security Group event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)){
      opValues as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(opValues), "Administrative")){
          checks @filter(eq(val(opValues), "microsoft.network/networksecuritygroups/write")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-delete-network-security-group" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-delete-network-security-group.html"
  display_name "Activity Log Alert For Delete Network Security Group"
  description "Monitoring for Delete Network Security Group events gives insight network access changes and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Delete Network Security Group event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.5" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)){
      opValues as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(opValues), "Administrative")){
          checks @filter(eq(val(opValues), "microsoft.network/networksecuritygroups/delete")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-create-or-update-network-security-group-rule" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-create-or-update-network-security-group-rule.html"
  display_name "Activity Log Alert For Create Or Update Network Security Group Rule"
  description "Monitoring for Create or Update Network Security Group Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Create or Update Network Security Group Rule event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.6" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)){
      opValues as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(opValues), "Administrative")){
          checks @filter(eq(val(opValues), "microsoft.network/networksecuritygroups/securityrules/write")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-delete-network-security-group-rule" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-delete-network-security-group-rule.html"
  display_name "Activity Log Alert For Delete Network Security Group Rule"
  description "Monitoring for Delete Network Security Group Rule events gives insight into network access changes and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Delete Network Security Group Rule event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.7"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.7" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)){
      opValues as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(opValues), "Administrative")){
          checks @filter(eq(val(opValues), "microsoft.network/networksecuritygroups/securityrules/delete")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-create-or-update-security-solution" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-create-or-update-security-solution.html"
  display_name "Activity Log Alert For Create Or Update Security Solution"
  description "Monitoring for Create or Update Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Create or Update Security Solution event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.8"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.8" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)){
      opValues as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(opValues), "Administrative")){
          checks @filter(eq(val(opValues), "microsoft.security/securitysolutions/write")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-monitoring-activity-log-alert-for-delete-network-security-solution" do
  action :define
  service :Microsoft_Insights
  link "https://kb.securestate.vmware.com/azure-monitoring-activity-log-alert-for-delete-network-security-solution.html"
  display_name "Activity Log Alert For Delete Network Security Solution"
  description "Monitoring for Delete Security Solution events gives insight into changes to the active security solutions and may reduce the time it takes to detect suspicious activity."
  category "Logging"
  suggested_action "Create an Activity Log Alert for the Delete Security Solution event."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "5.9"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "5.9" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(value)){
      opValues as value
    }
    var(func:has(<Microsoft.Insights/ActivityLogAlerts>)) @cascade{
      guards{
        checks @filter(eq(val(opValues), "Administrative")){
          checks @filter(eq(val(opValues), "microsoft.security/securitysolutions/delete")){
            endorses{
              records{
                happyTarget as uid
              }
            }
          }
        }
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(happyTarget)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Insights/ActivityLogAlerts' => []
  })
end

coreo_aws_rule "azure-security-rdp-access-restricted-from-internet" do
  action :define
  service :Microsoft_Network
  link "https://kb.securestate.vmware.com/azure-security-rdp-access-restricted-from-internet.html"
  display_name "Rdp Access Restricted From Internet"
  description "The potential security problem with using RDP over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use your virtual machine as a launch point for compromising other machines on your Azure Virtual Network or even attack networked devices outside of Azure."
  category "Security"
  suggested_action "Disable RDP access on Network Security Groups from Internet"
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "6.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "6.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(protocol)) @cascade{
      proto as protocol
      dportMin as destination_port_max
      dportMax as destination_port_min
      sAddrMin as source_cidr_range_min
      sAddrMax as source_cidr_range_max
    }
    var(func:has(<Microsoft.Network/networkSecurityGroups>)) {
      synthesises @filter(eq(val(proto), "TCP") AND eq(val(sAddrMin),0) AND eq(val(sAddrMax),4294967295) AND le(val(dportMin), 3389) AND ge(val(dportMax), 3389)){
        violation as uid
      }
    }
    query(func:uid(violation)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Network/networkSecurityGroups' => []
  })
end

coreo_aws_rule "azure-security-ssh-access-restricted-from-internet" do
  action :define
  service :Microsoft_Network
  link "https://kb.securestate.vmware.com/azure-security-ssh-access-restricted-from-internet.html"
  display_name "Ssh Access Restricted From Internet"
  description "The potential security problem with using SSH over the Internet is that attackers can use various brute force techniques to gain access to Azure Virtual Machines. Once the attackers gain access, they can use your virtual machine as a launch point for compromising other machines on your Azure Virtual Network or even attack networked devices outside of Azure."
  category "Security"
  suggested_action "Disable SSH access on Network Security Groups from Internet"
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "6.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "6.2" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(protocol)) @cascade{
      proto as protocol
      dportMin as destination_port_max
      dportMax as destination_port_min
      sAddrMin as source_cidr_range_min
      sAddrMax as source_cidr_range_max
    }
    var(func:has(<Microsoft.Network/networkSecurityGroups>)) {
      synthesises @filter(eq(val(proto), "TCP") AND eq(val(sAddrMin),0) AND eq(val(sAddrMax),4294967295) AND le(val(dportMin), 22) AND ge(val(dportMax), 22)){
        violation as uid
      }
    }
    query(func:uid(violation)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Network/networkSecurityGroups' => []
  })
end

coreo_aws_rule "azure-sql-sql-server-access-restricted-from-internet" do
  action :define
  service :Microsoft_Network
  link "https://kb.securestate.vmware.com/azure-sql-sql-server-access-restricted-from-internet.html"
  display_name "Sql Server Access Restricted From Internet"
  description "SQL Database includes a firewall to block access to unauthorized connections. After creating your SQL Database, you can specify which IP addresses can connect to your database. You can then define more granular IP addresses by referencing the range of addresses available from specific datacenters."
  category "Security"
  suggested_action "Ensure that no SQL Databases allow ingress from the internet."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "6.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "6.3" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(protocol)) @cascade{
      proto as protocol
      dportMin as destination_port_max
      dportMax as destination_port_min
      sAddrMin as source_cidr_range_min
      sAddrMax as source_cidr_range_max
    }
    var(func:has(<Microsoft.Network/networkSecurityGroups>)) {
      synthesises @filter(eq(val(proto), "TCP") AND eq(val(sAddrMin),0) AND eq(val(sAddrMax),4294967295) AND le(val(dportMin), 1433) AND ge(val(dportMax), 1433)){
        violation as uid
      }
    }
    query(func:uid(violation)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Network/networkSecurityGroups' => []
  })
end

coreo_aws_rule "azure-network-watcher-network-security-group-flow-log-retention-greater-than-90-days" do
  action :define
  service :Microsoft_Network
  link "https://kb.securestate.vmware.com/azure-network-watcher-network-security-group-flow-log-retention-greater-than-90-days.html"
  display_name "Network Security Group Flow Log Retention Greater Than 90 Days"
  description "Flow logs enable capturing information about IP traffic flowing in and out of your Network Security Groups. Logs can be used to check for anomalies and give insight into suspected breaches."
  category "Security"
  suggested_action "Network Security Group Flow Logs should be enabled and retention period is set to greater than or equal to 90 days."
  level "Low"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "6.4"
  meta_cis_scored "true"
  meta_cis_level "2"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "6.4" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(is_audit_enabled)) @cascade{
      flowLogs as is_audit_enabled
      retentionOk as retention_days
    }
    okNSG as var(func:has(<Microsoft.Network/networkSecurityGroups>)) @filter(eq(val(flowLogs), true)){
      uid
    }
    query(func:has(<Microsoft.Network/networkSecurityGroups>)) @filter(NOT uid(okNSG) AND NOT ge(val(retentionOk),90) ){
      <%= default_predicates %>
      retention_days
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Network/networkSecurityGroups' => ['retention_days']
  })
end

coreo_aws_rule "azure-network-watcher-network-watcher-enabled" do
  action :define
  service :Microsoft_Network
  link "https://kb.securestate.vmware.com/azure-network-watcher-network-watcher-enabled.html"
  display_name "Network Watcher Enabled"
  description "Network diagnostic and visualization tools available with Network Watcher help you understand, diagnose, and gain insights to your network in Azure."
  category "Security"
  suggested_action "Enable Network Watcher for your Azure Subscriptions."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "6.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "6.5" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(provisioning_status)) @cascade{
      provisioned as provisioning_status
    }
    good_uids as var(func:has(Microsoft.Subscription)){
      contains @filter(has(<Microsoft.Network/networkWatchers>) AND eq(val(provisioned), "Succeeded")){
        count(uid)
      }
    }
    query(func:has(Microsoft.Subscription)) @filter(NOT uid(good_uids)) {
      <%= default_predicates %>
    }
    ##TODO ADD ERB TEMPLATE TO CHECK IF count is < 27 (total locations from azure)
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Network/networkWatchers' => []
  })
end

coreo_aws_rule "azure-security-vm-agent-installed" do
  action :define
  service :Microsoft_Compute
  link "https://kb.securestate.vmware.com/azure-security-vm-agent-installed.html"
  display_name "Vm Agent Installed"
  description "The VM agent must be installed on Azure virtual machines (VMs) in order to enable Azure Security center for data collection. Security Center collects data from your virtual machines (VMs) to assess their security state, provide security recommendations, and alert you to threats."
  category "Security"
  suggested_action "Install VM agent on Virtual Machines."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "7.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "7.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    vms as var(func:has(<Microsoft.Compute/virtualMachines>)) @cascade{
      hasAgent as is_os_agent_enabled
    }
    query(func:uid(vms)) @filter(NOT eq(val(hasAgent), true)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Compute/virtualMachines' => ['is_os_agent_enabled']
  })
end

coreo_aws_rule "azure-security-os-disks-encrypted" do
  action :define
  service :Microsoft_Compute
  link "https://kb.securestate.vmware.com/azure-security-os-disks-encrypted.html"
  display_name "Os Disks Encrypted"
  description "Encrypting your IaaS VM's OS disk (boot volume) ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads."
  category "Security"
  suggested_action "Ensure that OS disks (boot volumes) are encrypted, where possible."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "7.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "7.2" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    vms as var(func:has(vm_hardware_profile)) @cascade{
      encrypted as is_os_encryption_enabled
    }
    query(func:uid(vms)) @filter(NOT eq(val(encrypted), true)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Compute/virtualMachines' => ['is_os_encryption_enabled']
  })
end

coreo_aws_rule "azure-security-data-disks-encrypted" do
  action :define
  service :Microsoft_Compute
  link "https://kb.securestate.vmware.com/azure-security-data-disks-encrypted.html"
  display_name "Data Disks Encrypted"
  description "Encrypting your IaaS VM's Data disks (non-boot volume) ensures that its entire content is fully unrecoverable without a key and thus protects the volume from unwarranted reads."
  category "Security"
  suggested_action "Ensure that Data disks (non-boot volumes) are encrypted, where possible."
  level "High"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "7.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "7.3" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    vms as var(func:has(<Microsoft.Compute/virtualMachines>)) @cascade{
      encrypted as disk_encryption
    }
    query(func:uid(vms)) @filter(NOT eq(val(encrypted), true)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
    'Microsoft.Compute/virtualMachines' => ['disk_encryption']
  })
end

coreo_aws_rule "azure-key-vault-expiry-date-set-for-all-keys" do
  action :define
  service :Microsoft_KeyVault
  link "https://kb.securestate.vmware.com/azure-key-vault-expiry-date-set-for-all-keys.html"
  display_name "Expiry Date Set For All Keys"
  description "Azure Key Vault enables users to store and use cryptographic keys within the Microsoft Azure environment. The `exp` (expiration time) attribute identifies the expiration time on or after which the key MUST NOT be used for a cryptographic operation. By default, Keys never expire. It is thus recommended that you rotate your keys in the key vault and set an explicit expiry time for all keys. This ensures that the keys cannot be used beyond their assigned lifetimes."
  category "Security"
  suggested_action "Ensure that all Keys in Azure Key Vault have an expiry time set."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "8.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "8.1" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    kvs as var(func: <%= filter['Microsoft.KeyVault'] %>) { }
    var(func: <%= filter['vault_uri'] %> ) @cascade{
      contains @filter(uid(kvs)){
        expires as validity_period_end_datetime
      }
    }
    query(func: uid(kvs)) @filter(NOT uid(expires)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
   'Microsoft.KeyVault' => []
  })
end

coreo_aws_rule "azure-key-vault-expiry-date-set-for-all-secrets" do
  action :define
  service :Microsoft_KeyVault
  link "https://kb.securestate.vmware.com/azure-key-vault-expiry-date-set-for-all-secrets.html"
  display_name "Expiry Date Set For All Secrets"
  description "Azure Key Vault enables users to store and secrets within the Microsoft Azure environment. Secrets in Azure Key Vault are octet sequences with a maximum size of 25k bytes each. The `exp` (expiration time) attribute identifies the expiration time on or after which the secret MUST NOT be used. By default, Secrets never expire. It is thus recommended that you rotate your secrets in the key vault and set an explicit expiry time for all secrets. This ensures that the secrets cannot be used beyond their assigned lifetimes."
  category "Security"
  suggested_action "Ensure that all Secrets in Azure Key Vault have an expiry time set."
  level "Medium"
  audit_objects [""]
  objectives [""]
  operators [""]
  raise_when [true]
  meta_cis_id "8.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  # meta_scoring_status "full"
  meta_compliance (
    [
      { "name" => "cis-azure-foundations-benchmark", "version" => "1.0.0" , "requirement" => "8.2" }
    ]
  )
  meta_rule_query <<~QUERY
  {
    var(func:has(vault_uri)) @cascade{
      contains @filter(has(AzureVaultSecret)){
        expires as validity_period_end_datetime
        vaultSecret as uid
      }
    }
    query(func:uid(vaultSecret)) @filter(NOT uid(expires)){
      <%= default_predicates %>
    }
  }
  QUERY
  meta_rule_visualize <<~QUERY
  {
    query(func: uid(<%= violation_uid %>)) {
      <%= default_predicates %>
      relates_to {
        <%= default_predicates %>
        relates_to @filter(NOT uid(<%= violation_uid %>)) {
          <%= default_predicates %>
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
   'Microsoft.KeyVault' => []
  })
end
