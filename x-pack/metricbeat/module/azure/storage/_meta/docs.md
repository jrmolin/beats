This is the storage metricset of the module azure.

This metricset allows users to retrieve all metrics from specified storage accounts.


## Metricset-specific configuration notes [_metricset_specific_configuration_notes_11]

`refresh_list_interval`
:   Resources will be retrieved at each fetch call (`period` interval), this means a number of Azure REST calls will be executed each time. This will be helpful if the azure users will be adding/removing resources that could match the configuration options so they will not added/removed to the list. To reduce on the number of API calls we are executing to retrieve the resources each time, users can configure this setting and make sure the list or resources will not be refreshed as often. This is also beneficial for performance and rate/ cost reasons ([https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-request-limits](https://docs.microsoft.com/en-us/azure/azure-resource-manager/resource-manager-request-limits)).

`resources`
:   This will contain all options for identifying resources and configuring the desired metrics


### Config options to identify resources [_config_options_to_identify_resources_11]

`resource_id`
:   (*[]string*) The fully qualified ID’s of the resource, including the resource name and resource type. Has the format `/subscriptions/{{guid}}/resourceGroups/{{resource-group-name}}/providers/{{resource-provider-namespace}}/{resource-type}/{{resource-name}}`. Should return a list of resources.

`resource_group`
:   (*[]string*) This option will return all storage accounts inside the resource group.

`service_type`
:   (*[]string*) This configuration key can be used with any of the 2 options above, for example:

```
resources:
    - resource_id: ""
      service_type: ["blob", "table"]
    - resource_group: ""
      service_type: ["queue", "file"]
```

it will filter the metric values to be returned by specific metric namespaces. The supported metrics and namespaces can be found here [https://docs.microsoft.com/en-us/azure/azure-monitor/platform/metrics-supported#microsoftstoragestorageaccounts](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/metrics-supported#microsoftstoragestorageaccounts). The service type values allowed are `blob`, `table`, `queue`, `file` based on the namespaces  `Microsoft.Storage/storageAccounts/blobServices`,`Microsoft.Storage/storageAccounts/tableServices`,`Microsoft.Storage/storageAccounts/fileServices`,`Microsoft.Storage/storageAccounts/queueServices`. If no service_type is specified all values are applied.

Also, if the `resources` option is not specified, then all the storage accounts from the entire subscription will be selected. The primary aggregation value will be retrieved for all the metrics contained in the namespaces. The aggregation options are `avg`, `sum`, `min`, `max`, `total`, `count`.

A default non configurable timegrain of 5 min is set so users are advised to configure an interval of 300s or  a multiply of it.
