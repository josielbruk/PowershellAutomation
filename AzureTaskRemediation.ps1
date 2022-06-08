# Getting all subscriptions Name
$subscriptionsName = Get-AzSubscription | Select-Object Name

#Loop through each subscription
foreach ($subscription in $subscriptionsName.Name) {
    # Select a subscription
    Write-Output $subscription    
    Select-AzSubscription -SubscriptionName $subscription
    # Check for policy with effect "deployIfNotExists" and state "NonCompliant"
    $nonCompliantPolicies = Get-AzPolicyState | Where-Object { $_.ComplianceState -eq "NonCompliant" -and ($_.PolicyDefinitionAction -eq "deployIfNotExists" -or $_.PolicyDefinitionAction -eq "modify")}
    # Create a Task remediation for each no compliant policy
    foreach ($policy in $nonCompliantPolicies) {
        $remediationName = "rem." + $policy.PolicyDefinitionName
        # Create the task remediation that will discover non-compliant resources before remediating
        if([string]::IsNullOrWhiteSpace($policy.PolicyDefinitionName)){
            Start-AzPolicyRemediation -Name $remediationName -PolicyAssignmentId $policy.PolicyAssignmentId -PolicyDefinitionReferenceId $policy.PolicyDefinitionReferenceId -ResourceDiscoveryMode ReEvaluateCompliance
            Get-AzPolicyRemediation -Subscription $subscription
            Write-Output "Policy Remediation Name:"
            Write-Output $remediationName
        }
    }
    # Triggers a policy compliance evaluation for all resources in a subscription and wait for it to complete in the background
    Start-AzPolicyComplianceScan -AsJob
}
