#######################################################################################
# Script that renews a Let's Encrypt certificate for an Azure Application Gateway
# Pre-requirements:
#      - Have a storage account in which the folder path has been created:
#        '/.well-known/acme-challenge/', to put here the Let's Encrypt DNS check files
#
#      - Add "Path-based" rule in the Application Gateway with this configuration:
#           - Path: '/.well-known/acme-challenge/*'
#           - Check the configure redirection option
#           - Choose redirection type: permanent
#           - Choose redirection target: External site
#           - Target URL: <Blob public path of the previously created storage account>
#                - Example: 'https://test.blob.core.windows.net/<nameOfStorageContainer>'
#
#       UPDATE 30.01.2020 by Nikolai Thingnes Leira - Original here: https://github.com/intelequia/letsencrypt-aw/blob/master/letsencryptaw_v2.ps1
#       - Migrated the script to use Az module instead of AzureRM
#       - Added function to temporarily open in firewall incase it is needed (Should do nothing if you do not specifiy $NSGName variable)
#       - Moved away from paramaters to use Azure Automation Variables instead, this allows for secure storage of the Certificate Password so it is not in cleartext
#       - TODO?: Change DNSName and EMail back to parameters so you can use the same runbook against mulitple domains, or do dynamic building based on variables in the
#                store
#
#      - For execution on Azure Automation import the following modules on the runbook:
#           Az.Accounts
#           Az.Automation
#           Az.Network
#           Az.Storage
#           ACME-PS
#
#       - You need to use Azure Automation variables, the ones needed is as follows:
#           - DNSName - the domain you want to update
#           - EMail - Contact info that is sent with the certificate request
#           - StorageAccountResourceGroup - The resource group assosciated with the storage account you're using
#           - StorageAccountName - The name of the storage account
#           - StorageContainer - The container you're using to store your files
#           - AppGWResourceGroupName - The resourcegroup associated with your application gateway
#           - AppGWName - The name of your application gateway
#           - AppGWCertName - The name of the certificate you're replacing (This will always be the same once you've set it)
#           - CertificatePassword - The password of your .pfx certificate. This should be set to sensitive!
#           - NSGRuleName - Name of the rule you're setting to allow in your Network Security Group
#           - NSGName - Name of the Network Security Group
#           - NSGResourceGroupName - Name of the resource group associated with your NSG
#
#######################################################################################

# Variables
$domain = Get-AutomationVariable -Name "DNSName"
$EmailAddress = Get-AutomationVariable -Name "EMail"
$STResourceGroupName = Get-AutomationVariable -Name "StorageAccountResourceGroup"
$storageName = Get-AutomationVariable -Name "StorageAccountName"
$stContainer = Get-AutomationVariable -Name "StorageContainer"
$AGResourceGroupName = Get-AutomationVariable -Name "AppGWResourceGroupName"
$AGName = Get-AutomationVariable -Name "AppGWName"
$AGOldCertName = Get-AutomationVariable -Name "AppGWCertName"
$CertPW = Get-AutomationVariable -Name "CertificatePassword"
$NSGRule = Get-AutomationVariable -Name "NSGRuleName"
$NSGName = Get-AutomationVariable -Name "NSGName"
$NSGResourceGroup = Get-AutomationVariable -Name "NSGResourceGroupName"

## Azure Login ##
# Azure Automation has it's own login method that can be used with Login-AzAccount
$connection = Get-AutomationConnection -Name AzureRunAsConnection

# Ensures that no login info is saved after the runbook is done
Disable-AzContextAutosave

# Log in as the service principal from the Runbook
Login-AzAccount -ServicePrincipal -Tenant $connection.TenantID -ApplicationId $connection.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint

# Opens the firewall if there's content in the $NSGName variable

If ($NSGName)
{
    # Temporarily open the firewall to allow outside requests
    # Workaround because the NSG cmdlet is buggy
    $nsg = Get-AzNetworkSecurityGroup -Name $NSGName -ResourceGroupName $NSGResourceGroup
    ($nsg.SecurityRules | Where-Object { $_.Name -eq $NSGRule }).Access = "Allow"
    # Pushes the entire object
    $nsg | Set-AzNetworkSecurityGroup | Get-AzNetworkSecurityRuleConfig -Name $NSGRule | Format-Table -AutoSize

    # Sleep for 30 seconds to allow the NSG rules to manifest, if we don't do this the update will fail
    Start-Sleep -Seconds 30
}
else
{
    Write-Output "Firewall not specified, skipping"
}


Try
{
    # Create a new state object for the LetsEncrypt Module
    $state = New-ACMEState -Path $env:TEMP
    $serviceName = 'LetsEncrypt'

    # Fetch the service directory and save it in the state
    Get-ACMEServiceDirectory $state -ServiceName $serviceName -PassThru

    # Get the first anti-replay nonce
    New-ACMENonce $state

    # Create an account key. The state will make sure it's stored.
    New-ACMEAccountKey $state -PassThru

    # Register the account key with the acme service. The account key will automatically be read from the state
    New-ACMEAccount $state -EmailAddresses $EmailAddress -AcceptTOS

    # Load an state object to have service directory and account keys available
    $state = Get-ACMEState -Path $env:TEMP

    # It might be neccessary to acquire a new nonce, so we'll just do it for the sake of the example.
    New-ACMENonce $state -PassThru

    # Create the identifier for the DNS name
    $identifier = New-ACMEIdentifier $domain

    # Create the order object at the ACME service.
    $order = New-ACMEOrder $state -Identifiers $identifier

    # Fetch the authorizations for that order
    $authZ = Get-ACMEAuthorization -State $state -Order $order

    # Select a challenge to fullfill
    $challenge = Get-ACMEChallenge $state $authZ "http-01"

    # Inspect the challenge data
    $challenge.Data

    # Gets the content of the challenge
    $challengeContent = $challenge.Data.Content

    # Create the file requested by the challenge
    $fileName = $env:TMP + '\' + $challenge.Token
    Set-Content -Path $fileName -Value $challengeContent -NoNewline

    # Stores the challenge file in a public storage account
    $blobName = ".well-known/acme-challenge/" + $challenge.Token
    $storageAccount = Get-AzStorageAccount -ResourceGroupName $STResourceGroupName -Name $storageName
    $ctx = $storageAccount.Context

    # Set the Blob Content type so it shows in a browser
    $blobProperties = @{
        "ContentType" = "text/plain; charset=utf-8"
    }

    Set-AzStorageBlobContent -File $fileName -Container $stContainer -Context $ctx -Blob $blobName -Properties $blobProperties

    # Signal the ACME server that the challenge is ready
    $challenge | Complete-ACMEChallenge $state

    # Wait a little bit and update the order, until we see the states
    while ($order.Status -notin ("ready", "invalid"))
    {
        Start-Sleep -Seconds 10
        $order | Update-ACMEOrder $state -PassThru
    }

    # We should have a valid order now and should be able to complete it
    # Therefore we need a certificate key
    $certKey = New-ACMECertificateKey -Path "$env:TEMP\$domain.key.xml"

    # Complete the order - this will issue a certificate singing request
    Complete-ACMEOrder $state -Order $order -CertificateKey $certKey

    # Now we wait until the ACME service provides the certificate url
    while (-not $order.CertificateUrl)
    {
        Start-Sleep -Seconds 15
        $order | Update-ACMEOrder $state -PassThru
    }

    # As soon as the url shows up we can create the PFX
    $password = ConvertTo-SecureString -String $CertPW -Force -AsPlainText
    Export-ACMECertificate $state -Order $order -CertificateKey $certKey -Path "$env:TEMP\$domain.pfx" -Password $password

    # This certificate does not have the full chain, which might break some applications. Creating the full chain
    # NOTE: The chain sometimes is in the wrong order
    $tmpPfx = Get-PfxData -FilePath "$env:TEMP\$domain.pfx" -Password $password
    Export-PfxCertificate -PFXData $tmpPfx -FilePath "$env:TEMP\fullChain.pfx" -Password $password -ChainOption BuildChain

    ## CLEANUP ##
    # Delete blob to check DNS
    Remove-AzStorageBlob -Container $stContainer -Context $ctx -Blob $blobName


    If ($NSGName)
    {
        # Close the temporary opening in the firewall
        # Again a workaround for the NSG CMDlet
        $nsg = Get-AzNetworkSecurityGroup -Name $NSGName -ResourceGroupName $NSGResourceGroup
        ($nsg.SecurityRules | Where-Object { $_.Name -eq $NSGRule }).Access = "Deny"
        # Pushing the entire object
        $nsg | Set-AzNetworkSecurityGroup | Get-AzNetworkSecurityRuleConfig -Name $NSGRule | Format-Table -AutoSize
    }
    else
    {
        # Do nothing
    }
}
catch
{
    If ($NSGName)
    {
        # We really want to ensure that the firewall is closed. So putting this in a try catch to ensure it will run regardless of outcome
        # Again a workaround for the NSG CMDlet
        $nsg = Get-AzNetworkSecurityGroup -Name $NSGName -ResourceGroupName $NSGResourceGroup
        ($nsg.SecurityRules | Where-Object { $_.Name -eq $NSGRule }).Access = "Deny"
        # Pushing the entire object
        $nsg | Set-AzNetworkSecurityGroup | Get-AzNetworkSecurityRuleConfig -Name $NSGRule | Format-Table -AutoSize
    }

    # Write out last error
    $error[0]
    break
}
### RENEW APPLICATION GATEWAY CERTIFICATE ###

# Get application gateway
$appgw = Get-AzApplicationGateway -ResourceGroupName $AGResourceGroupName -Name $AGName

# Set the new certificate
Set-AzApplicationGatewaySslCertificate -Name $AGOldCertName -ApplicationGateway $appgw -CertificateFile "$env:TEMP\fullChain.pfx" -Password $password

# Apply settings to the application gateway
Set-AzApplicationGateway -ApplicationGateway $appgw