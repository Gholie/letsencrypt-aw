# letsencrypt-aw
Powershell script to automate Azure Application Gateway SSL certificate renewals with Let’s Encrypt and Azure Automation

## My updates:

* Migrated script to use Az modules instead of AzureRM
* Changed variables from parameters to use automation account variables instead
  * This ensures you do not have a certificate password in clear text, as you can set a variable to sensitive
  * This does mean that you need one automation account per domain you're updating
    * I might update this to add DNS name to a parameter if I need it
* Added support to update certificate for application that's behind a Network Security Group with IP filters
  * Requires a NSG Rule that defaults to deny on port 80 or 443, if no rule is specified on variable $NSGName no firewall work will be done
  * This will open up the firewall for internet traffic on ports 80 and 443!
    * Will remain open for ~3 minutes depending on Let's Encrypts response time
* Added -FullChain to the exported certificate, this is required for some applications connecting to your application