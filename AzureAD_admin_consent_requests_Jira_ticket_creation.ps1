<#
 Script should be periodically run
 Script checks admin consent requests, if some new (unprocessed) is found, new Jira ticket will be created
 Processed requests are saved into XML file
 When request is allowed/denied, corresponding Jira ticket is closed and comment is added
#>

FIXME set these variables to match your environment
# your Confluence cloud URL
$confluenceUri = ??? # something like 'https://contoso.atlassian.net'
# application ID of the application that is used to gather admin consent request
$entAppId = ???

Start-Transcript (Join-Path $PSScriptRoot ((Split-Path $PSCommandPath -Leaf) + ".log"))

$ErrorActionPreference = "Stop"

Import-Module JiraPS
Import-Module AzureADStuff

# connect to Jira
# export Jira credentials (username + API token) to XML file
# Export-Clixml -InputObject (Get-Credential) -Path "$PSScriptRoot\jiraCred.xml" -Encoding UTF8 -Force
$jiraCred = Import-Clixml "$PSScriptRoot\jiraCred.xml"
Set-JiraConfigServer $confluenceUri # needed since version 2.10
$s = New-JiraSession -Credential $jiraCred

# XML where processed requests are stored
$processedRequestsXml = (Join-Path $PSScriptRoot ((Split-Path $PSCommandPath -Leaf) + ".xml"))
if (Test-Path $processedRequestsXml -ea SilentlyContinue) {
    "Importing processed data"
    $processedRequests = Import-Clixml $processedRequestsXml
} else {
    $processedRequests = @()
}

# authenticate using IT_Azure_Consent_Read app
# $thumbprint = Get-ChildItem Cert:\LocalMachine\My | ? subject -Match $entAppId | select -ExpandProperty Thumbprint
# if (!$thumbprint) { throw "Auth certificate is missing from cert. store" }
# Connect-AzureAD -ApplicationId $entAppId -CertificateThumbprint $thumbprint

# export App secret to XML file
# Export-Clixml -InputObject (Get-Credential) -Path "$PSScriptRoot\azureCred.xml" -Encoding UTF8 -Force
$azureCred = Import-Clixml "$PSScriptRoot\azureCred.xml"
$header = New-GraphAPIAuthHeader -credential $azureCred

# Get-AzureADAppConsentRequest | % { # use instead, when certificate auth is used
Get-AzureADAppConsentRequest -header $header | % {
    $request = $_

    $_.consentRequest | % {
        $status = $_.status
        $requestId = $_.RequestId
        $createdBy = $_.createdBy
        $reason = $_.reason

        $processedRequest = $processedRequests | ? requestId -EQ $requestId

        "################## PROCESSING $requestId "

        switch ($status) {
            inProgress {
                if (!$processedRequest) {
                    "Request $requestId wasn't processed yet"

                    if ($request.verifiedPublisher -eq "*unknown*") {
                        $createdByVerifiedPublisher = '*unknown*'
                    } elseif ($request.verifiedPublisher ) {
                        $createdByVerifiedPublisher = "true ($($request.verifiedPublisher))"
                    } else {
                        $createdByVerifiedPublisher = 'false'
                    }

                    # create Jira ticket
                    $description = "User: $createdBy`nRequests permission(s): $($request.pendingScopes)`nFor application: $($request.appDisplayName)`nCreatedByVerifiedPublisher: $createdByVerifiedPublisher`nReason: $reason`n`n`nFor IT Team: Check if application is allowed by our security team at https://kentico.atlassian.net/wiki/spaces/ISMS/pages/3383329076/Online+services+-+review and if so, check requested permissions at https://portal.azure.com/#blade/Microsoft_AAD_IAM/StartboardApplicationsMenuBlade/AccessRequests/menuId and grant or deny admin/user consent."
                    FIXME customize Jira ticket creation to your environment needs!
                    # $ticket = New-JIRATicket -summary "Azure App Admin Consent Request ($($request.appDisplayName))" -description $description -issueType 'IT Help' -type Request -subType 'Other' -participantUPN $createdBy

                    # make a note about processing this request
                    $processedRequests += [PSCustomObject]@{
                        requestId = $requestId
                        ticketKey = $ticket.key
                        status    = "InProgress"
                    }

                    # save changes
                    $processedRequests | Export-Clixml $processedRequestsXml
                } else {
                    # already processed
                    "Request $requestId is still in progress"
                }
            }

            Completed {
                if ($processedRequest) {
                    "Request $requestId was processed in the past"
                    if ($processedRequest.status -ne 'Completed') {
                        "Request $requestId is now completed"
                        try {
                            # close Jira ticket
                            # make a note about closing this request
                            Set-JiraIssue -Issue $processedRequest.ticketKey -AddComment "Permission was $($request.consentrequest.approval.reviewResult) by $($request.consentrequest.approval.reviewedBy) at $($request.consentrequest.approval.reviewedDateTime)"
                            # close this ticket
                            Resolve-JiraIssue -issue $processedRequest.ticketKey
                        } catch {
                            Write-Warning "There was problem when setting ticket $($processedRequest.ticketKey): $_"
                        }
                        # save changes
                        $processedRequest.status = 'Completed'
                        $processedRequests | Export-Clixml $processedRequestsXml
                    } else {
                        # ticket is already closed
                        "Request $requestId was already completed"
                    }
                } else {
                    # this shouldn't happen
                    Write-Warning "Request $requestId wasn't processed by this script but is finished now"
                }
            }

            Expired {
                "Request $requestId is expired"
            }

            default { throw "undefined status $_" }
        }
    }
}