Function Get-ADSIObject{
    <#
        .SYNOPSIS
            This function will query Active Directory using an ADSISearcher object.
        .PARAMETER DomainName
            Name of the domain to query.
        .PARAMETER LDAPFilter
            LDAP filter to use for the query.
        .PARAMETER Property
            Property to return.
        .PARAMETER PageSize
            PageSize to use for the query.
        .PARAMETER SearchBAse
            SearchBase to scope the query.
        .EXAMPLE
            Get-ADSIObject -Verbose
        .EXAMPLE
            Get-ADSIObject -NamingContext 'DC=D2K16,DC=itfordummies,DC=net' -LDAPFilter '(admincount=1)' -Verbose
        .EXAMPLE
            Get-ADSIObject -DomainName D2K12R2.itfordummies.net -LDAPFilter '(admincount=1)' -NamingContext 'DC=D2K12R2,DC=itfordummies,DC=net'
        .EXAMPLE
            Get-ADSIObject -Property Name,Mail,description -Verbose -SearchBase 'OU=Users,OU=Star Wars,OU=Prod,DC=D2K16,DC=itfordummies,DC=net' | Out-GridView
        .LINK
            https://ItForDummies.net
        .NOTES
            Futur updates : #Credential, Server, searchscope
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Position=0)]
        [String]$LDAPFilter = '(objectclass=user)',

        [Parameter(Position=1)]
        [String[]]$Property,

        [Parameter(Position=2)]
        [ValidateScript({Test-Connection -ComputerName $_ -Count 2 -Quiet})]
        [String]$DomainName = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name,

        [String]$SearchBase,

        [Int]$PageSize = 1000
    )

    DynamicParam{
        if([String]::IsNullOrEmpty($DomainName)){$DomainName = [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name}
        
        $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]
	    $ParamAttrib = New-Object System.Management.Automation.ParameterAttribute
	    $ParamAttrib.Mandatory = $false
	    $ParamAttrib.ParameterSetName = '__AllParameterSets'
	    $ParamAttrib.ValueFromPipeline = $false
	    $ParamAttrib.ValueFromPipelineByPropertyName = $false
	    $AttribColl.Add($ParamAttrib)
	    $AttribColl.Add((New-Object System.Management.Automation.ValidateSetAttribute(([ADSI]"LDAP://$DomainName/RootDSE" | Select-Object -ExpandProperty namingContexts))))
	    $RuntimeParam = New-Object System.Management.Automation.RuntimeDefinedParameter('NamingContext', [string], $AttribColl)
	    $RuntimeParamDic = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
	    $RuntimeParamDic.Add('NamingContext', $RuntimeParam)
	    $RuntimeParamDic
    }
    
    Begin{
        $PsBoundParameters.GetEnumerator() | ForEach-Object -Process { New-Variable -Name $_.Key -Value $_.Value -ErrorAction 'SilentlyContinue' }
    }
    Process{
        $ADSISearcher = [ADSISearcher]"$LDAPFilter"
        #Load each property if requested
        if($Property){
            $Property | ForEach-Object -Process {
                Write-Verbose -Message "Adding $_ to properties to load..."
                $ADSISearcher.PropertiesToLoad.Add($_.ToLower())
            } | Out-Null
        }
        
        #Use Naming Context if specified, otherwise, use the domain name
        if($NamingContext){
            Write-Verbose -Message "Will use $NamingContext."
            $ADSISearcher.SearchRoot = [ADSI]"LDAP://$NamingContext"
        }
        elseif($SearchBase){
            Write-Verbose -Message "Will use $SearchBase."
            $ADSISearcher.SearchRoot = [ADSI]"LDAP://$SearchBase"
        }
        else{
            Write-Verbose -Message "Will use $DomainName."
            $ADSISearcher.SearchRoot = [ADSI]"LDAP://$DomainName"
        }
        
        #Set PageSize
        $ADSISearcher.PageSize = $PageSize
        Write-Verbose -Message "Searching for $LDAPFilter in $DomainName with a pagesize of $PageSize..."
        $AllObjects = $ADSISearcher.FindAll()
        $LoadedProperties = $AllObjects | Select-Object -First 1 | Select-Object -ExpandProperty Properties | Select-Object -ExpandProperty PropertyNames

        #Going through each AD object
        Foreach($Object in $AllObjects){
            #Hashtable for storing properties
            $CurrentObj = @{}
            Foreach($LoadedProperty in $LoadedProperties){
                ##Adding each properties to the hashtable 
                $CurrentObj.Add($LoadedProperty,$($Object.Properties.Item($LoadedProperty)))
            }
            #Create an object per AD object with all properties
            New-Object -TypeName PSObject -Property $CurrentObj
        }
    }
    End{}
}
