Public MustInherit Class EC2Utilities



Public Shared Sub UpdateSecurityGroupIP(awsRegion As RegionEndpoint, port As Integer, securityGroup As String, username As String, roleARN As string)
'RegionEndPoint: Allows one login or function to update SG's in any region
'port: the TCP port to add/update to the whitelist in the security group
'securityGroup: the sg-xxxxx name of the security group to update
'username: used as the 'description' of the entry in the Security Group, gets replaced when an IP changes
'roleARN: Used with STS to update Security Groups in another account. 


Try
            Dim clientIP As String = HttpContext.Current.Request.Headers("X-Forwarded-For")?.ToString()
            If Not IsNothing(clientIP) AndAlso clientIP.Length > 0 AndAlso securityGroup.Length > 0 Then

                Dim officeIPs As New List(Of String)
                officeIPs.Add("0.0.0.0")
                officeIPs.Add("1.1.1.1") 
                officeIPs.Add("8.8.8.8") 
                'These are static IPs for our office locations, so we don't keep constantly updating the office IPs to the Security Groups, they are already manually added to it. 
                
                
                If Not officeIPs.Contains(clientIP) Then

                    clientIP &= "/32"

                    Dim ec2Config As New AmazonEC2Config
                    ec2Config.RegionEndpoint = awsRegion
                    Dim client As AmazonEC2Client
                    if roleARN = "" Then
                        client = New AmazonEC2Client(ec2Config)
                    Else
                        Dim token = fetchToken(roleARN, awsRegion)
                        client = New AmazonEC2Client(token, ec2Config)
                    End If
                    
                    Dim gIDs As New List(Of String)
                    gIDs.Add(securityGroup)

                    Dim oldIP As New List(Of IpRange)

                    Dim filterSet As New List(Of Filter)
                    filterSet.Add(New Filter With {.Name = "group-id", .Values = gIDs})
                    Dim secResponse = client.DescribeSecurityGroups(New DescribeSecurityGroupsRequest With {.Filters = filterSet})

                    If secResponse.SecurityGroups.Any() Then

                        For Each ipSet In secResponse.SecurityGroups.FirstOrDefault().IpPermissions
                            Dim theIP = ipSet
                            oldIP.AddRange(From ipRange In theIP.Ipv4Ranges Where ipRange.Description = username Select New IpRange With {.CidrIp = ipRange.CidrIp, .Description = ipRange.Description})
                        Next
                        If oldIP.Any() Then
                            Try
                                Dim oldPermList As New List(Of IpPermission)
                                oldPermList.Add(New IpPermission With {.FromPort = port, .ToPort = port, .IpProtocol = "TCP", .Ipv4Ranges = oldIP})
                                client.RevokeSecurityGroupIngress(New RevokeSecurityGroupIngressRequest With {.GroupId = gIDs.FirstOrDefault(), .IpPermissions = oldPermList})
                            Catch ex As AmazonEC2Exception
                                If ex.ErrorCode.Contains("InvalidPermission.NotFound") Then
                                    ExceptionlessClient.Default.CreateLog($"Failed in attempt to revoke for {username} on {clientIP} in {securityGroup}, not found.", LogLevel.Info).Submit()
                                Else
                                    ex.ToExceptionless().AddTags("BastionAccess - Removing").Submit()
                                End If
                            End Try
                        End If


                        Dim ipList = New List(Of IpRange)
                        ipList.Add(New IpRange With {.CidrIp = clientIP, .Description = username})
                        Dim permList As New List(Of IpPermission)
                        permList.Add(New IpPermission With {.FromPort = port, .ToPort = port, .IpProtocol = "TCP", .Ipv4Ranges = ipList})
                        Try
                            Dim addResp = client.AuthorizeSecurityGroupIngress(New AuthorizeSecurityGroupIngressRequest With {.GroupId = gIDs.FirstOrDefault(), .IpPermissions = permList})
                            If addResp.HttpStatusCode <> 200 Then
                                ExceptionlessClient.Default.CreateLog($"NonOK code returned from EC2 ({addResp.ToString()}) - {securityGroup}", LogLevel.Error).Submit()
                            Else 
                                ExceptionlessClient.Default.CreateLog($"Added {clientIP} for {username} to {securityGroup}", LogLevel.Info).Submit()
                            End If
                        Catch ex As AmazonEC2Exception
                            Select Case ex.ErrorCode
                                Case "InvalidPermission.Duplicate"
                                            'ExceptionlessClient.Default.CreateLog($"Duplicate Detected for {Username} on {clientIP}", LogLevel.Info).Submit()
                                Case "RulesPerSecurityGroupLimitExceeded"
                                    ExceptionlessClient.Default.CreateLog($"Unable to add new record for {username} on {clientIP}, SecurityGroup full ({securityGroup}).", LogLevel.Warn).Submit()
                                Case Else
                                    ex.ToExceptionless().AddTags("BastionAccess - Adding").Submit()
                            End Select
                        End Try
                    Else
                        ExceptionlessClient.Default.CreateLog($"No matching Security Groups", LogLevel.Warn).AddObject(securityGroup).Submit()
                    End If
                    client.Dispose()
                End If
            Else
                ExceptionlessClient.Default.CreateLog($"Unable to modify Bastion Access {securityGroup} - No Details ({clientIP})", LogLevel.Warn).Submit()
            End If
        Catch ex As Exception
            ex.ToExceptionless().AddTags("BastionAccess").Submit()
        End Try
    End Sub
    
        private Shared Function FetchToken(roleARN as string, awsRegion As RegionEndpoint) As SecurityToken.Model.Credentials
        Dim result As SecurityToken.Model.AssumeRoleResponse
        Try
            Using cli As New SecurityToken.AmazonSecurityTokenServiceClient(awsRegion)
                Dim request As New SecurityToken.Model.AssumeRoleRequest()
                request.RoleArn = roleARN
                request.DurationSeconds = 900
                request.RoleSessionName = "STSRole"
                result = cli.AssumeRole(request)
            End Using
            Return result.Credentials
        Catch ex As Exception
            ex.ToExceptionless().Submit()
            Return Nothing
        End Try
    End Function
End Class
