<?xml version="1.0"?>
<package >
  <metadata>
    <id>ContaQuanto.FieldCipher</id>
    <version>|{|VERSION|}|</version>
    <title>JSON Field Cipher</title>
    <authors>Lucas Teske</authors>
    <owners>ContaQuanto</owners>
    <licenseUrl>https://github.com/quan-to/field-cipher-dotnet/blob/master/LICENSE</licenseUrl>
    <projectUrl>https://github.com/quan-to/field-cipher-dotnet/</projectUrl>
    <iconUrl>https://secure.gravatar.com/avatar/9741862b069bddc72f7495a85ea3717d?s=512</iconUrl>
    <requireLicenseAcceptance>true</requireLicenseAcceptance>
    <description>A GPG JSON Field Cipher</description>
    <releaseNotes>
    </releaseNotes>
    <copyright>Copyright 2018</copyright>
    <tags>JSON Quanto ContaQuanto GPG Field Cipher Decipher Encryption Decryption</tags>
    <dependencies>
      <dependency id="BouncyCastle.OpenPgp" version="1.8.1.1"/>
      <dependency id="Newtonsoft.Json" version="11.0.2" />
    </dependencies>
  </metadata>
  <files>
     <file src="build/lib/**" target="lib" />
  </files>
</package>
